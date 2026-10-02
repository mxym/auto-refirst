#include "prts/pe_debug.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>

namespace prts { namespace {

bool rd32(std::span<const std::uint8_t> d,std::size_t off,std::uint32_t& out){
    if(off>d.size()||4>d.size()-off)return false;
    std::memcpy(&out,d.data()+off,4);return true;
}

std::optional<std::size_t> rva_file(const PeInfo& pe,std::uint32_t rva,
                                    std::size_t file_size,std::size_t extent=0){
    const auto need=static_cast<std::uint64_t>(extent);
    if(rva<pe.headers_size&&std::uint64_t(rva)<=file_size&&need<=std::uint64_t(pe.headers_size)-rva&&need<=std::uint64_t(file_size)-rva)
        return static_cast<std::size_t>(rva);
    for(const auto& s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva<s.rva||std::uint64_t(rva)-s.rva>=span)continue;
        const auto delta=std::uint64_t(rva)-s.rva;
        if(delta>=s.raw_size||need>std::uint64_t(s.raw_size)-delta||s.raw_offset>file_size||delta>std::uint64_t(file_size)-s.raw_offset)continue;
        const auto off=std::uint64_t(s.raw_offset)+delta;
        if(need>std::uint64_t(file_size)-off)continue;
        return static_cast<std::size_t>(off);
    }
    return {};
}

struct MagicHit { std::string name; std::size_t size=0; };

std::optional<MagicHit> magic_at(std::span<const std::uint8_t> d,std::size_t off,std::size_t end){
    if(off>=d.size()||off>=end)return std::nullopt;
    end=std::min(end,d.size());
    const auto n=end-off;
    if(n>=0x40&&d[off]=='M'&&d[off+1]=='Z'){
        std::uint32_t lfanew=0;if(rd32(d,off+0x3c,lfanew)&&lfanew<=n-4&&std::memcmp(d.data()+off+lfanew,"PE\0\0",4)==0)return MagicHit{"PE",2};
    }
    if(n>=4&&d[off]==0x7f&&d[off+1]=='E'&&d[off+2]=='L'&&d[off+3]=='F')return MagicHit{"ELF",4};
    if(n>=4&&d[off]=='P'&&d[off+1]=='K'&&d[off+2]==3&&d[off+3]==4)return MagicHit{"ZIP",4};
    if(n>=4&&d[off]=='D'&&d[off+1]=='E'&&d[off+2]=='X'&&d[off+3]=='\n')return MagicHit{"DEX",4};
    return std::nullopt;
}

Finding make_finding(std::string variant,std::string state,std::uint32_t type,
                     std::uint64_t dir_off,std::uint64_t payload_off,
                     std::uint64_t payload_size,std::string signature,
                     std::string embedded,std::uint64_t embedded_off=0,
                     std::uint64_t embedded_size=0){
    Finding f;f.kind="hidden-data";f.family="PE debug payload";f.variant=std::move(variant);f.state=std::move(state);
    f.fields["debug_type"]=std::to_string(type);
    f.fields["debug_directory_file_offset"]=std::to_string(dir_off);
    f.fields["payload_file_offset"]=std::to_string(payload_off);
    f.fields["payload_size"]=std::to_string(payload_size);
    if(!signature.empty())f.fields["codeview_signature"]=std::move(signature);
    if(!embedded.empty())f.fields["embedded_format"]=std::move(embedded);
    f.ranges.push_back(file_offset_range(payload_off,payload_size,"PE debug payload requiring inspection"));
    if(embedded_size){
        f.fields["embedded_file_offset"]=std::to_string(embedded_off);
        f.fields["embedded_size"]=std::to_string(embedded_size);
        f.ranges.push_back(file_offset_range(embedded_off,embedded_size,"embedded format magic requiring inspection"));
    }
    f.suggested_actions={"inspect:pe-debug-payload","extract:debug-directory-data"};
    return f;
}

} // namespace

std::vector<Finding> detect_pe_debug_payload(std::span<const std::uint8_t> data,const PeInfo& pe){
    std::vector<Finding> out;
    if(!pe.valid||!pe.debug.present||!pe.debug.rva||!pe.debug.size)return out;
    auto dir=rva_file(pe,pe.debug.rva,data.size(),pe.debug.size);
    if(!dir)return out;
    const auto available=std::min<std::uint64_t>(pe.debug.size,data.size()-*dir);
    constexpr std::size_t entry_size=28;
    const auto count=std::min<std::uint64_t>(available/entry_size,256);
    for(std::uint64_t i=0;i<count&&out.size()<32;++i){
        const auto off=*dir+static_cast<std::size_t>(i*entry_size);
        std::uint32_t type=0,size=0,addr=0,raw=0;
        if(!rd32(data,off+12,type)||!rd32(data,off+16,size)||!rd32(data,off+20,addr)||!rd32(data,off+24,raw))continue;
        // PointerToRawData is the authoritative file coordinate.  A few
        // producers leave it zero while retaining a valid AddressOfRawData;
        // recover that RVA only when it maps wholly into file-backed bytes.
        if(!raw&&addr){if(auto mapped=rva_file(pe,addr,data.size(),size))raw=static_cast<std::uint32_t>(*mapped);}
        if(!size||!raw||raw>=data.size()||std::uint64_t(size)>data.size()-raw)continue;
        const auto payload=data.subspan(raw,size);
        std::string signature;
        const bool rsds=type==2&&payload.size()>=4&&payload[0]=='R'&&payload[1]=='S'&&payload[2]=='D'&&payload[3]=='S';
        const bool nb10=type==2&&payload.size()>=4&&payload[0]=='N'&&payload[1]=='B'&&payload[2]=='1'&&payload[3]=='0';
        if(rsds||nb10){
            signature=rsds?"RSDS":"NB10";
            const std::size_t header=rsds?24:16;
            if(payload.size()<=header)continue;
            const auto path_begin=std::find(payload.begin()+static_cast<std::ptrdiff_t>(header),payload.end(),std::uint8_t(0));
            if(path_begin==payload.end())continue;
            const auto tail=static_cast<std::size_t>(std::distance(path_begin,payload.end())-1);
            if(!tail)continue;
            const auto tail_off=raw+static_cast<std::size_t>(std::distance(payload.begin(),path_begin))+1;
            std::optional<MagicHit> hit;
            std::size_t hit_off=0;
            for(std::size_t j=0;j<tail;++j)if((hit=magic_at(data,tail_off+j,raw+size))){hit_off=tail_off+j;break;}
            if(hit){
                auto f=make_finding("CodeView trailing embedded "+hit->name,"CONFIRMED",type,off,tail_off,tail,signature,hit->name,hit_off,hit->size);
                f.evidence={"a validated CodeView record contains non-path bytes after the NUL-terminated PDB path","the trailing bytes begin with a recognized PE/ELF/ZIP/DEX container magic"};
                f.negative_evidence={"the embedded bytes are reported as data in the debug record; execution or intent is not inferred"};
                out.push_back(std::move(f));
            }else if(tail>=16&&std::any_of(data.begin()+static_cast<std::ptrdiff_t>(tail_off),
                                           data.begin()+static_cast<std::ptrdiff_t>(tail_off+tail),
                                           [](std::uint8_t b){return b!=0;})){
                auto f=make_finding("CodeView trailing data","LIKELY",type,off,tail_off,tail,signature,{});
                f.evidence={"a validated CodeView record contains a bounded non-zero region after the NUL-terminated PDB path"};
                f.negative_evidence={"extended producer metadata can legally exist; no known container magic was found in the trailing region"};
                out.push_back(std::move(f));
            }
            continue;
        }
        std::optional<MagicHit> hit;
        std::size_t hit_off=0;
        for(std::size_t j=0;j<payload.size();++j)if((hit=magic_at(data,raw+j,raw+size))){hit_off=raw+j;break;}
        if(hit){
            auto f=make_finding("debug directory embedded "+hit->name,"CONFIRMED",type,off,raw,size,{},hit->name,hit_off,hit->size);
            f.evidence={"a non-CodeView PE debug-directory payload contains a recognized independent file/container magic"};
            f.negative_evidence={"the payload is reported for separate static inspection; no execution or intent is inferred"};
            out.push_back(std::move(f));
        }
    }
    return out;
}

} // namespace prts
