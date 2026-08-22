#include "prts/elf.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <vector>
#include <span>
#include <utility>

namespace prts { namespace {

template <typename T>
T bswapv(T v) {
    T out=0;
    for (std::size_t i=0;i<sizeof(T);++i) {
        out = static_cast<T>((out << 8) | (v & 0xff));
        v = static_cast<T>(v >> 8);
    }
    return out;
}

template <typename T>
bool rd(std::span<const std::uint8_t> d, std::size_t off, bool le, T& v) {
    if (off + sizeof(T) > d.size()) return false;
    std::memcpy(&v, d.data()+off, sizeof(T));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if (!le) v = bswapv(v);
#else
    if (le) v = bswapv(v);
#endif
    return true;
}

using EntropyCounts = std::array<std::size_t,256>;

double entropy_counts(const EntropyCounts& c, std::size_t n) {
    if (!n) return 0.0;
    double e=0.0;
    for (auto x:c) if (x) { double q=double(x)/double(n); e-=q*std::log2(q); }
    return e;
}

class EntropyMemo {
public:
    explicit EntropyMemo(std::span<const std::uint8_t> data) : data_(data) {}

    double get(std::size_t off,std::size_t n) {
        if (!n) return 0.0;
        const Entry* parent=nullptr;
        std::size_t best_delta=std::numeric_limits<std::size_t>::max();
        for (const auto& e:entries_) {
            if (e.off==off && e.size==n) return entropy_counts(e.counts,n);
            if (e.off<=off && n<=e.size && off-e.off<=e.size-n) {
                const auto delta=e.size-n;
                if (delta<n && delta<best_delta) { parent=&e;best_delta=delta; }
            }
        }
        EntropyCounts counts{};
        if (parent) {
            counts=parent->counts;
            for (std::size_t i=parent->off;i<off;++i) --counts[data_[i]];
            const auto end=off+n,parent_end=parent->off+parent->size;
            for (std::size_t i=end;i<parent_end;++i) --counts[data_[i]];
        } else {
            for (std::size_t i=0;i<n;++i) ++counts[data_[off+i]];
        }
        entries_.push_back({off,n,counts});
        return entropy_counts(counts,n);
    }
private:
    struct Entry { std::size_t off=0,size=0; EntropyCounts counts{}; };
    std::span<const std::uint8_t> data_;
    std::vector<Entry> entries_;
};

std::string zstr(std::span<const std::uint8_t> d, std::size_t off) {
    if (off >= d.size()) return {};
    std::string s;
    while (off < d.size() && d[off]) s.push_back(static_cast<char>(d[off++]));
    return s;
}

std::optional<std::string> zstr_bounded(std::span<const std::uint8_t> d,std::uint64_t off,std::uint64_t limit){
    if(off>d.size()||limit>d.size()-off)return std::nullopt;
    std::string s;
    for(std::uint64_t i=0;i<limit;++i){const auto c=d[static_cast<std::size_t>(off+i)];if(!c)return s;s.push_back(static_cast<char>(c));}
    return std::nullopt;
}

std::string elf_reloc_name(std::uint16_t machine,std::uint32_t type){
    if(machine==62){switch(type){case 1:return"R_X86_64_64";case 5:return"R_X86_64_COPY";case 6:return"R_X86_64_GLOB_DAT";case 7:return"R_X86_64_JUMP_SLOT";case 8:return"R_X86_64_RELATIVE";case 37:return"R_X86_64_IRELATIVE";default:break;}}
    if(machine==183){switch(type){case 257:return"R_AARCH64_ABS64";case 1024:return"R_AARCH64_COPY";case 1025:return"R_AARCH64_GLOB_DAT";case 1026:return"R_AARCH64_JUMP_SLOT";case 1027:return"R_AARCH64_RELATIVE";case 1032:return"R_AARCH64_IRELATIVE";default:break;}}
    return "R_"+std::to_string(type);
}

std::string elf_symbol_binding_name(std::uint8_t x){switch(x){case 0:return"LOCAL";case 1:return"GLOBAL";case 2:return"WEAK";case 10:return"GNU_UNIQUE";default:return"BIND_"+std::to_string(x);}}
std::string elf_symbol_type_name(std::uint8_t x){switch(x){case 0:return"NOTYPE";case 1:return"OBJECT";case 2:return"FUNC";case 3:return"SECTION";case 4:return"FILE";case 5:return"COMMON";case 6:return"TLS";case 10:return"GNU_IFUNC";default:return"TYPE_"+std::to_string(x);}}
std::string elf_symbol_visibility_name(std::uint8_t x){switch(x){case 0:return"DEFAULT";case 1:return"INTERNAL";case 2:return"HIDDEN";case 3:return"PROTECTED";default:return"VIS_"+std::to_string(x);}}
std::string elf_csvq(const std::string&s){std::string out(1,'"');for(const auto c:s){if(c=='"')out+="\"\"";else out+=c;}out+='"';return out;}

std::string elf_hex(std::span<const std::uint8_t>b){static constexpr char h[]="0123456789abcdef";std::string s;s.resize(b.size()*2);for(std::size_t i=0;i<b.size();++i){s[2*i]=h[b[i]>>4];s[2*i+1]=h[b[i]&15];}return s;}

enum class EhReadState { Ok, Unsupported, Failed };
struct EhReadResult { EhReadState state=EhReadState::Failed; std::uint64_t value=0; bool indirect=false,is_null=false; std::string error; };

bool eh_uleb(std::span<const std::uint8_t>d,std::size_t&off,std::size_t end,std::uint64_t&v){
    v=0;unsigned shift=0;
    for(unsigned n=0;n<10&&off<end;++n){const auto b=d[off++];if(shift==63&&(b&0x7e))return false;v|=std::uint64_t(b&0x7f)<<shift;if(!(b&0x80))return true;shift+=7;}
    return false;
}
bool eh_sleb(std::span<const std::uint8_t>d,std::size_t&off,std::size_t end,std::int64_t&v){
    std::uint64_t raw=0;unsigned shift=0;std::uint8_t b=0;
    for(unsigned n=0;n<10&&off<end;++n){b=d[off++];if(shift==63&&(b&0x7e)!=0&&(b&0x7e)!=0x7e)return false;raw|=std::uint64_t(b&0x7f)<<shift;shift+=7;if(!(b&0x80)){if((b&0x40)&&shift<64)raw|=(~std::uint64_t(0))<<shift;std::memcpy(&v,&raw,sizeof(v));return true;}}
    return false;
}
bool eh_add_signed(std::uint64_t base,std::int64_t delta,std::uint64_t&out){
    if(delta>=0){const auto u=static_cast<std::uint64_t>(delta);if(u>std::numeric_limits<std::uint64_t>::max()-base)return false;out=base+u;return true;}
    const auto mag=std::uint64_t(-(delta+1))+1;if(mag>base)return false;out=base-mag;return true;
}
EhReadResult eh_read_encoded(std::span<const std::uint8_t>d,std::size_t&off,std::size_t end,bool le,std::uint8_t enc,std::uint64_t field_va,std::optional<std::uint64_t> datarel,std::optional<std::uint64_t> funcrel){
    EhReadResult r;if(enc==0xff){r.state=EhReadState::Unsupported;r.error="DW_EH_PE_omit has no value";return r;}
    const auto app=enc&0x70,fmt=enc&0x0f;r.indirect=(enc&0x80)!=0;
    if(app==0x20){r.state=EhReadState::Unsupported;r.error="DW_EH_PE_textrel base is unavailable";return r;}
    if(app==0x30&&!datarel){r.state=EhReadState::Unsupported;r.error="DW_EH_PE_datarel base is unavailable";return r;}
    if(app==0x40&&!funcrel){r.state=EhReadState::Unsupported;r.error="DW_EH_PE_funcrel base is unavailable";return r;}
    if(app!=0&&app!=0x10&&app!=0x20&&app!=0x30&&app!=0x40&&app!=0x50){r.state=EhReadState::Unsupported;r.error="unsupported DW_EH_PE application";return r;}
    if(off>end){r.error="DW_EH_PE value offset exceeds record";return r;}
    if(app==0x50&&fmt!=0){r.state=EhReadState::Unsupported;r.error="DW_EH_PE_aligned with non-absptr format is unsupported";return r;}
    if(app==0x50){const auto pad=static_cast<std::size_t>((8-(field_va&7))&7);if(pad>end-off){r.error="aligned DW_EH_PE value exceeds record";return r;}off+=pad;field_va+=pad;}
    bool signed_value=false;std::uint64_t u=0;std::int64_t sv=0;auto room=[&](std::size_t n){return off<=end&&n<=end-off;};
    switch(fmt){
        case 0x00:if(!room(8)||!rd(d,off,le,u)){r.error="truncated DW_EH_PE_absptr";return r;}off+=8;break;
        case 0x01:if(!eh_uleb(d,off,end,u)){r.error="invalid DW_EH_PE_uleb128";return r;}break;
        case 0x02:{std::uint16_t x=0;if(!room(2)||!rd(d,off,le,x)){r.error="truncated DW_EH_PE_udata2";return r;}u=x;off+=2;break;}
        case 0x03:{std::uint32_t x=0;if(!room(4)||!rd(d,off,le,x)){r.error="truncated DW_EH_PE_udata4";return r;}u=x;off+=4;break;}
        case 0x04:if(!room(8)||!rd(d,off,le,u)){r.error="truncated DW_EH_PE_udata8";return r;}off+=8;break;
        case 0x09:signed_value=true;if(!eh_sleb(d,off,end,sv)){r.error="invalid DW_EH_PE_sleb128";return r;}break;
        case 0x0a:{std::uint16_t x=0;if(!room(2)||!rd(d,off,le,x)){r.error="truncated DW_EH_PE_sdata2";return r;}std::int16_t y=0;std::memcpy(&y,&x,sizeof(y));sv=y;signed_value=true;off+=2;break;}
        case 0x0b:{std::uint32_t x=0;if(!room(4)||!rd(d,off,le,x)){r.error="truncated DW_EH_PE_sdata4";return r;}std::int32_t y=0;std::memcpy(&y,&x,sizeof(y));sv=y;signed_value=true;off+=4;break;}
        case 0x0c:{std::uint64_t x=0;if(!room(8)||!rd(d,off,le,x)){r.error="truncated DW_EH_PE_sdata8";return r;}std::memcpy(&sv,&x,sizeof(sv));signed_value=true;off+=8;break;}
        default:r.state=EhReadState::Unsupported;r.error="unsupported DW_EH_PE format";return r;
    }
    if(off>end){r.error="DW_EH_PE value exceeds record";return r;}
    const bool zero=signed_value?sv==0:u==0;r.is_null=zero;if(zero){r.value=0;r.state=EhReadState::Ok;return r;}
    std::uint64_t base=0;
    switch(app){case 0:case 0x50:base=0;break;case 0x10:base=field_va;break;case 0x30:base=*datarel;break;case 0x40:base=*funcrel;break;default:break;}
    if(app==0||app==0x50){if(signed_value&&sv<0){r.error="negative absolute DW_EH_PE value";return r;}r.value=signed_value?static_cast<std::uint64_t>(sv):u;}
    else if(signed_value){if(!eh_add_signed(base,sv,r.value)){r.error="relative DW_EH_PE value overflows address space";return r;}}
    else{if(u>std::numeric_limits<std::uint64_t>::max()-base){r.error="relative DW_EH_PE value overflows address space";return r;}r.value=base+u;}
    r.state=EhReadState::Ok;return r;
}

std::vector<std::uint64_t> pointer_entries(std::span<const std::uint8_t> d,std::uint64_t off,std::uint64_t sz,bool is64,bool le){
    std::vector<std::uint64_t> v; const std::size_t w=is64?8:4; if(off>=d.size())return v; auto n=std::min<std::uint64_t>(sz,d.size()-off);
    for(std::size_t p=0;p+w<=n&&v.size()<4096;p+=w){if(is64){std::uint64_t x=0;if(!rd(d,off+p,le,x))break;v.push_back(x);}else{std::uint32_t x=0;if(!rd(d,off+p,le,x))break;v.push_back(x);}} return v;
}

}

ElfInfo parse_elf(std::span<const std::uint8_t> d) {
    ElfInfo out;
    if(d.size()<0x34 || d[0]!=0x7f || d[1]!='E' || d[2]!='L' || d[3]!='F') {out.error="not ELF";return out;}
    const unsigned cls=d[4], data=d[5];
    if(cls!=1 && cls!=2){out.error="unsupported ELF class";return out;}
    if(data!=1 && data!=2){out.error="unsupported ELF endian";return out;}
    out.elf64 = cls==2;
    out.little_endian = data==1;
    const bool le=out.little_endian;
    rd(d,16,le,out.type); rd(d,18,le,out.machine);
    std::uint64_t phoff=0, shoff=0;
    std::uint16_t phentsize=0, phnum=0, shentsize=0, shnum=0, shstrndx=0;
    if(out.elf64){
        rd(d,24,le,out.entry); rd(d,32,le,phoff); rd(d,40,le,shoff);
        rd(d,54,le,phentsize); rd(d,56,le,phnum); rd(d,58,le,shentsize); rd(d,60,le,shnum); rd(d,62,le,shstrndx);
    } else {
        std::uint32_t e=0,po=0,so=0;
        rd(d,24,le,e); rd(d,28,le,po); rd(d,32,le,so);
        out.entry=e;phoff=po;shoff=so;
        rd(d,42,le,phentsize); rd(d,44,le,phnum); rd(d,46,le,shentsize); rd(d,48,le,shnum); rd(d,50,le,shstrndx);
    }
    out.section_table_present=shoff!=0 && shentsize!=0;
    EntropyMemo entropy(d);

    // Program headers are the loader-facing truth for executable/shared ELF files. Keep
    // them even when a packer or stripper removes the section table entirely.
    std::uint64_t file_end=0;
    const std::size_t min_phentsize=out.elf64?56:32;
    for(std::uint16_t i=0;i<phnum && phentsize>=min_phentsize;i++){
        const std::size_t o=static_cast<std::size_t>(phoff)+static_cast<std::size_t>(i)*phentsize;
        if(o+min_phentsize>d.size()) break;
        ElfSegment s;
        rd(d,o,le,s.type);
        if(out.elf64){
            rd(d,o+4,le,s.flags);rd(d,o+8,le,s.offset);rd(d,o+16,le,s.address);
            rd(d,o+32,le,s.file_size);rd(d,o+40,le,s.memory_size);rd(d,o+48,le,s.align);
        }else{
            std::uint32_t off=0,va=0,fs=0,ms=0,al=0;
            rd(d,o+4,le,off);rd(d,o+8,le,va);rd(d,o+16,le,fs);rd(d,o+20,le,ms);rd(d,o+24,le,s.flags);rd(d,o+28,le,al);
            s.offset=off;s.address=va;s.file_size=fs;s.memory_size=ms;s.align=al;
        }
        if(s.offset<d.size() && s.file_size){
            const auto n=static_cast<std::size_t>(std::min<std::uint64_t>(s.file_size,d.size()-s.offset));
            s.entropy=entropy.get(static_cast<std::size_t>(s.offset),n);
            std::size_t used=n;while(used&&(d[s.offset+used-1]==0||d[s.offset+used-1]==0xcc))--used;s.used_size=used;
        }
        if(s.type==3 && s.offset<d.size()) out.interpreter=zstr(d,static_cast<std::size_t>(s.offset)); // PT_INTERP
        file_end=std::max(file_end,s.offset+s.file_size);
        out.segments.push_back(std::move(s));
    }
    out.program_header_count=static_cast<std::uint16_t>(std::min<std::size_t>(out.segments.size(),0xffff));

    auto vaddr_to_file=[&](std::uint64_t va)->std::optional<std::uint64_t>{
        for(const auto&s:out.segments){
            if(s.type!=1||va<s.address)continue; // PT_LOAD
            const auto delta=va-s.address;
            if(delta<s.file_size && s.offset+delta<d.size())return s.offset+delta;
        }
        return std::nullopt;
    };
    auto vaddr_file_extent=[&](std::uint64_t va)->std::optional<std::pair<std::uint64_t,std::uint64_t>>{
        for(const auto&s:out.segments){if(s.type!=1||va<s.address)continue;const auto delta=va-s.address;if(delta>=s.file_size||s.offset+delta>=d.size())continue;const auto off=s.offset+delta;return std::pair<std::uint64_t,std::uint64_t>{off,std::min<std::uint64_t>(s.file_size-delta,d.size()-off)};}return std::nullopt;
    };
    auto vaddr_in_load_memory=[&](std::uint64_t va)->bool{
        for(const auto&s:out.segments)if(s.type==1&&va>=s.address&&va-s.address<s.memory_size)return true;
        return false;
    };

    struct RawSec { std::uint32_t name=0,type=0,link=0; std::uint64_t flags=0,addr=0,off=0,size=0,entsize=0; };
    std::vector<RawSec> raw;
    raw.reserve(shnum);
    const std::size_t min_shentsize=out.elf64?64:40;
    for(std::uint16_t i=0;i<shnum && shentsize>=min_shentsize;i++){
        const std::size_t o=static_cast<std::size_t>(shoff)+static_cast<std::size_t>(i)*shentsize;
        if(o+min_shentsize>d.size()) break;
        RawSec s; rd(d,o,le,s.name); rd(d,o+4,le,s.type);
        if(out.elf64){rd(d,o+8,le,s.flags);rd(d,o+16,le,s.addr);rd(d,o+24,le,s.off);rd(d,o+32,le,s.size);rd(d,o+40,le,s.link);rd(d,o+56,le,s.entsize);}
        else {std::uint32_t a=0,b=0,c=0,e=0,en=0;rd(d,o+8,le,a);rd(d,o+12,le,b);rd(d,o+16,le,c);rd(d,o+20,le,e);rd(d,o+24,le,s.link);rd(d,o+36,le,en);s.flags=a;s.addr=b;s.off=c;s.size=e;s.entsize=en;}
        raw.push_back(s);
        if(s.type!=8) file_end=std::max(file_end,s.off+s.size); // SHT_NOBITS has no file bytes
    }
    out.section_header_count=static_cast<std::uint16_t>(std::min<std::size_t>(raw.size(),0xffff));

    std::size_t shstr_off=0,shstr_size=0;
    if(shstrndx<raw.size()) { shstr_off=static_cast<std::size_t>(raw[shstrndx].off); shstr_size=static_cast<std::size_t>(raw[shstrndx].size); }
    for(const auto& rs:raw){
        ElfSection s; s.type=rs.type;s.flags=rs.flags;s.address=rs.addr;s.offset=rs.off;s.size=rs.size;
        if(shstr_off<d.size() && rs.name<shstr_size) s.name=zstr(d,shstr_off+rs.name);
        if(rs.type!=8 && rs.off<d.size()){
            const auto n=static_cast<std::size_t>(std::min<std::uint64_t>(rs.size,d.size()-rs.off));
            s.entropy=entropy.get(static_cast<std::size_t>(rs.off),n);
            std::size_t used=n; while(used && (d[rs.off+used-1]==0 || d[rs.off+used-1]==0xcc)) --used;
            s.used_size=used;
        }
        if(s.name==".init") out.init.has_init=true;
        else if(s.name==".fini") out.init.has_fini=true;
        else if(s.name==".ctors") out.init.has_ctors=true;
        else if(s.name==".dtors") out.init.has_dtors=true;
        if(s.name==".preinit_array"||s.name==".init_array"||s.name==".fini_array") {
            ElfInitArray a; a.kind=s.name; a.address=s.address; a.offset=s.offset; a.size=s.size; a.entries=pointer_entries(d,s.offset,s.size,out.elf64,le); out.init.arrays.push_back(std::move(a));
        }
        out.sections.push_back(std::move(s));
    }

    auto apply_dynamic_tag=[&](std::int64_t tag,std::uint64_t val){
        switch(tag){case 12:out.init.dt_init=val;break;case 13:out.init.dt_fini=val;break;case 32:out.init.dt_preinit_array=val;break;case 33:out.init.dt_preinit_arraysz=val;break;case 25:out.init.dt_init_array=val;break;case 27:out.init.dt_init_arraysz=val;break;case 26:out.init.dt_fini_array=val;break;case 28:out.init.dt_fini_arraysz=val;break;default:break;}
    };
    // Section-backed SHT_DYNAMIC remains useful when present.
    for(const auto& rs:raw){ if(rs.type!=6||rs.off>=d.size()) continue; const std::size_t entsz=rs.entsize?static_cast<std::size_t>(rs.entsize):(out.elf64?16:8); auto n=std::min<std::uint64_t>(rs.size,d.size()-rs.off);
        std::uint64_t dynstr_off=0,dynstr_size=0;if(rs.link<raw.size()){dynstr_off=raw[rs.link].off;dynstr_size=raw[rs.link].size;}
        for(std::size_t p=0;p+entsz<=n;p+=entsz){std::int64_t tag=0;std::uint64_t val=0;if(out.elf64){std::uint64_t t=0;rd(d,rs.off+p,le,t);rd(d,rs.off+p+8,le,val);tag=static_cast<std::int64_t>(t);}else{std::uint32_t t=0,v=0;rd(d,rs.off+p,le,t);rd(d,rs.off+p+4,le,v);tag=static_cast<std::int32_t>(t);val=v;} if(tag==0)break;
            if(tag==1&&dynstr_off<d.size()&&val<dynstr_size){auto lib=zstr(d,static_cast<std::size_t>(dynstr_off+val));if(!lib.empty()&&std::find(out.needed.begin(),out.needed.end(),lib)==out.needed.end())out.needed.push_back(std::move(lib));}
            apply_dynamic_tag(tag,val);
        }
    }
    // A stripped/packed ELF may have no usable section headers. PT_DYNAMIC is loader-facing
    // and therefore the more robust source for DT_NEEDED and pre-entry dynamic tags.
    for(const auto& seg:out.segments){if(seg.type!=2||seg.offset>=d.size())continue; // PT_DYNAMIC
        const std::size_t entsz=out.elf64?16:8;const auto n=std::min<std::uint64_t>(seg.file_size,d.size()-seg.offset);
        std::vector<std::pair<std::int64_t,std::uint64_t>> tags;std::uint64_t strva=0,strsz=0;
        for(std::size_t p=0;p+entsz<=n;p+=entsz){std::int64_t tag=0;std::uint64_t val=0;if(out.elf64){std::uint64_t t=0;rd(d,seg.offset+p,le,t);rd(d,seg.offset+p+8,le,val);tag=static_cast<std::int64_t>(t);}else{std::uint32_t t=0,v=0;rd(d,seg.offset+p,le,t);rd(d,seg.offset+p+4,le,v);tag=static_cast<std::int32_t>(t);val=v;}if(tag==0)break;if(tags.size()>=65536)break;tags.emplace_back(tag,val);if(tag==5)strva=val;else if(tag==10)strsz=val;apply_dynamic_tag(tag,val);}
        auto stroff=vaddr_to_file(strva);
        if(stroff){for(auto[tag,val]:tags)if(tag==1&&(!strsz||val<strsz)&&*stroff+val<d.size()){auto lib=zstr(d,static_cast<std::size_t>(*stroff+val));if(!lib.empty()&&std::find(out.needed.begin(),out.needed.end(),lib)==out.needed.end())out.needed.push_back(std::move(lib));}}
    }
    // Loader-facing deep dynamic plane. PT_DYNAMIC wins; SHT_DYNAMIC is fallback only.
    {
        auto&dy=out.dynamic;std::vector<std::pair<std::int64_t,std::uint64_t>> deep_tags;bool terminated=false,source_bad=false,dynamic_source_seen=false;std::size_t pt_dynamic_count=0;
        auto scan_dynamic=[&](std::uint64_t off,std::uint64_t size,std::uint64_t entsz)->bool{
            if(entsz!=16||off>d.size()||size>d.size()-off||size%entsz)return false;
            dy.table_file_offset=off;dy.table_size=size;
            for(std::uint64_t p=0;p+entsz<=size;p+=entsz){std::uint64_t rt=0,v=0;if(!rd(d,static_cast<std::size_t>(off+p),le,rt)||!rd(d,static_cast<std::size_t>(off+p+8),le,v))return false;const auto tag=static_cast<std::int64_t>(rt);if(tag==0){terminated=true;return true;}if(deep_tags.size()>=65536)return false;deep_tags.emplace_back(tag,v);}return false;
        };
        for(const auto&seg:out.segments)if(seg.type==2){dynamic_source_seen=true;++pt_dynamic_count;if(pt_dynamic_count==1&&!scan_dynamic(seg.offset,seg.file_size,16))source_bad=true;}
        if(pt_dynamic_count>1){source_bad=true;dy.error="multiple PT_DYNAMIC segments";}
        if(!pt_dynamic_count){for(const auto&rs:raw)if(rs.type==6){if(dynamic_source_seen){source_bad=true;dy.error="multiple SHT_DYNAMIC sections";break;}dynamic_source_seen=true;const auto entsz=rs.entsize?rs.entsize:16;if(!scan_dynamic(rs.off,rs.size,entsz))source_bad=true;}}
        if(!dynamic_source_seen)dy.state="NOT_PRESENT";
        else if(!out.elf64||!(out.machine==62||out.machine==183)){dy.state="UNSUPPORTED";dy.error="deep dynamic parsing currently supports ELF64 x86-64/AArch64";}
        else if(source_bad||!terminated){dy.state="FAILED";if(dy.error.empty())dy.error="dynamic table geometry/termination invalid";}
        else{
            bool deep_ok=true,deep_partial=false;std::string partial_error;constexpr std::uint64_t max_symbols=2000000,max_relocs=4000000,max_dynamic_memory=256ull*1024*1024,max_symbol_name=64ull*1024,reloc_map_node_estimate=64;std::map<std::int64_t,std::uint64_t> one;std::uint64_t dynamic_memory=0;dy.memory_budget_bytes=max_dynamic_memory;
            auto fail=[&](std::string e){if(deep_ok){deep_ok=false;dy.error=std::move(e);}};
            auto charge=[&](std::uint64_t bytes,const char*what)->bool{if(bytes>max_dynamic_memory-dynamic_memory){fail(std::string("dynamic metadata memory budget exceeded by ")+what);return false;}dynamic_memory+=bytes;dy.estimated_memory_bytes=dynamic_memory;return true;};
            auto keep=[&](std::int64_t tag,std::uint64_t v){switch(tag){case 2:case 3:case 4:case 5:case 6:case 7:case 8:case 9:case 10:case 11:case 17:case 18:case 19:case 20:case 23:case 35:case 36:case 37:case 0x6ffffef5:break;default:return;}auto[it,ins]=one.emplace(tag,v);if(!ins&&it->second!=v)fail("conflicting singleton dynamic tag "+std::to_string(tag));};
            for(const auto&[tag,v]:deep_tags)keep(tag,v);
            auto val=[&](std::int64_t tag)->std::uint64_t{auto it=one.find(tag);return it==one.end()?0:it->second;};
            dy.pltrel_size=val(2);dy.pltgot_va=val(3);dy.hash_va=val(4);dy.strtab_va=val(5);dy.symtab_va=val(6);dy.rela_va=val(7);dy.rela_size=val(8);dy.rela_ent=val(9);dy.strtab_size=val(10);dy.syment=val(11);dy.rel_va=val(17);dy.rel_size=val(18);dy.rel_ent=val(19);dy.pltrel_kind=val(20);dy.jmprel_va=val(23);dy.relr_size=val(35);dy.relr_va=val(36);dy.relr_ent=val(37);dy.gnu_hash_va=val(0x6ffffef5);
            std::optional<std::uint64_t> symbol_count;std::string count_source;
            auto accept_count=[&](std::uint64_t n,const char*source){
                if(!n||n>max_symbols){fail(std::string(source)+" symbol count out of bounds");return;}
                if(symbol_count&&*symbol_count!=n){fail("dynamic symbol count sources disagree");return;}
                symbol_count=n;if(count_source.empty())count_source=source;else count_source += std::string("+")+source;
            };
            if(deep_ok&&dy.hash_va){
                auto hx=vaddr_file_extent(dy.hash_va);
                if(!hx||hx->second<8)fail("DT_HASH not file-backed");
                else{std::uint32_t nb=0,nc=0;rd(d,static_cast<std::size_t>(hx->first),le,nb);rd(d,static_cast<std::size_t>(hx->first+4),le,nc);const auto words=2ull+nb+nc;if(words>hx->second/4)fail("DT_HASH table exceeds PT_LOAD file range");else accept_count(nc,"DT_HASH");}
            }
            if(deep_ok&&dy.gnu_hash_va){
                auto hx=vaddr_file_extent(dy.gnu_hash_va);
                if(!hx||hx->second<16)fail("DT_GNU_HASH not file-backed");
                else{
                    std::uint32_t nb=0,symoff=0,bloom=0,shift=0;rd(d,static_cast<std::size_t>(hx->first),le,nb);rd(d,static_cast<std::size_t>(hx->first+4),le,symoff);rd(d,static_cast<std::size_t>(hx->first+8),le,bloom);rd(d,static_cast<std::size_t>(hx->first+12),le,shift);(void)shift;
                    if(!nb||!bloom||symoff>max_symbols)fail("DT_GNU_HASH header invalid");
                    else{
                        const auto bloom_bytes=std::uint64_t(bloom)*8,bucket_bytes=std::uint64_t(nb)*4;
                        if(bloom_bytes>hx->second-16||bucket_bytes>hx->second-16-bloom_bytes)fail("DT_GNU_HASH bloom/bucket table exceeds PT_LOAD file range");
                        else{
                            const auto buckets=hx->first+16+bloom_bytes,chains=buckets+bucket_bytes,limit=hx->first+hx->second;std::uint64_t maxidx=symoff;bool any=false;
                            for(std::uint32_t i=0;i<nb&&deep_ok;++i){std::uint32_t b=0;rd(d,static_cast<std::size_t>(buckets+std::uint64_t(i)*4),le,b);if(!b)continue;if(b<symoff||b>max_symbols){fail("DT_GNU_HASH bucket symbol index invalid");break;}any=true;std::uint64_t idx=b;
                                for(std::uint64_t guard=0;guard<max_symbols;++guard,++idx){const auto ci=idx-symoff;if(ci>(limit-chains)/4||chains+ci*4+4>limit){fail("DT_GNU_HASH chain exceeds PT_LOAD file range");break;}std::uint32_t h=0;rd(d,static_cast<std::size_t>(chains+ci*4),le,h);maxidx=std::max(maxidx,idx);if(h&1)break;if(guard+1==max_symbols)fail("DT_GNU_HASH chain limit exceeded");}
                            }
                            if(deep_ok)accept_count(any?maxidx+1:symoff,"DT_GNU_HASH");
                        }
                    }
                }
            }
            if(deep_ok&&!symbol_count&&dy.symtab_va){for(const auto&rs:raw)if(rs.type==11&&rs.addr==dy.symtab_va&&rs.entsize==24&&rs.size&&rs.size%24==0){accept_count(rs.size/24,"SHT_DYNSYM");break;}}
            const bool any_sym=dy.symtab_va||dy.strtab_va||dy.strtab_size||dy.syment;
            if(deep_ok&&(dy.hash_va||dy.gnu_hash_va)&&!any_sym)fail("dynamic hash declared without DT_SYMTAB/DT_STRTAB");
            if(deep_ok&&any_sym&&!(dy.symtab_va&&dy.strtab_va&&dy.strtab_size&&dy.syment))fail("incomplete DT_SYMTAB/DT_STRTAB geometry");
            if(deep_ok&&any_sym&&dy.syment!=24)fail("DT_SYMENT is not ELF64 symbol size");
            if(deep_ok&&any_sym&&!symbol_count){deep_partial=true;partial_error="dynamic symbol count unavailable (no valid DT_HASH/DT_GNU_HASH/SHT_DYNSYM)";}
            if(deep_ok&&symbol_count){
                auto st=vaddr_file_extent(dy.symtab_va),str=vaddr_file_extent(dy.strtab_va);
                if(!st||!str)fail("dynamic symbol/string table not file-backed");
                else if(dy.strtab_size>str->second)fail("DT_STRSZ exceeds PT_LOAD file range");
                else{
                    std::uint64_t sym_extent=st->second;for(const auto q:{dy.strtab_va,dy.hash_va,dy.gnu_hash_va,dy.rela_va,dy.rel_va,dy.jmprel_va,dy.relr_va})if(q>dy.symtab_va)sym_extent=std::min(sym_extent,q-dy.symtab_va);
                    if(*symbol_count>sym_extent/24)fail("dynamic symbol table overlaps next loader table");
                    if(deep_ok){
                        if(*symbol_count>max_dynamic_memory/sizeof(ElfDynamicSymbol))fail("dynamic symbol objects exceed memory budget");
                        else if(charge(*symbol_count*sizeof(ElfDynamicSymbol),"dynamic symbol objects")){
                            dy.symtab_file_offset=st->first;dy.strtab_file_offset=str->first;dy.symbol_count_source=count_source;dy.symbols.reserve(static_cast<std::size_t>(*symbol_count));
                            for(std::uint64_t i=0;i<*symbol_count&&deep_ok;++i){
                                const auto o=st->first+i*24;ElfDynamicSymbol x;x.index=static_cast<std::uint32_t>(i);x.entry_file_offset=o;
                                rd(d,static_cast<std::size_t>(o),le,x.name_offset);x.info=d[static_cast<std::size_t>(o+4)];x.other=d[static_cast<std::size_t>(o+5)];rd(d,static_cast<std::size_t>(o+6),le,x.section_index);rd(d,static_cast<std::size_t>(o+8),le,x.value);rd(d,static_cast<std::size_t>(o+16),le,x.size);
                                x.binding=x.info>>4;x.type=x.info&0xf;x.visibility=x.other&3;
                                if(x.name_offset>=dy.strtab_size){fail("dynamic symbol name offset outside DT_STRTAB");break;}
                                const auto name_remain=dy.strtab_size-x.name_offset;const auto name_limit=std::min<std::uint64_t>(name_remain,max_symbol_name+1);auto nm=zstr_bounded(d,str->first+x.name_offset,name_limit);if(!nm){fail(name_remain>max_symbol_name?"dynamic symbol name exceeds 64 KiB limit":"dynamic symbol name is not terminated within DT_STRSZ");break;}if(!charge(nm->size(),"dynamic symbol names"))break;x.name=std::move(*nm);
                                const bool loader_binding=x.binding==1||x.binding==2||x.binding==10;
                                x.imported=x.section_index==0&&loader_binding&&!x.name.empty();
                                x.exported=x.section_index!=0&&x.section_index!=0xffff&&loader_binding&&(x.visibility==0||x.visibility==3)&&!x.name.empty();
                                if(x.value&&x.type!=6)if(auto vo=vaddr_to_file(x.value)){x.value_file_backed=true;x.value_file_offset=*vo;}
                                dy.symbols.push_back(std::move(x));
                            }
                        }
                    }
                }
            }
            std::map<std::uint64_t,std::size_t> reloc_entries;
            auto parse_reloc=[&](std::uint64_t va,std::uint64_t sz,std::uint64_t ent,bool rela,const char*source,bool plt){
                if(!deep_ok||(!va&&!sz))return;
                if(!va||!sz){fail(std::string(source)+" relocation geometry incomplete");return;}
                const std::uint64_t expected=rela?24:16;if(ent!=expected||sz%expected){fail(std::string(source)+" relocation entry size invalid");return;}
                auto ex=vaddr_file_extent(va);if(!ex||sz>ex->second){fail(std::string(source)+" relocation table not bounded by PT_LOAD file range");return;}if(sz/expected>max_relocs){fail(std::string(source)+" relocation count out of bounds");return;}
                for(std::uint64_t p=0;p<sz&&deep_ok;p+=expected){
                    const auto eo=ex->first+p;std::uint64_t target=0,info=0;std::int64_t add=0;rd(d,static_cast<std::size_t>(eo),le,target);rd(d,static_cast<std::size_t>(eo+8),le,info);if(rela){std::uint64_t raw=0;rd(d,static_cast<std::size_t>(eo+16),le,raw);std::memcpy(&add,&raw,sizeof(add));}
                    const auto si=static_cast<std::uint32_t>(info>>32),rt=static_cast<std::uint32_t>(info);
                    if(!vaddr_in_load_memory(target)){fail(std::string(source)+" relocation target outside PT_LOAD memory");break;}
                    if(symbol_count&&si>=*symbol_count){fail(std::string(source)+" relocation symbol index outside dynamic symbol table");break;}
                    auto old=reloc_entries.find(eo);if(old!=reloc_entries.end()){auto&x=dy.relocations[old->second];x.plt=x.plt||plt;if(plt)x.source="DT_JMPREL";continue;}
                    ElfRelocation x;x.source=source;x.entry_file_offset=eo;x.target_va=target;x.type=rt;x.type_name=elf_reloc_name(out.machine,rt);x.symbol_index=si;x.addend=add;x.has_addend=rela;x.plt=plt;
                    if(auto to=vaddr_to_file(target)){x.target_file_backed=true;x.target_file_offset=*to;}
                    if(si<dy.symbols.size()){const auto&sym=dy.symbols[si];x.symbol_imported=sym.imported;x.symbol_exported=sym.exported;}
                    const auto mem=2ull*sizeof(ElfRelocation)+reloc_map_node_estimate+x.source.size()+x.type_name.size();if(!charge(mem,"relocation rows/bookkeeping"))break;reloc_entries.emplace(eo,dy.relocations.size());dy.relocations.push_back(std::move(x));
                }
            };
            if(deep_ok&&(dy.rela_va||dy.rela_size||dy.rela_ent))parse_reloc(dy.rela_va,dy.rela_size,dy.rela_ent,true,"DT_RELA",false);
            if(deep_ok&&(dy.rel_va||dy.rel_size||dy.rel_ent))parse_reloc(dy.rel_va,dy.rel_size,dy.rel_ent,false,"DT_REL",false);
            if(deep_ok&&(dy.jmprel_va||dy.pltrel_size||dy.pltrel_kind)){
                if(!(dy.jmprel_va&&dy.pltrel_size&&(dy.pltrel_kind==7||dy.pltrel_kind==17)))fail("DT_JMPREL/DT_PLTREL geometry invalid");
                else parse_reloc(dy.jmprel_va,dy.pltrel_size,dy.pltrel_kind==7?24u:16u,dy.pltrel_kind==7,"DT_JMPREL",true);
            }
            if(deep_ok&&(dy.relr_va||dy.relr_size||dy.relr_ent)){
                if(!(dy.relr_va&&dy.relr_size&&dy.relr_ent==8&&dy.relr_size%8==0))fail("DT_RELR geometry invalid");
                else if(auto ex=vaddr_file_extent(dy.relr_va);!ex||dy.relr_size>ex->second)fail("DT_RELR table not bounded by PT_LOAD file range");
                else{
                    const auto relr_ex=*vaddr_file_extent(dy.relr_va);std::uint64_t cursor=0,last_target=0;bool have_cursor=false,have_target=false;std::uint64_t expanded=0;
                    const auto relative_type=out.machine==62?8u:1027u;const auto relative_name=elf_reloc_name(out.machine,relative_type);
                    auto emit_relr=[&](std::uint64_t target,std::uint64_t entry_off){
                        if((target&7u)||!vaddr_in_load_memory(target)){fail("DT_RELR target invalid or outside PT_LOAD memory");return;}
                        if(have_target&&target<=last_target){fail("DT_RELR targets are not strictly increasing");return;}
                        if(++expanded>max_relocs){fail("DT_RELR expanded relocation count out of bounds");return;}
                        ElfRelocation x;x.source="DT_RELR";x.entry_file_offset=entry_off;x.target_va=target;x.type=relative_type;x.type_name=relative_name;
                        if(auto to=vaddr_to_file(target)){x.target_file_backed=true;x.target_file_offset=*to;}
                        const auto mem=2ull*sizeof(ElfRelocation)+x.source.size()+x.type_name.size();if(!charge(mem,"DT_RELR expanded rows"))return;dy.relocations.push_back(std::move(x));last_target=target;have_target=true;
                    };
                    for(std::uint64_t p=0;p<dy.relr_size&&deep_ok;p+=8){
                        std::uint64_t word=0;const auto entry_off=relr_ex.first+p;rd(d,static_cast<std::size_t>(entry_off),le,word);
                        if(!(word&1u)){
                            if(word&7u){fail("DT_RELR direct target is not pointer aligned");break;}
                            if(have_cursor&&word<cursor){fail("DT_RELR direct target moves backwards");break;}
                            emit_relr(word,entry_off);if(!deep_ok)break;
                            if(word>std::numeric_limits<std::uint64_t>::max()-8){fail("DT_RELR direct target overflow");break;}cursor=word+8;have_cursor=true;
                        }else{
                            if(!have_cursor){fail("DT_RELR bitmap appears before direct base");break;}
                            const auto bitmap=word>>1;
                            for(unsigned bit=0;bit<63&&deep_ok;++bit)if(bitmap&(std::uint64_t(1)<<bit)){
                                if(cursor>std::numeric_limits<std::uint64_t>::max()-std::uint64_t(bit)*8){fail("DT_RELR bitmap target overflow");break;}
                                emit_relr(cursor+std::uint64_t(bit)*8,entry_off);
                            }
                            if(!deep_ok)break;
                            constexpr std::uint64_t span=63u*8u;if(cursor>std::numeric_limits<std::uint64_t>::max()-span){fail("DT_RELR bitmap cursor overflow");break;}cursor+=span;
                        }
                    }
                }
            }
            if(!deep_ok)dy.state="FAILED";else if(deep_partial){dy.state="PARTIAL";dy.error=partial_error;}else{dy.state="RESOLVED";dy.error.clear();}
        }
    }
    // Independent implicit-loader plane. This intentionally reparses only bounded loader-facing
    // metadata instead of depending on ElfDynamicInfo success. Weird/malformed dynamic symbols may
    // therefore fail the ordinary strict plane while still leaving exact raw loader facts here.
    {
        auto& im=out.implicit_exec;
        constexpr std::size_t max_facts=65536;
        constexpr std::uint64_t max_raw_relocations=4000000,max_raw_symbol_index=4000000,max_init_bytes=16ull*1024*1024;
        bool plane_partial=false;
        auto limit=[&](const std::string& why){im.analysis_limited=true;plane_partial=true;if(im.error.empty())im.error=why;};
        auto add_fact=[&](ImplicitExecutionFact f)->std::int64_t{
            if(im.facts.size()>=max_facts){limit("implicit execution fact budget exceeded");return -1;}
            if(f.format=="ELF"&&f.source_size&&f.source_file_offset<=d.size()&&f.source_size<=d.size()-f.source_file_offset)f.source_file_backed=true;
            f.index=static_cast<std::uint32_t>(im.facts.size());
            if(f.priority=="HIGH")++im.high_priority_count;else if(f.priority=="REVIEW")++im.review_count;else ++im.informational_count;
            if(f.anomaly_class!="NONE"&& !f.anomaly_class.empty())++im.anomaly_count;
            if(f.evidence_state=="UNRESOLVED_RUNTIME_SEMANTICS")++im.unresolved_runtime_semantics;
            if(f.relation=="raw_loader_symbol_record")++im.raw_loader_symbol_count;
            const auto idx=static_cast<std::int64_t>(f.index);im.facts.push_back(std::move(f));return idx;
        };
        auto load_segment=[&](std::uint64_t va,std::uint64_t size)->const ElfSegment*{
            if(!size||va>std::numeric_limits<std::uint64_t>::max()-size)return nullptr;
            for(const auto&s:out.segments){if(s.type!=1||va<s.address)continue;const auto delta=va-s.address;if(delta<s.memory_size&&size<=s.memory_size-delta)return &s;}return nullptr;
        };
        auto mutability=[&](std::uint64_t va,std::uint64_t size)->std::string{
            const auto*s=load_segment(va,size);if(!s)return "UNMAPPED";const bool w=(s->flags&2)!=0,x=(s->flags&1)!=0;if(w&&x)return "WRITABLE_EXECUTABLE";if(w)return "WRITABLE";if(x)return "EXECUTABLE";return "READ_ONLY";
        };
        auto is_wx=[&](std::uint64_t va,std::uint64_t size)->bool{const auto*s=load_segment(va,size);return s&&(s->flags&3)==3;};
        auto dyn_tag_name=[](std::int64_t t)->std::string{switch(t){case 2:return"DT_PLTRELSZ";case 3:return"DT_PLTGOT";case 4:return"DT_HASH";case 5:return"DT_STRTAB";case 6:return"DT_SYMTAB";case 7:return"DT_RELA";case 8:return"DT_RELASZ";case 9:return"DT_RELAENT";case 10:return"DT_STRSZ";case 11:return"DT_SYMENT";case 12:return"DT_INIT";case 13:return"DT_FINI";case 17:return"DT_REL";case 18:return"DT_RELSZ";case 19:return"DT_RELENT";case 20:return"DT_PLTREL";case 23:return"DT_JMPREL";case 25:return"DT_INIT_ARRAY";case 26:return"DT_FINI_ARRAY";case 27:return"DT_INIT_ARRAYSZ";case 28:return"DT_FINI_ARRAYSZ";case 32:return"DT_PREINIT_ARRAY";case 33:return"DT_PREINIT_ARRAYSZ";case 35:return"DT_RELRSZ";case 36:return"DT_RELR";case 37:return"DT_RELRENT";case 0x6ffffef5:return"DT_GNU_HASH";case 0x6ffffff0:return"DT_VERSYM";case 0x6ffffffc:return"DT_VERDEF";case 0x6ffffffe:return"DT_VERNEED";default:return"DT_"+std::to_string(t);}};

        if(!out.elf64||!le||!(out.machine==62||out.machine==183)){
            im.state="UNSUPPORTED";im.error="implicit ELF loader analysis currently supports little-endian ELF64 x86-64/AArch64";
        }else{
            struct DynRec{std::int64_t tag=0;std::uint64_t value=0,file=0,va=0;};
            std::vector<DynRec> dr;std::uint64_t dyn_off=0,dyn_va=0,dyn_size=0;bool dyn_terminated=false;std::size_t dyn_sources=0;
            auto scan_dyn=[&](std::uint64_t off,std::uint64_t va,std::uint64_t size)->bool{
                if(off>d.size()||size>d.size()-off||size%16)return false;
                dyn_off=off;dyn_va=va;dyn_size=size;
                for(std::uint64_t p=0;p+16<=size&&dr.size()<65536;p+=16){std::uint64_t rt=0,v=0;if(!rd(d,static_cast<std::size_t>(off+p),le,rt)||!rd(d,static_cast<std::size_t>(off+p+8),le,v))return false;const auto tag=static_cast<std::int64_t>(rt);if(tag==0){dyn_terminated=true;return true;}dr.push_back({tag,v,off+p,va+p});}
                return false;
            };
            for(const auto&s:out.segments)if(s.type==2){++dyn_sources;if(dyn_sources==1&&!scan_dyn(s.offset,s.address,s.file_size))plane_partial=true;}
            if(dyn_sources>1){plane_partial=true;if(im.error.empty())im.error="multiple PT_DYNAMIC segments; implicit plane retained first source only";}
            if(!dyn_sources){for(const auto&rs:raw)if(rs.type==6){++dyn_sources;if(dyn_sources==1&&!scan_dyn(rs.off,rs.addr,rs.size))plane_partial=true;else if(dyn_sources>1){plane_partial=true;break;}}}
            if(!dyn_sources){im.state="NOT_PRESENT";}
            else{
                if(!dyn_terminated){plane_partial=true;if(im.error.empty())im.error="loader dynamic table lacks bounded DT_NULL termination";}
                std::map<std::int64_t,std::uint64_t> last;
                std::map<std::int64_t,const DynRec*> last_rec;
                for(const auto&r:dr){last[r.tag]=r.value;last_rec[r.tag]=&r;}
                auto tv=[&](std::int64_t t)->std::uint64_t{auto it=last.find(t);return it==last.end()?0:it->second;};
                auto tr=[&](std::int64_t t)->const DynRec*{auto it=last_rec.find(t);return it==last_rec.end()?nullptr:it->second;};
                auto surface=[&](const DynRec*src,const std::string&phase,const std::string&trigger,const std::string&source_kind,std::uint64_t target,const std::string&condition){
                    if(!src||!target)return;
                    ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase=phase;f.trigger=trigger;f.relation="implicit_callback";f.source_kind=source_kind;f.source_file_offset=src->file;f.source_va=src->va;f.source_size=16;f.target_kind="function_va";f.target_va=target;if(auto o=vaddr_to_file(target)){f.target_file_backed=true;f.target_file_offset=*o;}f.evidence_state="EXACT";f.mutability=mutability(target,1);f.execution_condition=condition;f.priority="INFORMATIONAL";f.priority_reason="loader/runtime invokes a structurally declared target outside the explicit entry CFG";if(is_wx(target,1)){f.anomaly_class="IMPLICIT_TARGET_IN_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="implicit loader callback target lies in writable executable storage";}add_fact(std::move(f));
                };
                surface(tr(12),"runtime_initialization","DT_INIT","dynamic_tag",tv(12),"dynamic loader processes DT_INIT before transferring to the program entry path");

                struct InitRange{std::string kind,phase,trigger;std::uint64_t va=0,size=0;const DynRec*src=nullptr;};
                std::vector<InitRange> init_ranges;
                auto add_init=[&](std::int64_t ptag,std::int64_t stag,const char*kind,const char*phase,const char*trigger){const auto va=tv(ptag),sz=tv(stag);if(!va&&!sz)return;if(!va||!sz||sz>max_init_bytes||sz%8){plane_partial=true;return;}init_ranges.push_back({kind,phase,trigger,va,sz,tr(ptag)});auto ex=vaddr_file_extent(va);if(!ex||sz>ex->second){plane_partial=true;return;}const auto count=sz/8;for(std::uint64_t i=0;i<count&&im.facts.size()<max_facts;++i){std::uint64_t target=0;rd(d,static_cast<std::size_t>(ex->first+i*8),le,target);if(!target)continue;ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase=phase;f.trigger=trigger;f.relation="implicit_callback";f.source_kind=kind;f.source_index=i;f.source_file_offset=ex->first+i*8;f.source_va=va+i*8;f.source_size=8;f.target_kind="function_va";f.target_va=target;if(auto o=vaddr_to_file(target)){f.target_file_backed=true;f.target_file_offset=*o;}f.evidence_state="EXACT";f.mutability=mutability(target,1);f.execution_condition=std::string("loader consumes ")+kind+" slot";f.priority="INFORMATIONAL";f.priority_reason="initializer slot is an ordinary implicit execution surface";if(is_wx(target,1)){f.anomaly_class="IMPLICIT_TARGET_IN_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="initializer target lies in writable executable storage";}add_fact(std::move(f));}}
                ;
                add_init(32,33,"DT_PREINIT_ARRAY_SLOT","loader_pre_entry","DT_PREINIT_ARRAY");
                add_init(25,27,"DT_INIT_ARRAY_SLOT","runtime_initialization","DT_INIT_ARRAY");

                // Resolved ordinary IFUNC symbols are normal implicit first-resolution surfaces.
                if(out.dynamic.state=="RESOLVED")for(const auto&s:out.dynamic.symbols)if(s.type==10&&s.section_index!=0&&s.value){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="GNU_IFUNC";f.relation="resolver_callback";f.source_kind="DT_SYMTAB_GNU_IFUNC";f.source_index=s.index;f.source_file_offset=s.entry_file_offset;f.source_va=out.dynamic.symtab_va+std::uint64_t(s.index)*24;f.source_size=24;f.target_kind="resolver_function_va";f.target_va=s.value;f.target_name=s.name;if(auto o=vaddr_to_file(s.value)){f.target_file_backed=true;f.target_file_offset=*o;}f.evidence_state="EXACT";f.mutability=mutability(s.value,1);f.execution_condition="dynamic loader resolves a GNU IFUNC symbol";f.priority="INFORMATIONAL";f.priority_reason="GNU IFUNC is a normal loader-managed resolver surface";if(is_wx(s.value,1)){f.anomaly_class="IFUNC_RESOLVER_IN_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="GNU IFUNC resolver lies in writable executable storage";}add_fact(std::move(f));}

                struct RelRange{std::string source;std::uint64_t va=0,off=0,size=0,declared_size=0,ent=0,trailing=0;bool rela=false;};
                std::vector<RelRange> rr;
                auto add_rr=[&](const char*source,std::uint64_t va,std::uint64_t sz,std::uint64_t ent,bool rela){
                    if(!va&&!sz)return;
                    if(!va||!sz||ent!=(rela?24u:16u)){plane_partial=true;return;}
                    auto ex=vaddr_file_extent(va);if(!ex||sz>ex->second){plane_partial=true;return;}
                    const auto trailing=sz%ent;const auto scan=sz-trailing;
                    if(trailing)plane_partial=true;
                    rr.push_back({source,va,ex->first,scan,sz,ent,trailing,rela});
                };
                add_rr("DT_RELA",tv(7),tv(8),tv(9),true);
                add_rr("DT_REL",tv(17),tv(18),tv(19),false);
                if(tv(23)||tv(2)||tv(20)){if(tv(20)==7)add_rr("DT_JMPREL",tv(23),tv(2),24,true);else if(tv(20)==17)add_rr("DT_JMPREL",tv(23),tv(2),16,false);else plane_partial=true;}
                std::sort(rr.begin(),rr.end(),[](const auto&a,const auto&b){return a.off<b.off;});

                bool need_effect_preview=false;
                struct EmbeddedRange{std::string kind;std::uint64_t file=0,size=0,child_va=0,child_file_base=0;};
                constexpr std::size_t max_embedded_elf_objects=2048;
                std::vector<EmbeddedRange> embedded_ranges;
                std::set<std::uint64_t> embedded_bases;
                std::set<std::uint64_t> embedded_runtime_boundary_reported;
                auto parent_file_loaded=[&](std::uint64_t off,std::uint64_t size)->bool{if(!size||off>std::numeric_limits<std::uint64_t>::max()-size)return false;for(const auto&s:out.segments){if(s.type!=1||off<s.offset)continue;const auto delta=off-s.offset;if(delta<s.file_size&&size<=s.file_size-delta)return true;}return false;};
                auto inspect_embedded=[&](std::uint64_t base){
                    if(base==0||!parent_file_loaded(base,64)||base>d.size()||64>d.size()-base)return;
                    if(embedded_bases.size()>=max_embedded_elf_objects){limit("embedded ELF structural-object budget exceeded");return;}
                    if(d[base]!=0x7f||d[base+1]!='E'||d[base+2]!='L'||d[base+3]!='F'||d[base+4]!=2||d[base+5]!=1||d[base+6]!=1)return;
                    std::uint16_t et=0,em=0,phents=0,phnum=0;std::uint64_t phoff=0;rd(d,base+16,true,et);rd(d,base+18,true,em);rd(d,base+32,true,phoff);rd(d,base+54,true,phents);rd(d,base+56,true,phnum);if((et!=2&&et!=3)||(em!=62&&em!=183)||phents<56||!phnum||phnum>256||phoff>d.size()-base||std::uint64_t(phnum)>((d.size()-base-phoff)/phents))return;
                    struct CSeg{std::uint32_t type=0,flags=0;std::uint64_t off=0,va=0,fs=0,ms=0;};std::vector<CSeg> cs;const CSeg*dyn=nullptr;std::size_t dyn_count=0,load_count=0;
                    for(std::uint16_t i=0;i<phnum;++i){const auto o=base+phoff+std::uint64_t(i)*phents;CSeg x;rd(d,o,true,x.type);rd(d,o+4,true,x.flags);rd(d,o+8,true,x.off);rd(d,o+16,true,x.va);rd(d,o+32,true,x.fs);rd(d,o+40,true,x.ms);if(x.off>d.size()-base||x.fs>d.size()-base-x.off)return;cs.push_back(x);if(x.type==1)++load_count;}
                    for(const auto&x:cs)if(x.type==2){dyn=&x;++dyn_count;}
                    if(!load_count||dyn_count!=1||!dyn||!dyn->fs||dyn->fs%16||dyn->fs>4ull*1024*1024)return;
                    auto cextent=[&](std::uint64_t va)->std::optional<std::pair<std::uint64_t,std::uint64_t>>{for(const auto&s:cs){if(s.type!=1||va<s.va)continue;const auto delta=va-s.va;if(delta>=s.fs||base+s.off+delta>=d.size())continue;return std::pair<std::uint64_t,std::uint64_t>{base+s.off+delta,std::min<std::uint64_t>(s.fs-delta,d.size()-(base+s.off+delta))};}return std::nullopt;};
                    bool dyn_in_load=false;for(const auto&s:cs)if(s.type==1&&dyn->va>=s.va&&dyn->va-s.va<s.fs&&dyn->fs<=s.fs-(dyn->va-s.va)){dyn_in_load=true;break;}if(!dyn_in_load)return;
                    std::map<std::int64_t,std::uint64_t> ct;bool term=false;const auto doff=base+dyn->off;for(std::uint64_t p=0;p+16<=dyn->fs&&ct.size()<65536;p+=16){std::uint64_t rt=0,v=0;rd(d,doff+p,true,rt);rd(d,doff+p+8,true,v);const auto tag=static_cast<std::int64_t>(rt);if(tag==0){term=true;break;}ct[tag]=v;}if(!term)return;
                    embedded_bases.insert(base);embedded_ranges.push_back({"embedded_elf_dynamic_control",doff,dyn->fs,dyn->va,base});
                    auto cv=[&](std::int64_t t)->std::uint64_t{auto it=ct.find(t);return it==ct.end()?0:it->second;};
                    const auto sym=cv(6),syment=cv(11);if(sym&&syment==24)if(auto ex=cextent(sym)){auto extent=ex->second;for(const auto q:{cv(5),cv(4),cv(0x6ffffef5),cv(7),cv(17),cv(23),cv(36),cv(0x6ffffff0),cv(0x6ffffffc),cv(0x6ffffffe)})if(q>sym)extent=std::min(extent,q-sym);if(extent>=24)embedded_ranges.push_back({"embedded_elf_dynamic_symbol_table",ex->first,extent,sym,base});}
                    auto cr=[&](const char*kind,std::uint64_t va,std::uint64_t sz,std::uint64_t ent){if(!va||!sz||!ent||sz%ent)return;auto ex=cextent(va);if(ex&&sz<=ex->second)embedded_ranges.push_back({kind,ex->first,sz,va,base});};
                    cr("embedded_elf_relocation_table",cv(7),cv(8),cv(9));cr("embedded_elf_relocation_table",cv(17),cv(18),cv(19));if(cv(20)==7)cr("embedded_elf_relocation_table",cv(23),cv(2),24);else if(cv(20)==17)cr("embedded_elf_relocation_table",cv(23),cv(2),16);
                    auto ci=[&](const char*kind,std::uint64_t va,std::uint64_t sz){if(!va||!sz||sz%8)return;auto ex=cextent(va);if(ex&&sz<=ex->second)embedded_ranges.push_back({kind,ex->first,sz,va,base});};ci("embedded_elf_preinit_array",cv(32),cv(33));ci("embedded_elf_init_array",cv(25),cv(27));
                };
                const std::array<std::uint8_t,4> elfmagic={0x7f,'E','L','F'};
                const bool has_textrel=last.count(22)!=0;
                for(const auto&s:out.segments){if(s.type!=1||(!has_textrel&&!(s.flags&2))||!s.file_size||s.offset>=d.size())continue;const auto end=s.offset+std::min<std::uint64_t>(s.file_size,d.size()-s.offset);auto it=d.begin()+static_cast<std::ptrdiff_t>(s.offset),last_it=d.begin()+static_cast<std::ptrdiff_t>(end);while(it<last_it){it=std::search(it,last_it,elfmagic.begin(),elfmagic.end());if(it==last_it)break;const auto base=static_cast<std::uint64_t>(it-d.begin());inspect_embedded(base);it+=4;}}
                auto embedded_loc=[&](std::uint64_t off)->const EmbeddedRange*{for(const auto&x:embedded_ranges)if(off>=x.file&&off-x.file<x.size)return &x;return nullptr;};
                auto embedded_dependency=[&](const RelRange&r,std::uint64_t eo,std::uint64_t ev,std::uint64_t target,std::uint64_t to,const EmbeddedRange&x,std::int64_t dep)->std::int64_t{ImplicitExecutionFact f;f.depends_on_fact_index=dep;f.format="ELF";f.ecosystem="native";f.phase="module_load";f.trigger="ELF_RELOCATION_WRITE";f.relation="loader_metadata_write_dependency";f.source_kind=r.source+"_RECORD";f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind=x.kind;f.target_va=target;f.target_file_backed=true;f.target_file_offset=to;f.evidence_state="EXACT";f.mutability=mutability(target,8);f.execution_condition="relocation writes bytes that are structurally part of a bounded embedded ELF loader object";f.anomaly_class="RELOCATION_TARGETS_EMBEDDED_ELF_LOADER_METADATA";f.priority="HIGH";f.priority_reason="loader relocation deterministically targets loader metadata of a distinct embedded ELF object";std::ostringstream q;q<<"embedded_elf_file=0x"<<std::hex<<x.child_file_base<<";child_metadata_va=0x"<<x.child_va;f.detail=q.str();need_effect_preview=true;const auto idx=add_fact(std::move(f));if(embedded_runtime_boundary_reported.insert(x.child_file_base).second){ImplicitExecutionFact u;u.depends_on_fact_index=idx;u.format="ELF";u.ecosystem="native";u.phase="module_load";u.trigger="EMBEDDED_ELF_LATER_LOAD";u.relation="runtime_semantics_boundary";u.source_kind=x.kind;u.source_file_offset=x.file;u.source_va=x.child_va;u.source_size=x.size;u.target_kind="embedded_elf_loader_object";u.target_file_backed=true;u.target_file_offset=x.child_file_base;u.evidence_state="UNRESOLVED_RUNTIME_SEMANTICS";u.mutability="UNKNOWN";u.execution_condition="whether this structurally valid embedded ELF is later mapped/loaded as a module is not inferred without an independent load trigger";u.anomaly_class="EMBEDDED_ELF_LOAD_CONDITION_UNRESOLVED";u.priority="REVIEW";u.priority_reason="metadata dependency is exact but later module-load consumption is a separate runtime condition";add_fact(std::move(u));}return idx;};
                auto section_covers=[&](const RelRange&r)->bool{if(!out.section_table_present)return true;const auto typ=r.rela?4u:9u;for(const auto&s:raw)if(s.type==typ&&s.off<=r.off&&(r.off-s.off)<=s.size&&r.declared_size<=s.size-(r.off-s.off))return true;return false;};
                for(const auto&r:rr){const auto*seg=load_segment(r.va,r.declared_size);if(seg&&(seg->flags&2)){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="LOADER_RELOCATION_TABLE";f.relation="loader_metadata_storage";f.source_kind=r.source;f.source_file_offset=r.off;f.source_va=r.va;f.source_size=r.declared_size;f.target_kind="relocation_table";f.evidence_state="EXACT";f.mutability=mutability(r.va,r.declared_size);f.execution_condition="dynamic loader reads this declared relocation range; only complete physical records are statically decoded";f.anomaly_class="WRITABLE_LOADER_RELOCATION_STORAGE";f.priority="HIGH";f.priority_reason="loader-visible relocation storage resides in a writable mapping";add_fact(std::move(f));}if(r.trailing){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="LOADER_RELOCATION_TABLE";f.relation="loader_metadata_geometry";f.source_kind=r.source;f.source_file_offset=r.off;f.source_va=r.va;f.source_size=r.declared_size;f.target_kind="relocation_table";f.evidence_state="EXACT";f.mutability=mutability(r.va,r.declared_size);f.execution_condition="loader-visible relocation size is retained exactly, while the static decoder stops before the incomplete trailing bytes";f.anomaly_class="LOADER_RELOCATION_SIZE_NOT_ENTRY_ALIGNED";f.priority="REVIEW";f.priority_reason="declared relocation range is not an integer number of ABI relocation records";std::ostringstream q;q<<"entry_size="<<r.ent<<";trailing_bytes="<<r.trailing;f.detail=q.str();add_fact(std::move(f));}if(!section_covers(r)){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="LOADER_RELOCATION_TABLE";f.relation="section_metadata_divergence";f.source_kind=r.source;f.source_file_offset=r.off;f.source_va=r.va;f.source_size=r.declared_size;f.target_kind="relocation_table";f.evidence_state="EXACT";f.mutability=mutability(r.va,r.declared_size);f.execution_condition="loader consumes the dynamic relocation range independently of section-table partitioning";f.anomaly_class="LOADER_RELOCATION_SECTION_DIVERGENCE";f.priority="REVIEW";f.priority_reason="loader-visible relocation range is not wholly represented by a matching relocation section";add_fact(std::move(f));}}

                const auto symva=tv(6),syment=tv(11),strva=tv(5),strsz=tv(10);std::uint64_t sym_extent=0,symoff=0,stroff=0;
                if(symva&&syment==24){if(auto ex=vaddr_file_extent(symva)){symoff=ex->first;sym_extent=ex->second;for(const auto q:{strva,tv(4),tv(0x6ffffef5),tv(7),tv(17),tv(23),tv(36),tv(0x6ffffff0),tv(0x6ffffffc),tv(0x6ffffffe)})if(q>symva)sym_extent=std::min(sym_extent,q-symva);if(const auto*s=load_segment(symva,std::min<std::uint64_t>(sym_extent,24));s&&(s->flags&2)){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="DT_SYMTAB";f.relation="loader_metadata_storage";f.source_kind="DT_SYMTAB";f.source_file_offset=symoff;f.source_va=symva;f.source_size=sym_extent;f.target_kind="dynamic_symbol_table";f.evidence_state="EXACT";f.mutability=mutability(symva,std::min<std::uint64_t>(sym_extent,24));f.execution_condition="dynamic loader reads symbol records during relocation/resolution";f.anomaly_class="WRITABLE_LOADER_DYNSYM_STORAGE";f.priority="HIGH";f.priority_reason="loader-visible dynamic symbol storage resides in a writable mapping";add_fact(std::move(f));}}}
                if(strva&&strsz)if(auto ex=vaddr_file_extent(strva);ex&&strsz<=ex->second)stroff=ex->first;

                struct RawSym{bool valid=false;std::uint32_t index=0,name_off=0;std::uint8_t info=0,other=0;std::uint16_t shndx=0;std::uint64_t value=0,size=0,file=0,va=0;std::string name;};
                auto raw_sym=[&](std::uint32_t idx)->RawSym{RawSym x;x.index=idx;if(!symoff||sym_extent<24||syment!=24||idx>max_raw_symbol_index||std::uint64_t(idx)>=sym_extent/24)return x;const auto o=symoff+std::uint64_t(idx)*24;if(o>d.size()||24>d.size()-o)return x;x.file=o;x.va=symva+std::uint64_t(idx)*24;rd(d,static_cast<std::size_t>(o),le,x.name_off);x.info=d[static_cast<std::size_t>(o+4)];x.other=d[static_cast<std::size_t>(o+5)];rd(d,static_cast<std::size_t>(o+6),le,x.shndx);rd(d,static_cast<std::size_t>(o+8),le,x.value);rd(d,static_cast<std::size_t>(o+16),le,x.size);if(stroff&&x.name_off<strsz){const auto remain=strsz-x.name_off;auto n=zstr_bounded(d,stroff+x.name_off,std::min<std::uint64_t>(remain,4096));if(n)x.name=std::move(*n);}x.valid=true;return x;};
                std::set<std::uint32_t> raw_reported;

                struct RelLoc{const RelRange*r=nullptr;std::uint64_t record_off=0;std::string field;};
                auto relocation_loc=[&](std::uint64_t off)->std::optional<RelLoc>{for(const auto&r:rr){if(off<r.off||off>=r.off+r.size)continue;const auto rel=off-r.off,rec=r.off+(rel/r.ent)*r.ent,pos=rel%r.ent;std::string field;if(pos<8)field="r_offset";else if(pos<16)field="r_info";else if(r.rela&&pos<24)field="r_addend";else continue;return RelLoc{&r,rec,field};}return std::nullopt;};
                auto dynamic_loc=[&](std::uint64_t off)->const DynRec*{if(off<dyn_off||off>=dyn_off+dyn_size)return nullptr;const auto rel=off-dyn_off;const auto rec=rel/16;if(rec>=dr.size())return nullptr;return &dr[static_cast<std::size_t>(rec)];};
                auto init_loc=[&](std::uint64_t va)->const InitRange*{for(const auto&x:init_ranges)if(va>=x.va&&va-x.va<x.size)return &x;return nullptr;};
                auto emit_dependency=[&](const RelRange&r,std::uint64_t entry_off,std::uint64_t entry_va,std::uint64_t target,std::uint64_t target_off,const std::string&target_kind,const std::string&anomaly,const std::string&reason,const std::string&detail){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="ELF_RELOCATION_WRITE";f.relation="loader_metadata_write_dependency";f.source_kind=r.source+"_RECORD";f.source_file_offset=entry_off;f.source_va=entry_va;f.source_size=r.ent;f.target_kind=target_kind;f.target_va=target;f.target_file_backed=true;f.target_file_offset=target_off;f.evidence_state="EXACT";f.mutability=mutability(target,8);f.execution_condition="dynamic loader processes the source relocation before a later loader/runtime consumer";f.anomaly_class=anomaly;f.priority="HIGH";f.priority_reason=reason;f.detail=detail;need_effect_preview=true;return add_fact(std::move(f));};

                std::uint64_t scanned=0;
                for(const auto&r:rr){for(std::uint64_t p=0;p<r.size&&scanned<max_raw_relocations;p+=r.ent,++scanned){const auto eo=r.off+p,ev=r.va+p;std::uint64_t target=0,info=0;std::int64_t add=0;rd(d,static_cast<std::size_t>(eo),le,target);rd(d,static_cast<std::size_t>(eo+8),le,info);if(r.rela){std::uint64_t a=0;rd(d,static_cast<std::size_t>(eo+16),le,a);std::memcpy(&add,&a,sizeof(add));}const auto si=static_cast<std::uint32_t>(info>>32),rt=static_cast<std::uint32_t>(info);auto to=vaddr_to_file(target);
                    if(to){if(auto loc=relocation_loc(*to)){const auto future=loc->record_off>eo,current=loc->record_off==eo;emit_dependency(r,eo,ev,target,*to,"relocation_record_field",future?"RELOCATION_TARGETS_FUTURE_RELOCATION_RECORD":(current?"RELOCATION_TARGETS_CURRENT_RELOCATION_RECORD":"RELOCATION_TARGETS_PRIOR_RELOCATION_RECORD"),future?"relocation writes a later loader relocation record":"relocation writes loader relocation metadata","target_record_file=0x"+[&](){std::ostringstream q;q<<std::hex<<loc->record_off;return q.str();}()+";field="+loc->field);}
                        if(const auto*drec=dynamic_loc(*to)){emit_dependency(r,eo,ev,target,*to,"dynamic_control_field","RELOCATION_TARGETS_DYNAMIC_CONTROL","relocation writes loader dynamic-control metadata","tag="+dyn_tag_name(drec->tag));}
                        if(symoff&&*to>=symoff&&*to-symoff<sym_extent){emit_dependency(r,eo,ev,target,*to,"dynamic_symbol_record","RELOCATION_TARGETS_DYNSYM","relocation writes loader-visible dynamic symbol metadata","");}
                        if(const auto*x=embedded_loc(*to))embedded_dependency(r,eo,ev,target,*to,*x,-1);}
                    if(const auto*ir=init_loc(target)){if(to){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase=ir->phase;f.trigger="ELF_RELOCATION_WRITE";f.relation="loader_metadata_write_dependency";f.source_kind=r.source+"_RECORD";f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind="initializer_slot";f.target_va=target;f.target_file_backed=true;f.target_file_offset=*to;f.evidence_state="EXACT";f.mutability=mutability(target,8);f.execution_condition="relocation initializes a slot consumed later by the loader/runtime initializer phase";f.priority="INFORMATIONAL";f.priority_reason="relocation-backed initializer slots are normal compiler/loader behavior without an additional control-metadata anomaly";f.detail="array="+ir->kind;add_fact(std::move(f));}}
                    if(is_wx(target,8)){need_effect_preview=true;ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="ELF_RELOCATION_WRITE";f.relation="relocation_targets_executable_storage";f.source_kind=r.source+"_RECORD";f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind="writable_executable_storage";f.target_va=target;if(to){f.target_file_backed=true;f.target_file_offset=*to;}f.evidence_state="EXACT";f.mutability="WRITABLE_EXECUTABLE";f.execution_condition="dynamic loader applies the relocation";f.anomaly_class="RELOCATION_TARGETS_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="loader relocation writes directly into writable executable storage";add_fact(std::move(f));}
                    const bool loader_pointer=(out.machine==62&&(rt==6||rt==7))||(out.machine==183&&(rt==1025||rt==1026));
                    if(loader_pointer){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="RELOCATION_LOADER_POINTER_STATE";f.relation="loader_pointer_state";f.source_kind=r.source+"_RECORD";f.source_index=si;f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind="GOT_or_loader_pointer_slot";f.target_va=target;if(to){f.target_file_backed=true;f.target_file_offset=*to;}f.evidence_state="EXACT";f.mutability=mutability(target,8);f.execution_condition="loader writes a resolved address into this exact pointer slot; the resolved runtime address is not claimed here";f.priority="INFORMATIONAL";f.priority_reason="GLOB_DAT/JUMP_SLOT pointer state is normal loader-managed resolution metadata";if(si<out.dynamic.symbols.size())f.target_name=out.dynamic.symbols[si].name;add_fact(std::move(f));}

                    RawSym rs;if(si)rs=raw_sym(si);const bool outside=out.dynamic.state!="RESOLVED"||si>=out.dynamic.symbols.size();
                    if(si&&rs.valid&&outside&&raw_reported.insert(si).second){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="ELF_RELOCATION_RAW_SYMBOL_REFERENCE";f.relation="raw_loader_symbol_record";f.source_kind="DT_SYMTAB_RAW_RECORD";f.source_index=si;f.source_file_offset=rs.file;f.source_va=rs.va;f.source_size=24;f.target_kind=(rs.info&0xf)==10?"raw_ifunc_resolver_value":"raw_symbol_value";f.target_va=rs.value;if(auto o=vaddr_to_file(rs.value)){f.target_file_backed=true;f.target_file_offset=*o;}f.target_name=rs.name;f.evidence_state="RAW_LOADER_REFERENCED_SYMBOL_RECORD";f.mutability=mutability(rs.value,1);f.execution_condition="a loader-visible relocation references this bounded raw DT_SYMTAB record beyond the ordinary validated inventory";f.anomaly_class="RAW_LOADER_REFERENCED_SYMBOL_RECORD";f.priority="REVIEW";f.priority_reason="loader references a bounded raw symbol record that the strict ordinary dynsym plane intentionally does not admit";std::ostringstream q;q<<"st_info=0x"<<std::hex<<unsigned(rs.info)<<";st_value=0x"<<rs.value<<";st_shndx=0x"<<rs.shndx<<std::dec;f.detail=q.str();add_fact(std::move(f));}
                    const bool irelative=(out.machine==62&&rt==37)||(out.machine==183&&rt==1032);if(irelative){std::uint64_t resolver=0;if(r.rela&&add>=0)resolver=static_cast<std::uint64_t>(add);ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="IRELATIVE";f.relation="resolver_callback";f.source_kind=r.source+"_RECORD";f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind="resolver_function_va";f.target_va=resolver;if(resolver)if(auto o=vaddr_to_file(resolver)){f.target_file_backed=true;f.target_file_offset=*o;}f.evidence_state=resolver?"EXACT":"UNRESOLVED_RUNTIME_SEMANTICS";f.mutability=resolver?mutability(resolver,1):"UNKNOWN";f.execution_condition="dynamic loader invokes the IRELATIVE resolver; resolver execution itself is not interpreted";f.priority="INFORMATIONAL";f.priority_reason="IRELATIVE is a normal loader-managed implicit resolver surface";if(resolver&&is_wx(resolver,1)){f.anomaly_class="IFUNC_RESOLVER_IN_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="IRELATIVE resolver lies in writable executable storage";}add_fact(std::move(f));}
                    const bool ifunc=rs.valid&&((rs.info&0xf)==10)&&rs.value;if(ifunc){ImplicitExecutionFact f;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="RELOCATION_TRIGGERED_GNU_IFUNC";f.relation="resolver_callback";f.source_kind=r.source+"_RECORD";f.source_index=si;f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind="resolver_function_va";f.target_va=rs.value;if(auto o=vaddr_to_file(rs.value)){f.target_file_backed=true;f.target_file_offset=*o;}f.target_name=rs.name;f.evidence_state=outside?"RAW_LOADER_REFERENCED_SYMBOL_RECORD":"EXACT";f.mutability=mutability(rs.value,1);f.execution_condition="loader relocation resolution invokes a GNU IFUNC resolver; resolver code is not executed by analysis";f.priority="INFORMATIONAL";f.priority_reason="relocation-triggered GNU IFUNC is an implicit resolver surface";if(is_wx(rs.value,1)){f.anomaly_class="IFUNC_RESOLVER_IN_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="relocation-triggered IFUNC resolver lies in writable executable storage";}add_fact(std::move(f));}
                }}
                // Strict relocation-effect preview: freeze the physical record ranges above, then make
                // one forward pass. Exact writes may change bytes of later physical records/metadata,
                // but never alter the frozen iterator or cause backward/loop dispatch.
                if(need_effect_preview){
                    constexpr std::uint64_t overlay_page_size=4096,max_overlay_pages=4096;
                    std::map<std::uint64_t,std::array<std::uint8_t,overlay_page_size>> pages;
                    struct WriteOrigin{std::uint64_t size=0;std::int64_t fact=-1;};
                    std::map<std::uint64_t,WriteOrigin> write_origins;
                    bool preview_enabled=true;
                    auto page_for=[&](std::uint64_t off)->std::array<std::uint8_t,overlay_page_size>*{
                        const auto base=off&~(overlay_page_size-1);auto it=pages.find(base);if(it!=pages.end())return &it->second;
                        if(pages.size()>=max_overlay_pages){limit("implicit relocation-effect overlay exceeded 16 MiB page budget");preview_enabled=false;return nullptr;}
                        std::array<std::uint8_t,overlay_page_size> q{};if(base<d.size()){const auto n=std::min<std::uint64_t>(overlay_page_size,d.size()-base);std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(base),static_cast<std::size_t>(n),q.begin());}
                        return &pages.emplace(base,std::move(q)).first->second;
                    };
                    auto ov8=[&](std::uint64_t off)->std::uint8_t{const auto base=off&~(overlay_page_size-1);auto it=pages.find(base);if(it!=pages.end())return it->second[static_cast<std::size_t>(off-base)];return off<d.size()?d[static_cast<std::size_t>(off)]:0;};
                    auto ov16=[&](std::uint64_t off)->std::uint16_t{std::uint16_t v=0;for(unsigned i=0;i<2;++i)v|=std::uint16_t(ov8(off+i))<<(8*i);return v;};
                    auto ov32=[&](std::uint64_t off)->std::uint32_t{std::uint32_t v=0;for(unsigned i=0;i<4;++i)v|=std::uint32_t(ov8(off+i))<<(8*i);return v;};
                    auto ov64=[&](std::uint64_t off)->std::uint64_t{std::uint64_t v=0;for(unsigned i=0;i<8;++i)v|=std::uint64_t(ov8(off+i))<<(8*i);return v;};
                    auto origin_for=[&](std::uint64_t off,std::uint64_t size)->std::int64_t{if(!size)return -1;auto it=write_origins.upper_bound(off+size-1);while(it!=write_origins.begin()){--it;if(it->first+it->second.size<=off)break;if(it->first<off+size&&it->first+it->second.size>off)return it->second.fact;}return -1;};
                    auto write_n=[&](std::uint64_t off,std::uint64_t value,std::uint64_t width,std::int64_t origin)->bool{if(!preview_enabled||!width||width>8||off>d.size()||width>d.size()-off)return false;for(std::uint64_t i=0;i<width;++i){auto*p=page_for(off+i);if(!p)return false;const auto base=(off+i)&~(overlay_page_size-1);(*p)[static_cast<std::size_t>(off+i-base)]=static_cast<std::uint8_t>(value>>(8*i));}write_origins[off]={width,origin};return true;};
                    auto write64=[&](std::uint64_t off,std::uint64_t value,std::int64_t origin)->bool{return write_n(off,value,8,origin);};
                    auto write32=[&](std::uint64_t off,std::uint32_t value,std::int64_t origin)->bool{return write_n(off,value,4,origin);};
                    auto raw_sym_effect=[&](std::uint32_t idx)->RawSym{RawSym x;x.index=idx;if(!symoff||sym_extent<24||syment!=24||idx>max_raw_symbol_index||std::uint64_t(idx)>=sym_extent/24)return x;const auto o=symoff+std::uint64_t(idx)*24;if(o>d.size()||24>d.size()-o)return x;x.file=o;x.va=symva+std::uint64_t(idx)*24;x.name_off=ov32(o);x.info=ov8(o+4);x.other=ov8(o+5);x.shndx=ov16(o+6);x.value=ov64(o+8);x.size=ov64(o+16);if(stroff&&x.name_off<strsz){const auto remain=strsz-x.name_off;auto n=zstr_bounded(d,stroff+x.name_off,std::min<std::uint64_t>(remain,4096));if(n)x.name=std::move(*n);}x.valid=true;return x;};
                    std::map<std::uint32_t,std::int64_t> derived_symbol_facts;
                    auto derived_symbol_fact=[&](const RawSym& rs)->std::int64_t{auto it=derived_symbol_facts.find(rs.index);if(it!=derived_symbol_facts.end())return it->second;const auto dep=origin_for(rs.file,24);if(dep<0)return -1;ImplicitExecutionFact f;f.depends_on_fact_index=dep;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="DETERMINISTIC_RELOCATION_EFFECT";f.relation="derived_loader_metadata";f.source_kind="DT_SYMTAB_RAW_RECORD";f.source_index=rs.index;f.source_file_offset=rs.file;f.source_va=rs.va;f.source_size=24;f.target_kind="mutated_dynamic_symbol_record";f.target_va=rs.value;if(auto o=vaddr_to_file(rs.value)){f.target_file_backed=true;f.target_file_offset=*o;}f.target_name=rs.name;f.evidence_state="EXACT_DERIVED";f.mutability=mutability(rs.va,24);f.execution_condition="a prior exact relocation write changes this symbol record before a later relocation consumes it";f.anomaly_class="DYNAMIC_SYMBOL_RECORD_MUTATED_BEFORE_LOADER_USE";f.priority="HIGH";f.priority_reason="loader symbol semantics are deterministically rewritten by an earlier relocation";std::ostringstream q;q<<"st_info=0x"<<std::hex<<unsigned(rs.info)<<";st_value=0x"<<rs.value<<";st_shndx=0x"<<rs.shndx;f.detail=q.str();const auto n=add_fact(std::move(f));derived_symbol_facts.emplace(rs.index,n);return n;};
                    auto exact_symbol_value=[&](std::uint32_t si,std::uint64_t& value,std::string& why,std::int64_t& dep)->bool{dep=-1;if(si==0){value=0;return true;}auto rs=raw_sym_effect(si);if(!rs.valid){why="referenced raw symbol record is not structurally bounded";return false;}dep=derived_symbol_fact(rs);const auto type=rs.info&0xf,bind=rs.info>>4,vis=rs.other&3;if(type==10){why="GNU IFUNC requires resolver execution";return false;}if(rs.shndx==0){why="undefined symbol requires runtime lookup";return false;}const bool nonpreemptable=bind==0||vis==2||vis==3;if(!nonpreemptable){why="default-visible symbol may require external/interposable lookup";return false;}if(rs.shndx==0xfff1){value=rs.value;return true;}if(out.type==2){value=rs.value;return true;}why="ET_DYN symbol value requires runtime load bias";return false;};
                    const bool gnu_ld_linux=out.interpreter.find("ld-linux")!=std::string::npos;
                    auto exact_pc32_value=[&](std::uint32_t si,std::uint64_t place,std::int64_t add,std::uint32_t& value,std::string& why,std::int64_t& dep)->bool{
                        dep=-1;
                        if(si==0){
                            if(out.type==2||(out.type==3&&gnu_ld_linux)){
                                const auto raw=static_cast<std::uint64_t>(add)-place;
                                value=static_cast<std::uint32_t>(raw);
                                return true;
                            }
                            why="symbol-zero PC32 base cancellation is only proven for ET_EXEC or GNU ld-linux PIE";
                            return false;
                        }
                        auto rs=raw_sym_effect(si);
                        if(!rs.valid){why="referenced raw symbol record is not structurally bounded";return false;}
                        dep=derived_symbol_fact(rs);
                        const auto type=rs.info&0xf,bind=rs.info>>4,vis=rs.other&3;
                        if(type==10){why="GNU IFUNC requires resolver execution";return false;}
                        if(rs.shndx==0){why="undefined symbol requires runtime lookup";return false;}
                        const bool nonpreemptable=bind==0||vis==2||vis==3;
                        if(!nonpreemptable){why="default-visible symbol may require external/interposable lookup";return false;}
                        if(rs.shndx==0xfff1&&out.type==3){why="absolute symbol PC32 in ET_DYN retains load-bias dependence in P";return false;}
                        const auto raw=rs.value+static_cast<std::uint64_t>(add)-place;
                        value=static_cast<std::uint32_t>(raw);
                        return true;
                    };
                    auto bss_zero_addend=[&](std::uint64_t va,bool& exact)->std::uint64_t{exact=false;for(const auto&s:out.segments){if(s.type!=1||va<s.address)continue;const auto delta=va-s.address;if(delta>=s.memory_size||8>s.memory_size-delta)return 0;if(delta>=s.file_size){exact=true;return 0;}break;}return 0;};
                    auto meta_kind=[&](std::uint64_t target,std::optional<std::uint64_t> to)->std::string{if(to){if(relocation_loc(*to))return "relocation_record_field";if(dynamic_loc(*to))return "dynamic_control_field";if(symoff&&*to>=symoff&&*to-symoff<sym_extent)return "dynamic_symbol_record";if(embedded_loc(*to))return "embedded_elf_loader_metadata";}if(init_loc(target))return "initializer_slot";if(is_wx(target,8))return "writable_executable_storage";return {};};
                    auto exact_effect_fact=[&](const RelRange&r,std::uint64_t eo,std::uint64_t ev,std::uint64_t target,std::optional<std::uint64_t> to,std::uint64_t value,std::uint64_t width,const std::string&kind,std::uint32_t rt,std::int64_t dep)->std::int64_t{ImplicitExecutionFact f;f.depends_on_fact_index=dep;f.format="ELF";f.ecosystem="native";f.phase="loader_pre_entry";f.trigger="DETERMINISTIC_RELOCATION_EFFECT";f.relation="exact_relocation_write";f.source_kind=r.source+"_RECORD";f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind=kind.empty()?"memory_qword":kind;f.target_va=target;if(to){f.target_file_backed=true;f.target_file_offset=*to;}f.evidence_state="EXACT_DERIVED";f.mutability=mutability(target,8);f.execution_condition="one-pass preview evaluates this relocation write without CPU state, external lookup, resolver execution, or iterator mutation";f.priority="INFORMATIONAL";f.priority_reason="deterministic relocation write retained for bounded forward metadata effects";if(kind=="relocation_record_field"){f.anomaly_class="DETERMINISTIC_WRITE_TO_RELOCATION_METADATA";f.priority="HIGH";f.priority_reason="an exact relocation effect rewrites loader relocation metadata";}else if(kind=="dynamic_control_field"){f.anomaly_class="DETERMINISTIC_WRITE_TO_DYNAMIC_CONTROL";f.priority="HIGH";f.priority_reason="an exact relocation effect rewrites loader dynamic-control metadata";}else if(kind=="dynamic_symbol_record"){f.anomaly_class="DETERMINISTIC_WRITE_TO_DYNSYM";f.priority="HIGH";f.priority_reason="an exact relocation effect rewrites loader-visible symbol metadata";}else if(kind=="writable_executable_storage"){f.anomaly_class="DETERMINISTIC_WRITE_TO_WRITABLE_EXECUTABLE_STORAGE";f.priority="HIGH";f.priority_reason="an exact loader relocation writes generated/writable executable storage";}else if(kind=="embedded_elf_loader_metadata"){f.anomaly_class="DETERMINISTIC_WRITE_TO_EMBEDDED_ELF_LOADER_METADATA";f.priority="HIGH";f.priority_reason="an exact relocation effect rewrites loader metadata of a distinct embedded ELF object";}std::ostringstream q;q<<"reloc="<<elf_reloc_name(out.machine,rt)<<";write_width="<<std::dec<<width<<";write=0x"<<std::hex<<value;f.detail=q.str();return add_fact(std::move(f));};
                    auto unresolved_fact=[&](const RelRange&r,std::uint64_t eo,std::uint64_t ev,std::uint64_t target,std::optional<std::uint64_t> to,std::uint32_t rt,std::uint32_t si,const std::string&why,std::int64_t dep,const std::string&kind){ImplicitExecutionFact f;f.depends_on_fact_index=dep;f.format="ELF";f.ecosystem="native";f.phase="first_resolution";f.trigger="ELF_RELOCATION_RUNTIME_SEMANTICS";f.relation="unresolved_relocation_effect";f.source_kind=r.source+"_RECORD";f.source_index=si;f.source_file_offset=eo;f.source_va=ev;f.source_size=r.ent;f.target_kind=kind.empty()?"runtime_relocation_target":kind;f.target_va=target;if(to){f.target_file_backed=true;f.target_file_offset=*to;}f.evidence_state="UNRESOLVED_RUNTIME_SEMANTICS";f.mutability=mutability(target,8);f.execution_condition="relocation requires runtime state not modeled by the bounded static preview";f.priority=(kind=="relocation_record_field"||kind=="dynamic_control_field"||kind=="dynamic_symbol_record"||kind=="writable_executable_storage"||kind=="embedded_elf_loader_metadata")?"HIGH":"INFORMATIONAL";if(f.priority=="HIGH"){f.anomaly_class="LOADER_METADATA_EFFECT_REQUIRES_RUNTIME_SEMANTICS";f.priority_reason="loader-control metadata is targeted but the exact write depends on runtime semantics";}else f.priority_reason="normal loader resolution is retained without simulating runtime lookup/resolver state";f.detail=elf_reloc_name(out.machine,rt)+": "+why;add_fact(std::move(f));};

                    std::vector<std::uint64_t> pos(rr.size(),0);
                    std::uint64_t preview_records=0;
                    std::uint64_t last_off=std::numeric_limits<std::uint64_t>::max();
                    while(preview_enabled){
                        std::uint64_t best=std::numeric_limits<std::uint64_t>::max();
                        std::size_t pick=rr.size();
                        for(std::size_t z=0;z<rr.size();++z){
                            if(pos[z]>=rr[z].size)continue;
                            const auto o=rr[z].off+pos[z];
                            if(o<best){best=o;pick=z;}
                        }
                        if(pick==rr.size())break;
                        const RelRange* rp=&rr[pick];
                        const std::uint64_t ent=rp->ent;
                        const bool rela=rp->rela;
                        for(std::size_t z=0;z<rr.size();++z){
                            if(pos[z]>=rr[z].size||rr[z].off+pos[z]!=best)continue;
                            if(rr[z].ent!=ent||rr[z].rela!=rela){
                                limit("overlapping relocation ranges disagree on entry format");
                                preview_enabled=false;
                                break;
                            }
                            if(rr[z].source=="DT_JMPREL")rp=&rr[z];
                            pos[z]+=rr[z].ent;
                        }
                        if(!preview_enabled)break;
                        if(best==last_off)continue;
                        last_off=best;
                        if(++preview_records>max_raw_relocations){
                            limit("implicit relocation-effect preview record budget exceeded");
                            break;
                        }
                        const auto ev=rp->va+(best-rp->off);
                        std::uint64_t initial_target=0,initial_info=0,initial_add_raw=0;
                        rd(d,static_cast<std::size_t>(best),le,initial_target);
                        rd(d,static_cast<std::size_t>(best+8),le,initial_info);
                        if(rela)rd(d,static_cast<std::size_t>(best+16),le,initial_add_raw);
                        const auto target=ov64(best);
                        const auto info=ov64(best+8);
                        const auto add_raw=rela?ov64(best+16):0;
                        std::int64_t add=0;
                        std::memcpy(&add,&add_raw,sizeof(add));
                        const auto si=static_cast<std::uint32_t>(info>>32);
                        const auto rt=static_cast<std::uint32_t>(info);
                        std::int64_t derived=-1;
                        if(target!=initial_target||info!=initial_info||(rela&&add_raw!=initial_add_raw)){
                            const auto dep=origin_for(best,ent);
                            ImplicitExecutionFact f;
                            f.depends_on_fact_index=dep;f.format="ELF";f.ecosystem="native";
                            f.phase="loader_pre_entry";f.trigger="PHYSICAL_FORWARD_RELOCATION_REDECODE";
                            f.relation="derived_loader_action";f.source_kind=rp->source+"_RECORD";
                            f.source_file_offset=best;f.source_va=ev;f.source_size=ent;
                            f.target_kind="derived_relocation_record";f.evidence_state="EXACT_DERIVED";
                            f.mutability=mutability(ev,ent);
                            f.execution_condition="this frozen physical relocation record is re-decoded once when the forward pass reaches it";
                            f.anomaly_class="FUTURE_RELOCATION_RECORD_MUTATED_BEFORE_CONSUMPTION";
                            f.priority="HIGH";
                            f.priority_reason="an earlier exact loader write changes the semantics of a later physical relocation record";
                            std::ostringstream q;
                            q<<"old_target=0x"<<std::hex<<initial_target<<";new_target=0x"<<target
                             <<";old_info=0x"<<initial_info<<";new_info=0x"<<info;
                            if(rela)q<<";old_addend=0x"<<initial_add_raw<<";new_addend=0x"<<add_raw;
                            f.detail=q.str();
                            derived=add_fact(std::move(f));
                        }
                        if(rt==0)continue;
                        auto to=vaddr_to_file(target);
                        const auto kind=meta_kind(target,to);
                        bool exact=false;
                        std::uint64_t value=0;
                        std::uint64_t write_width=8;
                        std::string why;
                        std::int64_t symdep=-1;
                        std::int64_t effective_dep=derived;
                        std::int64_t effective_add=add;
                        if(!rela){
                            if(to){
                                const auto ar=ov64(*to);
                                std::memcpy(&effective_add,&ar,sizeof(effective_add));
                            }else{
                                bool z=false;
                                const auto ar=bss_zero_addend(target,z);
                                if(z)std::memcpy(&effective_add,&ar,sizeof(effective_add));
                                else why="REL implicit addend is not file-backed or proven BSS-zero";
                            }
                        }
                        const bool pc32=out.machine==62&&rt==2;
                        const bool abs64=(out.machine==62&&rt==1)||(out.machine==183&&rt==257);
                        const bool relative=(out.machine==62&&rt==8)||(out.machine==183&&rt==1027);
                        const bool irelative=(out.machine==62&&rt==37)||(out.machine==183&&rt==1032);
                        const bool glob=(out.machine==62&&(rt==6||rt==7))||(out.machine==183&&(rt==1025||rt==1026));
                        if(pc32&&why.empty()){
                            std::uint32_t v=0;
                            if(exact_pc32_value(si,target,effective_add,v,why,symdep)){value=v;write_width=4;exact=true;}
                        }else if(abs64&&why.empty()){
                            std::uint64_t sv=0;
                            if(exact_symbol_value(si,sv,why,symdep)){
                                std::uint64_t v=0;
                                if(eh_add_signed(sv,effective_add,v)){value=v;exact=true;}
                                else why="symbol plus addend overflows";
                            }
                        }else if(relative&&why.empty()){
                            if(out.type==2){
                                std::uint64_t v=0;
                                if(eh_add_signed(0,effective_add,v)){value=v;exact=true;}
                                else why="relative addend overflows";
                            }else why="ET_DYN RELATIVE requires runtime load bias";
                        }else if(irelative)why="IRELATIVE requires resolver execution";
                        else if(glob&&why.empty()){
                            std::uint64_t sv=0;
                            if(exact_symbol_value(si,sv,why,symdep)){value=sv;exact=true;}
                        }else if(why.empty())why="relocation type is outside the strict deterministic preview set";
                        if(effective_dep<0&&symdep>=0)effective_dep=symdep;
                        if(exact){
                            ++im.deterministic_effect_count;
                            std::int64_t effect=-1;
                            if(!kind.empty()||derived>=0)
                                effect=exact_effect_fact(*rp,best,ev,target,to,value,write_width,kind,rt,effective_dep);
                            if(to){
                                const bool wrote=write_width==4?write32(*to,static_cast<std::uint32_t>(value),effect):write64(*to,value,effect);
                                if(!wrote&&preview_enabled)limit("deterministic relocation write could not be represented in bounded file overlay");
                            }
                            if(effect>=0&&kind=="initializer_slot"){
                                const auto*ir=init_loc(target);
                                if(ir){
                                    ImplicitExecutionFact f;
                                    f.depends_on_fact_index=effect;f.format="ELF";f.ecosystem="native";
                                    f.phase=ir->phase;f.trigger="DERIVED_INITIALIZER_SLOT";f.relation="implicit_callback";
                                    f.source_kind=ir->kind;f.source_file_offset=to?*to:0;f.source_va=target;f.source_size=8;
                                    f.target_kind="function_va";f.target_va=value;
                                    if(auto o=vaddr_to_file(value)){f.target_file_backed=true;f.target_file_offset=*o;}
                                    f.evidence_state="EXACT_DERIVED";f.mutability=mutability(value,1);
                                    f.execution_condition="a deterministic loader relocation writes the initializer target before the initializer phase";
                                    f.anomaly_class=derived>=0?"DERIVED_INITIALIZER_FROM_MUTATED_RELOCATION":"NONE";
                                    f.priority=derived>=0?"HIGH":"INFORMATIONAL";
                                    f.priority_reason=derived>=0?"a self-modified relocation deterministically creates a later implicit callback":"deterministic relocation-backed initializer target";
                                    add_fact(std::move(f));
                                }
                            }
                            if(effect>=0&&kind=="embedded_elf_loader_metadata"&&to){if(const auto*x=embedded_loc(*to);x&&embedded_runtime_boundary_reported.insert(x->child_file_base).second){ImplicitExecutionFact u;u.depends_on_fact_index=effect;u.format="ELF";u.ecosystem="native";u.phase="module_load";u.trigger="EMBEDDED_ELF_LATER_LOAD";u.relation="runtime_semantics_boundary";u.source_kind=x->kind;u.source_file_offset=x->file;u.source_va=x->child_va;u.source_size=x->size;u.target_kind="embedded_elf_loader_object";u.target_file_backed=true;u.target_file_offset=x->child_file_base;u.evidence_state="UNRESOLVED_RUNTIME_SEMANTICS";u.mutability="UNKNOWN";u.execution_condition="whether this structurally valid embedded ELF is later mapped/loaded is not inferred by the one-pass relocation preview";u.anomaly_class="EMBEDDED_ELF_LOAD_CONDITION_UNRESOLVED";u.priority="REVIEW";u.priority_reason="exact metadata mutation does not prove a later module-load trigger";add_fact(std::move(u));}}
                            if(effect>=0&&kind=="dynamic_control_field"){
                                ImplicitExecutionFact f;
                                f.depends_on_fact_index=effect;f.format="ELF";f.ecosystem="native";
                                f.phase="loader_pre_entry";f.trigger="DERIVED_DYNAMIC_CONTROL";
                                f.relation="runtime_semantics_boundary";f.source_kind="PT_DYNAMIC";
                                f.source_file_offset=to?*to:0;f.source_va=target;f.source_size=8;
                                f.target_kind="mutated_dynamic_control_value";f.target_va=value;
                                f.evidence_state="UNRESOLVED_RUNTIME_SEMANTICS";f.mutability=mutability(target,8);
                                f.execution_condition="whether the loader re-reads this mutated DT_* field versus cached dynamic state is runtime/linker specific and is not simulated";
                                f.anomaly_class="DYNAMIC_CONTROL_MUTATED_DURING_RELOCATION";f.priority="HIGH";
                                f.priority_reason="loader control metadata changes deterministically, but subsequent runtime consumption semantics are intentionally not emulated";
                                add_fact(std::move(f));
                            }
                        }else{
                            if(!kind.empty()||derived>=0)
                                unresolved_fact(*rp,best,ev,target,to,rt,si,why,effective_dep,kind);
                        }
                    }
                }
                if(scanned>=max_raw_relocations)limit("implicit raw relocation scan budget exceeded");
                if(im.state=="NOT_PRESENT")im.state=plane_partial?"PARTIAL":"RESOLVED";else if(plane_partial)im.state="PARTIAL";
            }
        }
    }
    // Loader ABI metadata: GNU build-id plus dynamic-string and GNU symbol-version tables.
    // PT_NOTE/PT_DYNAMIC are authoritative; named sections are fallback-only when loader-facing
    // program headers do not expose the corresponding metadata.
    {
        auto&ab=out.abi;bool abi_seen=false,abi_ok=true,abi_partial=false;constexpr std::uint64_t max_abi_string=1ull<<20,max_abi_strings_total=16ull<<20,max_version_records=65534,max_version_aux=262144;
        std::uint64_t abi_string_bytes=0;
        auto fail=[&](std::string e){if(abi_ok){abi_ok=false;ab.error=std::move(e);}};
        auto partial=[&](std::string e){if(abi_ok&&!abi_partial){abi_partial=true;ab.error=std::move(e);}};
        auto note_build_id=[&](std::uint64_t off,std::uint64_t size,const char*source)->bool{
            if(off>d.size()||size>d.size()-off)return false;
            std::uint64_t p=off,end=off+size;
            while(p<end){
                if(end-p<12){for(auto q=p;q<end;++q)if(d[static_cast<std::size_t>(q)])return false;break;}
                std::uint32_t namesz=0,descsz=0,type=0;if(!rd(d,static_cast<std::size_t>(p),le,namesz)||!rd(d,static_cast<std::size_t>(p+4),le,descsz)||!rd(d,static_cast<std::size_t>(p+8),le,type))return false;
                const auto name_off=p+12;const auto name_pad=(std::uint64_t(namesz)+3u)&~std::uint64_t(3);if(name_pad<std::uint64_t(namesz)||name_pad>end-name_off)return false;const auto desc_off=name_off+name_pad;const auto desc_pad=(std::uint64_t(descsz)+3u)&~std::uint64_t(3);if(desc_pad<std::uint64_t(descsz)||desc_pad>end-desc_off)return false;
                if(type==3&&namesz==4&&d[static_cast<std::size_t>(name_off)]=='G'&&d[static_cast<std::size_t>(name_off+1)]=='N'&&d[static_cast<std::size_t>(name_off+2)]=='U'&&d[static_cast<std::size_t>(name_off+3)]==0){
                    if(!descsz||descsz>256)return false;
                    const auto id=elf_hex(d.subspan(static_cast<std::size_t>(desc_off),descsz));abi_seen=true;
                    if(ab.build_id.empty()){ab.build_id=id;ab.build_id_source=source;ab.build_id_file_offset=desc_off;ab.build_id_size=descsz;}else if(ab.build_id!=id){fail("conflicting GNU Build ID notes");return false;}
                }
                p=desc_off+desc_pad;
            }
            return true;
        };
        for(const auto&s:out.segments)if(s.type==4){if(!note_build_id(s.offset,s.file_size,"PT_NOTE")){fail("malformed PT_NOTE while scanning GNU Build ID");break;}}
        if(abi_ok&&ab.build_id.empty()){for(const auto&s:out.sections)if(s.name==".note.gnu.build-id"){if(!note_build_id(s.offset,s.size,"SHT_NOTE")){fail("malformed .note.gnu.build-id section");break;}}}

        std::map<std::int64_t,std::uint64_t> tags;bool dyn_seen=false,dyn_terminated=false,dyn_bad=false;std::size_t dyn_sources=0;
        auto keep_tag=[&](std::int64_t tag,std::uint64_t value){switch(tag){case 5:case 10:break;case 14:case 15:case 29:case 0x6ffffff0:case 0x6ffffffc:case 0x6ffffffd:case 0x6ffffffe:case 0x6fffffff:abi_seen=true;break;default:return;}auto[it,ins]=tags.emplace(tag,value);if(!ins&&it->second!=value)fail("conflicting ABI dynamic tag "+std::to_string(tag));};
        auto scan_abi_dynamic=[&](std::uint64_t off,std::uint64_t size,std::uint64_t entsz)->bool{
            const auto expected=out.elf64?16u:8u;if(entsz!=expected||off>d.size()||size>d.size()-off||size%entsz)return false;
            for(std::uint64_t p=0;p+entsz<=size;p+=entsz){std::int64_t tag=0;std::uint64_t value=0;if(out.elf64){std::uint64_t rt=0;if(!rd(d,static_cast<std::size_t>(off+p),le,rt)||!rd(d,static_cast<std::size_t>(off+p+8),le,value))return false;tag=static_cast<std::int64_t>(rt);}else{std::uint32_t rt=0,v=0;if(!rd(d,static_cast<std::size_t>(off+p),le,rt)||!rd(d,static_cast<std::size_t>(off+p+4),le,v))return false;tag=static_cast<std::int32_t>(rt);value=v;}if(tag==0){dyn_terminated=true;return true;}keep_tag(tag,value);}return false;
        };
        for(const auto&s:out.segments)if(s.type==2){dyn_seen=true;++dyn_sources;if(dyn_sources==1&&!scan_abi_dynamic(s.offset,s.file_size,out.elf64?16:8))dyn_bad=true;}
        if(dyn_sources>1){dyn_bad=true;fail("multiple PT_DYNAMIC segments while scanning ABI metadata");}
        if(!dyn_sources){for(const auto&rs:raw)if(rs.type==6){dyn_seen=true;++dyn_sources;if(dyn_sources==1&&!scan_abi_dynamic(rs.off,rs.size,rs.entsize?rs.entsize:(out.elf64?16:8)))dyn_bad=true;else if(dyn_sources>1){dyn_bad=true;fail("multiple SHT_DYNAMIC sections while scanning ABI metadata");break;}}}
        if(dyn_seen&&(!dyn_terminated||dyn_bad)){if(abi_ok)partial("dynamic table geometry prevents complete ABI metadata scan");}
        auto tagv=[&](std::int64_t tag)->std::uint64_t{auto it=tags.find(tag);return it==tags.end()?0:it->second;};
        const auto strva=tagv(5),strsz=tagv(10);std::optional<std::pair<std::uint64_t,std::uint64_t>> strex;
        const bool need_dynstr=tagv(14)||tagv(15)||tagv(29)||tagv(0x6ffffffc)||tagv(0x6ffffffe);
        if(abi_ok&&need_dynstr){if(!strva||!strsz)fail("ABI metadata requires DT_STRTAB/DT_STRSZ");else{strex=vaddr_file_extent(strva);if(!strex||strsz>strex->second)fail("ABI DT_STRTAB is not bounded by PT_LOAD file range");}}
        auto read_abi_string=[&](std::uint64_t nameoff,const char*what,std::uint64_t*fileoff)->std::optional<std::string>{
            if(!strex||nameoff>=strsz){fail(std::string(what)+" string offset outside DT_STRTAB");return std::nullopt;}const auto remain=strsz-nameoff;const auto limit=std::min<std::uint64_t>(remain,max_abi_string+1);auto x=zstr_bounded(d,strex->first+nameoff,limit);if(!x){fail(std::string(what)+(remain>max_abi_string?" string exceeds 1 MiB limit":" string is not terminated within DT_STRSZ"));return std::nullopt;}if(abi_string_bytes>max_abi_strings_total-x->size()){fail("ABI copied-string budget exceeded");return std::nullopt;}abi_string_bytes+=x->size();if(fileoff)*fileoff=strex->first+nameoff;return x;
        };
        if(abi_ok&&tagv(14)){if(auto x=read_abi_string(tagv(14),"DT_SONAME",&ab.soname_file_offset))ab.soname=std::move(*x);}
        if(abi_ok&&tagv(15)){if(auto x=read_abi_string(tagv(15),"DT_RPATH",&ab.rpath_file_offset))ab.rpath=std::move(*x);}
        if(abi_ok&&tagv(29)){if(auto x=read_abi_string(tagv(29),"DT_RUNPATH",&ab.runpath_file_offset))ab.runpath=std::move(*x);}

        ab.versym_va=tagv(0x6ffffff0);ab.verdef_va=tagv(0x6ffffffc);ab.verdef_count=static_cast<std::uint32_t>(tagv(0x6ffffffd));ab.verneed_va=tagv(0x6ffffffe);ab.verneed_count=static_cast<std::uint32_t>(tagv(0x6fffffff));
        if(tagv(0x6ffffffd)>std::numeric_limits<std::uint32_t>::max()||tagv(0x6fffffff)>std::numeric_limits<std::uint32_t>::max())fail("GNU version-table count exceeds uint32 range");
        if(abi_ok&&((ab.verdef_va==0)!=(ab.verdef_count==0)))fail("DT_VERDEF/DT_VERDEFNUM geometry incomplete");
        if(abi_ok&&((ab.verneed_va==0)!=(ab.verneed_count==0)))fail("DT_VERNEED/DT_VERNEEDNUM geometry incomplete");
        if(abi_ok&&(ab.verdef_count>max_version_records||ab.verneed_count>max_version_records))fail("GNU version-table top-level count exceeds limit");
        std::map<std::uint16_t,std::size_t> version_by_index;std::uint64_t version_aux_seen=0;
        auto add_version=[&](ElfVersionRecord x){if(x.index==0){fail("GNU version record uses reserved index zero");return;}if(ab.versions.size()>=max_version_records){fail("GNU version record count exceeds limit");return;}if(auto[it,ins]=version_by_index.emplace(x.index,ab.versions.size());!ins){fail("duplicate GNU version index "+std::to_string(x.index));return;}ab.versions.push_back(std::move(x));};
        if(abi_ok&&ab.verdef_count){
            auto ex=vaddr_file_extent(ab.verdef_va);if(!ex)fail("DT_VERDEF is not file-backed");else{ab.verdef_file_offset=ex->first;std::uint64_t cur=0;
                for(std::uint32_t n=0;n<ab.verdef_count&&abi_ok;++n){if(cur>ex->second||20>ex->second-cur){fail("DT_VERDEF record exceeds PT_LOAD file range");break;}const auto ro=ex->first+cur;std::uint16_t ver=0,flags=0,ndx=0,cnt=0;std::uint32_t hash=0,aux=0,next=0;rd(d,ro,le,ver);rd(d,ro+2,le,flags);rd(d,ro+4,le,ndx);rd(d,ro+6,le,cnt);rd(d,ro+8,le,hash);rd(d,ro+12,le,aux);rd(d,ro+16,le,next);(void)hash;if(ver!=1||!cnt){fail("DT_VERDEF record version/count invalid");break;}const auto idx=static_cast<std::uint16_t>(ndx&0x7fff);if(!idx){fail("DT_VERDEF index is zero");break;}if((n+1<ab.verdef_count&&(!next||(next&3)||next<20||next>ex->second-cur))||(n+1==ab.verdef_count&&next)){fail("DT_VERDEF next-chain geometry invalid");break;}const auto rec_limit=next?cur+next:ex->second;if(aux<20||(aux&3)||aux>rec_limit-cur||8>rec_limit-cur-aux){fail("DT_VERDEF auxiliary offset invalid");break;}ElfVersionRecord vr;vr.index=idx;vr.flags=flags;vr.base=(flags&1)!=0;vr.source="VERDEF";vr.file_offset=ro;vr.va=ab.verdef_va+cur;std::uint64_t ap=cur+aux;
                    for(std::uint16_t a=0;a<cnt&&abi_ok;++a){if(++version_aux_seen>max_version_aux){fail("GNU version auxiliary record count exceeds limit");break;}if(ap>rec_limit||8>rec_limit-ap){fail("DT_VERDEF auxiliary record exceeds definition");break;}std::uint32_t no=0,an=0;rd(d,ex->first+ap,le,no);rd(d,ex->first+ap+4,le,an);auto nm=read_abi_string(no,"DT_VERDEF",nullptr);if(!abi_ok||!nm)break;if(a==0)vr.name=std::move(*nm);else vr.parents.push_back(std::move(*nm));if((a+1<cnt&&(!an||(an&3)||an<8||an>rec_limit-ap))||(a+1==cnt&&an)){fail("DT_VERDEF auxiliary next-chain invalid");break;}if(an)ap+=an;}
                    if(!abi_ok)break;
                    if(vr.name.empty()){fail("DT_VERDEF primary name is empty");break;}
                    add_version(std::move(vr));if(next)cur+=next;
                }
            }
        }
        if(abi_ok&&ab.verneed_count){
            auto ex=vaddr_file_extent(ab.verneed_va);if(!ex)fail("DT_VERNEED is not file-backed");else{ab.verneed_file_offset=ex->first;std::uint64_t cur=0;
                for(std::uint32_t n=0;n<ab.verneed_count&&abi_ok;++n){if(cur>ex->second||16>ex->second-cur){fail("DT_VERNEED record exceeds PT_LOAD file range");break;}const auto ro=ex->first+cur;std::uint16_t ver=0,cnt=0;std::uint32_t file=0,aux=0,next=0;rd(d,ro,le,ver);rd(d,ro+2,le,cnt);rd(d,ro+4,le,file);rd(d,ro+8,le,aux);rd(d,ro+12,le,next);if(ver!=1||!cnt){fail("DT_VERNEED record version/count invalid");break;}if((n+1<ab.verneed_count&&(!next||(next&3)||next<16||next>ex->second-cur))||(n+1==ab.verneed_count&&next)){fail("DT_VERNEED next-chain geometry invalid");break;}const auto rec_limit=next?cur+next:ex->second;if(aux<16||(aux&3)||aux>rec_limit-cur||16>rec_limit-cur-aux){fail("DT_VERNEED auxiliary offset invalid");break;}auto provider=read_abi_string(file,"DT_VERNEED provider",nullptr);if(!abi_ok||!provider)break;std::uint64_t ap=cur+aux;
                    for(std::uint16_t a=0;a<cnt&&abi_ok;++a){if(++version_aux_seen>max_version_aux){fail("GNU version auxiliary record count exceeds limit");break;}if(ap>rec_limit||16>rec_limit-ap){fail("DT_VERNEED auxiliary record exceeds need record");break;}std::uint32_t hash=0,no=0,an=0;std::uint16_t flags=0,other=0;rd(d,ex->first+ap,le,hash);rd(d,ex->first+ap+4,le,flags);rd(d,ex->first+ap+6,le,other);rd(d,ex->first+ap+8,le,no);rd(d,ex->first+ap+12,le,an);(void)hash;const auto idx=static_cast<std::uint16_t>(other&0x7fff);if(idx<=1){fail("DT_VERNEED auxiliary version index is reserved");break;}auto nm=read_abi_string(no,"DT_VERNEED",nullptr);if(!abi_ok||!nm)break;if(abi_string_bytes>max_abi_strings_total-provider->size()){fail("ABI copied-string budget exceeded");break;}abi_string_bytes+=provider->size();ElfVersionRecord vr;vr.index=idx;vr.flags=flags;vr.source="VERNEED";vr.name=std::move(*nm);vr.provider=*provider;vr.file_offset=ex->first+ap;vr.va=ab.verneed_va+ap;add_version(std::move(vr));if((a+1<cnt&&(!an||(an&3)||an<16||an>rec_limit-ap))||(a+1==cnt&&an)){fail("DT_VERNEED auxiliary next-chain invalid");break;}if(an)ap+=an;}
                    if(next)cur+=next;
                }
            }
        }
        if(abi_ok&&ab.versym_va){
            if(!out.elf64||!(out.machine==62||out.machine==183)){partial("DT_VERSYM binding currently supports ELF64 x86-64/AArch64 only");}
            else if(out.dynamic.state!="RESOLVED"){partial("DT_VERSYM cannot bind symbols because the dynamic symbol plane is not RESOLVED");}
            else{auto ex=vaddr_file_extent(ab.versym_va);const auto need=std::uint64_t(out.dynamic.symbols.size())*2;if(!ex||need>ex->second)fail("DT_VERSYM array is not bounded by PT_LOAD file range");else{ab.versym_file_offset=ex->first;std::vector<std::uint16_t> versym;versym.reserve(out.dynamic.symbols.size());for(std::size_t i=0;i<out.dynamic.symbols.size()&&abi_ok;++i){std::uint16_t raw_version=0;rd(d,ex->first+i*2,le,raw_version);const auto idx=static_cast<std::uint16_t>(raw_version&0x7fff);if(idx>1&&!version_by_index.count(idx)){fail("DT_VERSYM references unknown GNU version index "+std::to_string(idx));break;}versym.push_back(raw_version);}if(abi_ok){for(std::size_t i=0;i<versym.size();++i){out.dynamic.symbols[i].version_index=static_cast<std::uint16_t>(versym[i]&0x7fff);out.dynamic.symbols[i].version_hidden=(versym[i]&0x8000)!=0;}}}}
        }
        if(!abi_seen)ab.state="NOT_PRESENT";else if(!abi_ok)ab.state="FAILED";else if(abi_partial)ab.state="PARTIAL";else{ab.state="RESOLVED";ab.error.clear();}
    }
    // Bounded ELF64 unwind metadata plane. This recovers only GNU EH header/CIE/FDE
    // geometry and augmentation references; DWARF CFI instruction programs are never interpreted.
    {
        auto&uw=out.unwind;constexpr std::uint32_t PT_GNU_EH_FRAME=0x6474e550u;constexpr std::uint64_t max_fdes=4000000,max_cies=1000000,max_unwind_memory=256ull*1024*1024,map_node_estimate=64;std::uint64_t unwind_memory=0;uw.memory_budget_bytes=max_unwind_memory;
        std::vector<const ElfSegment*> eh_segments;for(const auto&s:out.segments)if(s.type==PT_GNU_EH_FRAME)eh_segments.push_back(&s);
        const ElfSection*hdr_sec=nullptr;const ElfSection*frame_sec=nullptr;std::size_t hdr_secs=0,frame_secs=0;
        for(const auto&s:out.sections){if(s.name==".eh_frame_hdr"){++hdr_secs;if(!hdr_sec)hdr_sec=&s;}else if(s.name==".eh_frame"){++frame_secs;if(!frame_sec)frame_sec=&s;}}
        const bool unwind_candidate=!eh_segments.empty()||hdr_sec||frame_sec;
        if(unwind_candidate){
            bool uw_ok=true,uw_unsupported=false;auto fail=[&](std::string e){if(uw_ok){uw_ok=false;uw.error=std::move(e);}};auto unsupported=[&](std::string e){if(uw_ok){uw_ok=false;uw_unsupported=true;uw.error=std::move(e);}};auto charge=[&](std::uint64_t bytes,const char*what)->bool{if(bytes>max_unwind_memory-unwind_memory){fail(std::string("unwind metadata memory budget exceeded by ")+what);return false;}unwind_memory+=bytes;uw.estimated_memory_bytes=unwind_memory;return true;};
            auto decode=[&](std::size_t&off,std::size_t end,std::uint8_t enc,std::uint64_t field_va,std::optional<std::uint64_t>datarel,std::optional<std::uint64_t>funcrel,const char*what)->EhReadResult{
                auto r=eh_read_encoded(d,off,end,le,enc,field_va,datarel,funcrel);if(r.state==EhReadState::Unsupported)unsupported(std::string(what)+": "+r.error);else if(r.state==EhReadState::Failed)fail(std::string(what)+": "+r.error);return r;
            };
            auto load_range=[&](std::uint64_t va,std::uint64_t size,bool exec,std::uint64_t*file_off)->bool{
                if(!size||va>std::numeric_limits<std::uint64_t>::max()-size)return false;
                for(const auto&s:out.segments){if(s.type!=1||(exec&&!(s.flags&1))||va<s.address)continue;const auto delta=va-s.address;if(delta>=s.memory_size||size>s.memory_size-delta)continue;if(file_off){if(delta<s.file_size&&size<=s.file_size-delta&&s.offset+delta<d.size()&&size<=d.size()-(s.offset+delta))*file_off=s.offset+delta;else *file_off=std::numeric_limits<std::uint64_t>::max();}return true;}return false;
            };
            if(!out.elf64||!le||!(out.machine==62||out.machine==183))unsupported("unwind parsing currently supports little-endian ELF64 x86-64/AArch64");
            if(uw_ok&&eh_segments.size()>1)fail("multiple PT_GNU_EH_FRAME segments");
            if(uw_ok&&hdr_secs>1)fail("multiple .eh_frame_hdr sections");
            if(uw_ok&&frame_secs>1)fail("multiple .eh_frame sections");
            struct HeaderRow{std::uint64_t entry_file_offset=0,function_start_va=0,fde_va=0;};std::vector<HeaderRow>header_rows;bool header_present=false,frame_exact=false;
            if(uw_ok&&(eh_segments.size()==1||hdr_sec)){
                std::uint64_t hoff=0,hva=0,hsize=0;
                if(eh_segments.size()==1){const auto&s=*eh_segments.front();hoff=s.offset;hva=s.address;hsize=s.file_size;uw.source="PT_GNU_EH_FRAME";}
                else{hoff=hdr_sec->offset;hva=hdr_sec->address;hsize=hdr_sec->size;uw.source="SHT_EH_FRAME_HDR";}
                if(hoff>d.size()||hsize>d.size()-hoff||hsize<4)fail(".eh_frame_hdr file range invalid");
                else if(auto hx=vaddr_file_extent(hva);!hx||hx->first!=hoff||hsize>hx->second)fail(".eh_frame_hdr is not exactly file-backed by PT_LOAD");
                else{
                    header_present=true;uw.eh_frame_hdr_file_offset=hoff;uw.eh_frame_hdr_va=hva;uw.eh_frame_hdr_size=hsize;std::size_t p=static_cast<std::size_t>(hoff),end=static_cast<std::size_t>(hoff+hsize);
                    uw.header_version=d[p++];uw.eh_frame_ptr_encoding=d[p++];uw.fde_count_encoding=d[p++];uw.table_encoding=d[p++];
                    if(uw.header_version!=1)unsupported("unsupported .eh_frame_hdr version");
                    if(uw_ok&&uw.eh_frame_ptr_encoding==0xff)unsupported(".eh_frame_hdr omits the .eh_frame pointer");
                    if(uw_ok){const auto field_va=hva+(p-hoff);auto r=decode(p,end,uw.eh_frame_ptr_encoding,field_va,hva,std::nullopt,".eh_frame_hdr eh_frame pointer");if(uw_ok){if(r.indirect)unsupported("indirect .eh_frame_hdr eh_frame pointer is unsupported");else if(!r.value)fail(".eh_frame_hdr resolved a null .eh_frame pointer");else uw.eh_frame_va=r.value;}}
                    if(uw_ok&&uw.fde_count_encoding==0xff)unsupported(".eh_frame_hdr omits the FDE count");
                    if(uw_ok){const auto field_va=hva+(p-hoff);auto r=decode(p,end,uw.fde_count_encoding,field_va,hva,std::nullopt,".eh_frame_hdr FDE count");if(uw_ok){if(r.indirect)unsupported("indirect .eh_frame_hdr FDE count is unsupported");else if(r.value>max_fdes)fail(".eh_frame_hdr FDE count exceeds limit");else uw.header_fde_count=r.value;}}
                    if(uw_ok&&uw.header_fde_count&&uw.table_encoding==0xff)unsupported(".eh_frame_hdr omits a non-empty search table");
                    std::uint64_t prev_start=0;bool have_prev=false;
                    for(std::uint64_t i=0;i<uw.header_fde_count&&uw_ok;++i){HeaderRow row;row.entry_file_offset=p;const auto pc_field=hva+(p-hoff);auto pc=decode(p,end,uw.table_encoding,pc_field,hva,std::nullopt,".eh_frame_hdr table initial location");if(!uw_ok)break;const auto fde_field=hva+(p-hoff);auto fv=decode(p,end,uw.table_encoding,fde_field,hva,std::nullopt,".eh_frame_hdr table FDE pointer");if(!uw_ok)break;if(pc.indirect||fv.indirect){unsupported("indirect .eh_frame_hdr table entries are unsupported");break;}if(!pc.value||!fv.value){fail(".eh_frame_hdr table contains null entry");break;}if(have_prev&&pc.value<prev_start){fail(".eh_frame_hdr search table is not sorted");break;}prev_start=pc.value;have_prev=true;row.function_start_va=pc.value;row.fde_va=fv.value;if(!charge(2ull*sizeof(HeaderRow),".eh_frame_hdr rows"))break;header_rows.push_back(row);}
                    if(uw_ok){for(;p<end;++p)if(d[p]){fail(".eh_frame_hdr has non-zero trailing bytes");break;}}
                }
            }
            if(uw_ok){
                if(header_present){auto ex=vaddr_file_extent(uw.eh_frame_va);if(!ex)fail(".eh_frame pointer is not file-backed by PT_LOAD");else{uw.eh_frame_file_offset=ex->first;uw.eh_frame_size=ex->second;if(frame_sec&&frame_sec->address==uw.eh_frame_va&&frame_sec->offset==uw.eh_frame_file_offset){if(!frame_sec->size||frame_sec->size>ex->second)fail(".eh_frame section range invalid");else{uw.eh_frame_size=frame_sec->size;frame_exact=true;}}}}
                else if(frame_sec){uw.source="SHT_EH_FRAME";uw.eh_frame_va=frame_sec->address;uw.eh_frame_file_offset=frame_sec->offset;uw.eh_frame_size=frame_sec->size;frame_exact=true;if(!uw.eh_frame_size||uw.eh_frame_file_offset>d.size()||uw.eh_frame_size>d.size()-uw.eh_frame_file_offset)fail(".eh_frame section file range invalid");else if(auto ex=vaddr_file_extent(uw.eh_frame_va);!ex||ex->first!=uw.eh_frame_file_offset||uw.eh_frame_size>ex->second)fail(".eh_frame section is not exactly file-backed by PT_LOAD");}
                else fail("GNU EH header is present but .eh_frame could not be located");
            }
            std::map<std::uint64_t,std::uint32_t>cie_by_file;
            if(uw_ok){
                const auto base_off=uw.eh_frame_file_offset,base_va=uw.eh_frame_va;std::size_t p=static_cast<std::size_t>(base_off),limit=static_cast<std::size_t>(base_off+uw.eh_frame_size);bool terminated=false;std::uint64_t records=0;
                while(uw_ok&&p+4<=limit){const auto rec=p;std::uint32_t len=0;rd(d,p,le,len);p+=4;if(len==0){terminated=true;if(!frame_exact)uw.eh_frame_size=p-base_off;break;}if(len==0xffffffffu){unsupported("DWARF64 .eh_frame records are unsupported");break;}if(len<4||len>limit-p){fail(".eh_frame record length exceeds bounded range");break;}if(++records>max_fdes+max_cies){fail(".eh_frame record count exceeds limit");break;}const auto rend=p+len,idfield=p;std::uint32_t ident=0;rd(d,p,le,ident);p+=4;const auto rec_va=base_va+(rec-base_off);
                    if(ident==0){
                        if(uw.cies.size()>=max_cies){fail(".eh_frame CIE count exceeds limit");break;}ElfUnwindCie cie;cie.index=static_cast<std::uint32_t>(uw.cies.size());cie.file_offset=rec;cie.va=rec_va;cie.record_size=4ull+len;cie.fde_encoding=0;
                        if(p>=rend){fail("truncated .eh_frame CIE version");break;}cie.version=d[p++];if(!(cie.version==1||cie.version==3||cie.version==4)){unsupported("unsupported .eh_frame CIE version");break;}
                        const auto az=p;while(p<rend&&d[p])++p;if(p>=rend){fail("unterminated .eh_frame CIE augmentation string");break;}if(p-az>128){fail(".eh_frame CIE augmentation string exceeds limit");break;}for(auto q=az;q<p;++q)if(d[q]<0x20||d[q]>0x7e){fail("non-ASCII .eh_frame CIE augmentation string");break;}if(!uw_ok)break;cie.augmentation.assign(reinterpret_cast<const char*>(d.data()+az),p-az);++p;
                        if(cie.version==4){if(rend-p<2){fail("truncated DWARF4 CIE address-size fields");break;}cie.address_size=d[p++];cie.segment_selector_size=d[p++];if(cie.address_size!=8||cie.segment_selector_size!=0){unsupported("unsupported DWARF4 CIE address/segment size");break;}}else cie.address_size=8;
                        if(!eh_uleb(d,p,rend,cie.code_alignment)||!cie.code_alignment){fail("invalid .eh_frame CIE code alignment");break;}if(!eh_sleb(d,p,rend,cie.data_alignment)){fail("invalid .eh_frame CIE data alignment");break;}if(cie.version==1){if(p>=rend){fail("truncated CIE return-address register");break;}cie.return_address_register=d[p++];}else if(!eh_uleb(d,p,rend,cie.return_address_register)){fail("invalid CIE return-address register");break;}
                        if(cie.augmentation.empty()){}
                        else if(cie.augmentation.front()=='z'){
                            std::uint64_t auglen=0;if(!eh_uleb(d,p,rend,auglen)||auglen>rend-p){fail("invalid CIE augmentation-data length");break;}const auto ae=p+static_cast<std::size_t>(auglen);
                            for(std::size_t ai=1;ai<cie.augmentation.size()&&uw_ok;++ai){const auto ch=cie.augmentation[ai];if(ch=='L'){if(p>=ae){fail("truncated CIE LSDA encoding");break;}cie.lsda_encoding=d[p++];}else if(ch=='R'){if(p>=ae){fail("truncated CIE FDE encoding");break;}cie.fde_encoding=d[p++];}else if(ch=='P'){if(p>=ae){fail("truncated CIE personality encoding");break;}cie.personality_encoding=d[p++];const auto field=base_va+(p-base_off);auto pr=decode(p,ae,cie.personality_encoding,field,std::nullopt,std::nullopt,"CIE personality reference");if(!uw_ok)break;cie.personality_reference_va=pr.value;cie.personality_indirect=pr.indirect;if(pr.value){std::uint64_t fo=0;if(pr.indirect){if(!load_range(pr.value,1,false,&fo)){fail("indirect CIE personality slot is outside PT_LOAD memory");break;}}else if(!load_range(pr.value,1,true,&fo)){fail("direct CIE personality address is outside executable PT_LOAD memory");break;}if(fo!=std::numeric_limits<std::uint64_t>::max()){cie.personality_reference_file_backed=true;cie.personality_reference_file_offset=fo;}}}else if(ch=='S')cie.signal_frame=true;else{unsupported(std::string("unsupported CIE augmentation character: ")+ch);break;}}
                            if(uw_ok&&p!=ae)fail("CIE augmentation-data length does not match known fields");
                            p=ae;
                        }else unsupported("legacy non-z CIE augmentation is unsupported");
                        if(!uw_ok)break;
                        cie.cfi_file_offset=p;cie.cfi_size=rend-p;
                        if(cie.personality_reference_va){std::string sym;bool imported=false;if(cie.personality_indirect&&out.dynamic.state=="RESOLVED"){for(const auto&r:out.dynamic.relocations)if(r.target_va==cie.personality_reference_va&&r.symbol_index<out.dynamic.symbols.size()){const auto&rs=out.dynamic.symbols[r.symbol_index];if(rs.name.empty())continue;if(sym.empty()){sym=rs.name;imported=rs.imported;}else if(sym!=rs.name){sym.clear();imported=false;break;}}}else if(!cie.personality_indirect&&out.dynamic.state=="RESOLVED"){for(const auto&ds:out.dynamic.symbols)if(ds.value==cie.personality_reference_va&&!ds.name.empty()){if(sym.empty()){sym=ds.name;imported=ds.imported;}else if(sym!=ds.name){sym.clear();imported=false;break;}}}cie.personality_symbol=std::move(sym);cie.personality_imported=imported;}
                        if(!charge(2ull*sizeof(ElfUnwindCie)+map_node_estimate+cie.augmentation.size()+cie.personality_symbol.size(),"CIE rows/bookkeeping"))break;
                        cie_by_file.emplace(cie.file_offset,cie.index);uw.cies.push_back(std::move(cie));
                    }else{
                        if(uw.fdes.size()>=max_fdes){fail(".eh_frame FDE count exceeds limit");break;}if(ident>idfield-base_off){fail("FDE CIE pointer moves before .eh_frame");break;}const auto cie_off=idfield-ident;auto ci=cie_by_file.find(cie_off);if(ci==cie_by_file.end()){fail("FDE CIE pointer does not reference a prior CIE");break;}const auto&cie=uw.cies[ci->second];if(cie.fde_encoding==0xff){unsupported("FDE initial-location encoding is DW_EH_PE_omit");break;}
                        ElfUnwindFde fde;fde.index=static_cast<std::uint32_t>(uw.fdes.size());fde.cie_index=ci->second;fde.file_offset=rec;fde.va=rec_va;fde.record_size=4ull+len;fde.cie_file_offset=cie.file_offset;fde.cie_va=cie.va;
                        const auto start_field=base_va+(p-base_off);auto st=decode(p,rend,cie.fde_encoding,start_field,std::nullopt,std::nullopt,"FDE initial location");if(!uw_ok)break;if(st.indirect||!st.value){if(st.indirect)unsupported("indirect FDE initial location is unsupported");else fail("FDE initial location is null");break;}const auto range_enc=static_cast<std::uint8_t>(cie.fde_encoding&0x0f);auto rr=decode(p,rend,range_enc,0,std::nullopt,std::nullopt,"FDE address range");if(!uw_ok)break;if(rr.indirect||!rr.value){fail("FDE address range is zero/indirect");break;}if(st.value>std::numeric_limits<std::uint64_t>::max()-rr.value){fail("FDE function range overflows address space");break;}fde.function_start_va=st.value;fde.function_size=rr.value;fde.function_end_va=st.value+rr.value;std::uint64_t foff=0;if(!load_range(fde.function_start_va,fde.function_size,true,&foff)){fail("FDE function range is outside one executable PT_LOAD segment");break;}if(foff!=std::numeric_limits<std::uint64_t>::max()){fde.function_file_backed=true;fde.function_file_offset=foff;}
                        if(!cie.augmentation.empty()&&cie.augmentation.front()=='z'){std::uint64_t auglen=0;if(!eh_uleb(d,p,rend,auglen)||auglen>rend-p){fail("invalid FDE augmentation-data length");break;}const auto ae=p+static_cast<std::size_t>(auglen);if(cie.lsda_encoding!=0xff){const auto field=base_va+(p-base_off);auto lr=decode(p,ae,cie.lsda_encoding,field,std::nullopt,fde.function_start_va,"FDE LSDA reference");if(!uw_ok)break;fde.lsda_reference_va=lr.value;fde.lsda_indirect=lr.indirect;if(lr.value){std::uint64_t lo=0;if(!load_range(lr.value,1,false,&lo)){fail("FDE LSDA reference is outside PT_LOAD memory");break;}if(lo!=std::numeric_limits<std::uint64_t>::max()){fde.lsda_file_backed=true;fde.lsda_file_offset=lo;}}}if(uw_ok&&p!=ae)fail("FDE augmentation-data length does not match known fields");p=ae;}
                        if(!uw_ok)break;
                        fde.cfi_file_offset=p;fde.cfi_size=rend-p;
                        if(!charge(2ull*sizeof(ElfUnwindFde)+(header_present?map_node_estimate:0),"FDE rows/bookkeeping"))break;
                        uw.fdes.push_back(std::move(fde));
                    }
                    p=rend;
                }
                if(uw_ok&&!frame_exact&&!terminated)fail("PT_LOAD-bounded .eh_frame has no zero terminator");
                if(uw_ok&&frame_exact&&p<limit){for(auto q=p;q<limit;++q)if(d[q]){fail(".eh_frame has non-zero bytes after terminator");break;}}
            }
            if(uw_ok&&header_present){if(header_rows.size()!=uw.fdes.size()){fail(".eh_frame_hdr FDE count does not match parsed .eh_frame FDE count");}else{std::map<std::uint64_t,std::uint32_t>by_va;for(const auto&f:uw.fdes)if(!by_va.emplace(f.va,f.index).second){fail("duplicate FDE record VA");break;}for(const auto&h:header_rows)if(uw_ok){auto it=by_va.find(h.fde_va);if(it==by_va.end()){fail(".eh_frame_hdr table references unknown FDE");break;}auto&f=uw.fdes[it->second];if(f.header_matched){fail(".eh_frame_hdr table references one FDE more than once");break;}if(f.function_start_va!=h.function_start_va){fail(".eh_frame_hdr initial location disagrees with FDE");break;}f.header_matched=true;}if(uw_ok)for(const auto&f:uw.fdes)if(!f.header_matched){fail("parsed FDE is missing from .eh_frame_hdr table");break;}}}
            if(uw_ok){uw.state="RESOLVED";uw.error.clear();}else uw.state=uw_unsupported?"UNSUPPORTED":"FAILED";
        }
    }
    auto add_dynamic_array=[&](const char*kind,std::uint64_t va,std::uint64_t sz){if(!va||!sz)return;auto off=vaddr_to_file(va);if(!off)return;ElfInitArray a;a.kind=kind;a.address=va;a.offset=*off;a.size=sz;a.entries=pointer_entries(d,*off,sz,out.elf64,le);out.init.arrays.push_back(std::move(a));};
    if(out.sections.empty()){add_dynamic_array("DT_PREINIT_ARRAY",out.init.dt_preinit_array,out.init.dt_preinit_arraysz);add_dynamic_array("DT_INIT_ARRAY",out.init.dt_init_array,out.init.dt_init_arraysz);add_dynamic_array("DT_FINI_ARRAY",out.init.dt_fini_array,out.init.dt_fini_arraysz);}

    if(file_end<d.size()){out.overlay_offset=file_end;out.overlay_size=d.size()-file_end;}
    out.valid=true;
    return out;
}
ElfInfo parse_elf(const std::filesystem::path& p){
    std::ifstream f(p,std::ios::binary);
    if(!f){ElfInfo o;o.error="open failed";return o;}
    std::vector<std::uint8_t> d((std::istreambuf_iterator<char>(f)),{});
    return parse_elf(d);
}

ElfExtractResult extract_elf_dynamic(const ElfInfo&i,const std::filesystem::path&symbols_csv){
    ElfExtractResult r;
    if(!i.valid){r.error="ELF not valid";return r;}
    if(i.dynamic.state!="RESOLVED"){r.error="ELF dynamic plane is not complete: "+i.dynamic.state;if(!i.dynamic.error.empty())r.error += ": "+i.dynamic.error;return r;}
    auto relocs_csv=symbols_csv;auto name=relocs_csv.filename().string();
    const std::string suffix=".elf-symbols.csv";
    if(name.size()>=suffix.size()&&name.compare(name.size()-suffix.size(),suffix.size(),suffix)==0)name.replace(name.size()-suffix.size(),suffix.size(),".elf-relocations.csv");
    else name=relocs_csv.stem().string()+"-relocations.csv";
    relocs_csv=relocs_csv.parent_path()/name;
    std::ofstream sf(symbols_csv,std::ios::binary|std::ios::trunc),rf(relocs_csv,std::ios::binary|std::ios::trunc);
    if(!sf||!rf){r.error="cannot create ELF dynamic extraction CSV";sf.close();rf.close();std::error_code ec;std::filesystem::remove(symbols_csv,ec);ec.clear();std::filesystem::remove(relocs_csv,ec);return r;}
    std::map<std::uint16_t,const ElfVersionRecord*> versions;if(i.abi.state=="RESOLVED")for(const auto&v:i.abi.versions)if(v.index>1)versions.emplace(v.index,&v);
    auto version_of=[&](const ElfDynamicSymbol&s)->const ElfVersionRecord*{auto it=versions.find(s.version_index);return s.version_index>1&&it!=versions.end()?it->second:nullptr;};
    sf<<"symbol_index,entry_file_offset,name_offset,name,binding,binding_name,type,type_name,visibility,visibility_name,section_index,value_va,size,value_file_backed,value_file_offset,imported,exported,version_index,version_hidden,version_name,version_source,version_provider\n";
    for(const auto&x:i.dynamic.symbols){const auto*v=version_of(x);
        sf<<x.index<<",0x"<<std::hex<<x.entry_file_offset<<std::dec<<','<<x.name_offset<<','<<elf_csvq(x.name)<<','<<unsigned(x.binding)<<','<<elf_csvq(elf_symbol_binding_name(x.binding))<<','<<unsigned(x.type)<<','<<elf_csvq(elf_symbol_type_name(x.type))<<','<<unsigned(x.visibility)<<','<<elf_csvq(elf_symbol_visibility_name(x.visibility))<<','<<x.section_index<<",0x"<<std::hex<<x.value<<std::dec<<','<<x.size<<','<<(x.value_file_backed?1:0)<<',';
        if(x.value_file_backed)sf<<"0x"<<std::hex<<x.value_file_offset<<std::dec;
        sf<<','<<(x.imported?1:0)<<','<<(x.exported?1:0)<<','<<x.version_index<<','<<(x.version_hidden?1:0)<<','<<elf_csvq(v?v->name:std::string{})<<','<<elf_csvq(v?v->source:std::string{})<<','<<elf_csvq(v?v->provider:std::string{})<<"\n";
    }
    rf<<"relocation_index,source,entry_file_offset,target_va,target_file_backed,target_file_offset,type,type_name,symbol_index,symbol,symbol_imported,symbol_exported,symbol_version_index,symbol_version_hidden,symbol_version_name,symbol_version_source,symbol_version_provider,has_addend,addend,plt\n";
    for(std::size_t n=0;n<i.dynamic.relocations.size();++n){const auto&x=i.dynamic.relocations[n];const ElfDynamicSymbol*sym=x.symbol_index<i.dynamic.symbols.size()?&i.dynamic.symbols[x.symbol_index]:nullptr;const auto*v=sym?version_of(*sym):nullptr;
        rf<<n<<','<<elf_csvq(x.source)<<",0x"<<std::hex<<x.entry_file_offset<<",0x"<<x.target_va<<std::dec<<','<<(x.target_file_backed?1:0)<<',';
        if(x.target_file_backed)rf<<"0x"<<std::hex<<x.target_file_offset<<std::dec;
        rf<<','<<x.type<<','<<elf_csvq(x.type_name)<<','<<x.symbol_index<<','<<elf_csvq(sym?sym->name:std::string{})<<','<<(x.symbol_imported?1:0)<<','<<(x.symbol_exported?1:0)<<','<<(sym?sym->version_index:0)<<','<<(sym&&sym->version_hidden?1:0)<<','<<elf_csvq(v?v->name:std::string{})<<','<<elf_csvq(v?v->source:std::string{})<<','<<elf_csvq(v?v->provider:std::string{})<<','<<(x.has_addend?1:0)<<',';
        if(x.has_addend)rf<<x.addend;
        rf<<','<<(x.plt?1:0)<<"\n";
    }
    sf.close();rf.close();
    if(!sf||!rf){r.error="write ELF dynamic extraction CSV failed";std::error_code ec;std::filesystem::remove(symbols_csv,ec);ec.clear();std::filesystem::remove(relocs_csv,ec);return r;}
    r.success=true;r.symbols_csv=symbols_csv;r.relocations_csv=relocs_csv;r.symbol_count=i.dynamic.symbols.size();r.relocation_count=i.dynamic.relocations.size();return r;
}

ElfUnwindExtractResult extract_elf_unwind(const ElfInfo&i,const std::filesystem::path&fdes_csv){
    ElfUnwindExtractResult r;
    if(!i.valid){r.error="ELF not valid";return r;}
    if(i.unwind.state!="RESOLVED"){r.error="ELF unwind plane is not complete: "+i.unwind.state;if(!i.unwind.error.empty())r.error += ": "+i.unwind.error;return r;}
    auto cies_csv=fdes_csv;auto name=cies_csv.filename().string();const std::string suffix=".elf-fdes.csv";
    if(name.size()>=suffix.size()&&name.compare(name.size()-suffix.size(),suffix.size(),suffix)==0)name.replace(name.size()-suffix.size(),suffix.size(),".elf-cies.csv");else name=cies_csv.stem().string()+"-cies.csv";
    cies_csv=cies_csv.parent_path()/name;
    auto cleanup=[&](){std::error_code ec;std::filesystem::remove(cies_csv,ec);ec.clear();std::filesystem::remove(fdes_csv,ec);};
    std::ofstream cf(cies_csv,std::ios::binary|std::ios::trunc),ff(fdes_csv,std::ios::binary|std::ios::trunc);
    if(!cf||!ff){r.error="cannot create ELF unwind extraction CSV";cf.close();ff.close();cleanup();return r;}
    cf<<"cie_index,record_file_offset,record_va,record_size,version,address_size,segment_selector_size,augmentation,code_alignment,data_alignment,return_address_register,fde_encoding,lsda_encoding,personality_encoding,personality_reference_va,personality_indirect,personality_reference_file_backed,personality_reference_file_offset,personality_symbol,personality_imported,signal_frame\n";
    for(const auto&x:i.unwind.cies){cf<<x.index<<",0x"<<std::hex<<x.file_offset<<",0x"<<x.va<<std::dec<<','<<x.record_size<<','<<unsigned(x.version)<<','<<unsigned(x.address_size)<<','<<unsigned(x.segment_selector_size)<<','<<elf_csvq(x.augmentation)<<','<<x.code_alignment<<','<<x.data_alignment<<','<<x.return_address_register<<",0x"<<std::hex<<unsigned(x.fde_encoding)<<",0x"<<unsigned(x.lsda_encoding)<<",0x"<<unsigned(x.personality_encoding)<<std::dec<<',';if(x.personality_reference_va)cf<<"0x"<<std::hex<<x.personality_reference_va<<std::dec;cf<<','<<(x.personality_indirect?1:0)<<','<<(x.personality_reference_file_backed?1:0)<<',';if(x.personality_reference_file_backed)cf<<"0x"<<std::hex<<x.personality_reference_file_offset<<std::dec;cf<<','<<elf_csvq(x.personality_symbol)<<','<<(x.personality_imported?1:0)<<','<<(x.signal_frame?1:0)<<"\n";}
    ff<<"fde_index,record_file_offset,record_va,record_size,cie_index,cie_file_offset,cie_va,function_start_va,function_end_va,function_size,function_file_backed,function_file_offset,lsda_reference_va,lsda_indirect,lsda_file_backed,lsda_file_offset,header_matched,personality_reference_va,personality_indirect,personality_symbol,personality_imported\n";
    for(const auto&x:i.unwind.fdes){const auto&c=i.unwind.cies[x.cie_index];ff<<x.index<<",0x"<<std::hex<<x.file_offset<<",0x"<<x.va<<std::dec<<','<<x.record_size<<','<<x.cie_index<<",0x"<<std::hex<<x.cie_file_offset<<",0x"<<x.cie_va<<",0x"<<x.function_start_va<<",0x"<<x.function_end_va<<std::dec<<','<<x.function_size<<','<<(x.function_file_backed?1:0)<<',';if(x.function_file_backed)ff<<"0x"<<std::hex<<x.function_file_offset<<std::dec;ff<<',';if(x.lsda_reference_va)ff<<"0x"<<std::hex<<x.lsda_reference_va<<std::dec;ff<<','<<(x.lsda_indirect?1:0)<<','<<(x.lsda_file_backed?1:0)<<',';if(x.lsda_file_backed)ff<<"0x"<<std::hex<<x.lsda_file_offset<<std::dec;ff<<','<<(x.header_matched?1:0)<<',';if(c.personality_reference_va)ff<<"0x"<<std::hex<<c.personality_reference_va<<std::dec;ff<<','<<(c.personality_indirect?1:0)<<','<<elf_csvq(c.personality_symbol)<<','<<(c.personality_imported?1:0)<<"\n";}
    cf.close();ff.close();if(!cf||!ff){r.error="write ELF unwind extraction CSV failed";cleanup();return r;}
    r.success=true;r.cies_csv=cies_csv;r.fdes_csv=fdes_csv;r.cie_count=i.unwind.cies.size();r.fde_count=i.unwind.fdes.size();return r;
}

std::string elf_machine_name(std::uint16_t m){switch(m){case 3:return"x86";case 40:return"ARM";case 62:return"x86-64";case 183:return"AArch64";case 243:return"RISC-V";case 8:return"MIPS";default:return"EM_"+std::to_string(m);}}
std::string elf_type_name(std::uint16_t t){switch(t){case 1:return"REL";case 2:return"EXEC";case 3:return"DYN";case 4:return"CORE";default:return"ET_"+std::to_string(t);}}
}
