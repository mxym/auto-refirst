#include "prts/dotnet_native.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>

namespace prts {
namespace {
constexpr std::array<std::uint8_t,32> k_bundle_signature={
    0x8b,0x12,0x02,0xb9,0x6a,0x61,0x20,0x38,0x72,0x7b,0x93,0x02,0x14,0xd7,0xa0,0x32,
    0x13,0xf5,0xb9,0xe6,0xef,0xae,0x33,0x18,0xee,0x3b,0x2d,0xce,0x24,0xb3,0x6a,0xae};
constexpr std::uint64_t k_max_entries=4096;
constexpr std::uint64_t k_max_path=4096;

bool span_ok(std::size_t n,std::uint64_t off,std::uint64_t len){
    return off<=n&&len<=static_cast<std::uint64_t>(n)-off;
}
std::uint16_t u16(std::span<const std::uint8_t>d,std::uint64_t o){return static_cast<std::uint16_t>(d[o])|(static_cast<std::uint16_t>(d[o+1])<<8);}
std::uint32_t u32(std::span<const std::uint8_t>d,std::uint64_t o){return static_cast<std::uint32_t>(d[o])|(static_cast<std::uint32_t>(d[o+1])<<8)|(static_cast<std::uint32_t>(d[o+2])<<16)|(static_cast<std::uint32_t>(d[o+3])<<24);}
std::uint64_t u64(std::span<const std::uint8_t>d,std::uint64_t o){
    std::uint64_t v=0;for(unsigned i=0;i<8;i++)v|=static_cast<std::uint64_t>(d[o+i])<<(8*i);return v;
}
bool add_ok(std::uint64_t a,std::uint64_t b,std::uint64_t& out){
    if(b>std::numeric_limits<std::uint64_t>::max()-a)return false;
    out=a+b;return true;
}
bool utf8_valid(std::string_view s){
    for(std::size_t i=0;i<s.size();){
        const auto c=static_cast<unsigned char>(s[i]);
        if(c<0x80){if(c==0)return false;i++;continue;}
        unsigned need=0;std::uint32_t cp=0,min=0;
        if((c&0xe0)==0xc0){need=1;cp=c&0x1f;min=0x80;}
        else if((c&0xf0)==0xe0){need=2;cp=c&0x0f;min=0x800;}
        else if((c&0xf8)==0xf0){need=3;cp=c&0x07;min=0x10000;}
        else return false;
        if(i+need>=s.size())return false;
        for(unsigned j=1;j<=need;j++){
            const auto x=static_cast<unsigned char>(s[i+j]);if((x&0xc0)!=0x80)return false;cp=(cp<<6)|(x&0x3f);
        }
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;
        i+=need+1;
    }
    return true;
}
bool safe_relative_path(std::string_view s){
    if(s.empty()||s.size()>k_max_path||s.front()=='/'||s.back()=='/'||!utf8_valid(s))return false;
    if(s.find('\\')!=std::string_view::npos||s.find(':')!=std::string_view::npos)return false;
    std::size_t start=0;
    while(start<s.size()){
        const auto slash=s.find('/',start);const auto end=slash==std::string_view::npos?s.size():slash;
        const auto part=s.substr(start,end-start);if(part.empty()||part=="."||part=="..")return false;
        for(unsigned char c:part)if(c<0x20||c==0x7f)return false;
        if(slash==std::string_view::npos)break;
        start=slash+1;
    }
    return true;
}
struct Cursor{
    std::span<const std::uint8_t>d;std::uint64_t p=0;std::string error;
    bool take(std::uint64_t n){if(!span_ok(d.size(),p,n)){error="manifest is truncated";return false;}p+=n;return true;}
    bool read32(std::uint32_t&v){if(!span_ok(d.size(),p,4)){error="manifest is truncated";return false;}v=u32(d,p);p+=4;return true;}
    bool read64(std::uint64_t&v){if(!span_ok(d.size(),p,8)){error="manifest is truncated";return false;}v=u64(d,p);p+=8;return true;}
    bool byte(std::uint8_t&v){if(!span_ok(d.size(),p,1)){error="manifest is truncated";return false;}v=d[p++];return true;}
    bool path(std::string&v){
        std::uint8_t a=0;if(!byte(a))return false;std::uint64_t n=a&0x7f;
        if(a&0x80){std::uint8_t b=0;if(!byte(b))return false;if(b&0x80){error="path length encoding exceeds two bytes";return false;}n|=static_cast<std::uint64_t>(b)<<7;}
        if(n==0||n>k_max_path){error="path length is zero or exceeds the bounded limit";return false;}
        if(!span_ok(d.size(),p,n)){error="path string is truncated";return false;}
        v.assign(reinterpret_cast<const char*>(d.data()+p),static_cast<std::size_t>(n));p+=n;return true;
    }
};
const char* type_name(std::uint8_t t){
    static constexpr const char* names[]={"unknown","assembly","native_binary","deps_json","runtimeconfig_json","symbols"};
    return t<6?names[t]:"invalid";
}
DotNetBundleInfo bundle_fail(DotNetBundleInfo i,std::string e){i.valid=false;i.state="FAILED";i.error=std::move(e);return i;}
std::optional<std::uint64_t> va_to_file(const ElfInfo&e,std::uint64_t va){
    for(const auto&s:e.segments){if(s.type!=1||va<s.address)continue;const auto delta=va-s.address;if(delta<s.file_size){std::uint64_t out=0;if(add_ok(s.offset,delta,out))return out;}}
    return std::nullopt;
}
std::optional<std::uint64_t> pe_va_to_file(const PeInfo&p,std::uint64_t va){
    if(va<p.image_base)return std::nullopt;
    const auto rva=va-p.image_base;
    if(rva<p.headers_size)return rva;
    for(const auto&s:p.sections){if(rva<s.rva)continue;const auto delta=rva-s.rva;if(delta<s.raw_size){std::uint64_t out=0;if(add_ok(s.raw_offset,delta,out))return out;}}
    return std::nullopt;
}
bool va_in_memory(const ElfInfo&e,std::uint64_t va,bool endpoint=false){
    for(const auto&s:e.segments){if(s.type!=1||va<s.address)continue;const auto delta=va-s.address;if(delta<s.memory_size||(endpoint&&delta==s.memory_size))return true;}return false;
}
bool native_id(std::uint32_t id){
    switch(id){case 201:case 202:case 204:case 205:case 206:case 207:case 208:case 212:case 213:return true;default:return id>=300&&id<=399;}
}
bool rtr_shape(std::span<const std::uint8_t>d,std::uint64_t off){
    if(!span_ok(d.size(),off,16)||u32(d,off)!=0x00525452||u16(d,off+4)!=16||u16(d,off+6)!=0||u32(d,off+8)!=0)return false;
    const auto count=u16(d,off+12);if(count==0||count>k_max_entries||d[off+14]!=24||d[off+15]!=1)return false;
    std::uint64_t bytes=0,end=0;return add_ok(16,static_cast<std::uint64_t>(count)*24,bytes)&&add_ok(off,bytes,end)&&end<=d.size();
}
NativeAotInfo native_fail(NativeAotInfo i,std::string e){i.valid=false;i.state="FAILED";i.error=std::move(e);return i;}
}

DotNetBundleInfo detect_dotnet_bundle(std::span<const std::uint8_t> data,const PeInfo& pe,const ElfInfo& elf){
    DotNetBundleInfo out;std::vector<std::uint64_t> sigs;
    if(data.size()>=k_bundle_signature.size())for(std::size_t i=0;i+k_bundle_signature.size()<=data.size();i++){
        if(std::equal(k_bundle_signature.begin(),k_bundle_signature.end(),data.begin()+static_cast<std::ptrdiff_t>(i)))sigs.push_back(i);
    }
    if(sigs.empty())return out;
    out.candidate=true;
    if(sigs.size()!=1)return bundle_fail(out,"bundle locator signature is not unique");
    if(sigs[0]<8)return bundle_fail(out,"bundle locator signature has no preceding header offset");
    out.locator_offset=sigs[0]-8;if(!pe.valid&&!elf.valid)return bundle_fail(out,"bundle locator is not inside a validated PE or ELF image");
    const auto raw_header=u64(data,out.locator_offset);
    if((raw_header>>63)!=0||raw_header==0||raw_header>=data.size())return bundle_fail(out,"bundle header offset is invalid");
    out.header_offset=raw_header;
    if(out.header_offset<=sigs[0]+k_bundle_signature.size())return bundle_fail(out,"bundle header does not follow the complete apphost locator");
    Cursor c{data,out.header_offset,{}};std::uint32_t count=0;
    if(!c.read32(out.major_version)||!c.read32(out.minor_version)||!c.read32(count))return bundle_fail(out,c.error);
    if(!((out.major_version==2||out.major_version==6)&&out.minor_version==0))return bundle_fail(out,"unsupported or unknown bundle manifest version");
    if(count==0||count>k_max_entries)return bundle_fail(out,"bundle entry count is zero or exceeds the bounded limit");
    out.file_count=count;
    if(!c.path(out.bundle_id))return bundle_fail(out,c.error);
    if(out.bundle_id.size()!=12||!std::all_of(out.bundle_id.begin(),out.bundle_id.end(),[](unsigned char ch){return std::isalnum(ch)||ch=='-'||ch=='_';}))return bundle_fail(out,"bundle ID is not the official 12-byte base64url form");
    if(!c.read64(out.deps_json_offset)||!c.read64(out.deps_json_size)||!c.read64(out.runtimeconfig_json_offset)||!c.read64(out.runtimeconfig_json_size)||!c.read64(out.flags))return bundle_fail(out,c.error);
    if((out.deps_json_offset>>63)||(out.deps_json_size>>63)||(out.runtimeconfig_json_offset>>63)||(out.runtimeconfig_json_size>>63))return bundle_fail(out,"cached JSON location contains a negative signed value");
    if((out.flags&~std::uint64_t{1})!=0)return bundle_fail(out,"bundle header contains unknown flags");
    std::set<std::string> paths;std::vector<std::pair<std::uint64_t,std::uint64_t>> spans;
    std::optional<std::pair<std::uint64_t,std::uint64_t>> deps,config;
    for(std::uint32_t i=0;i<count;i++){
        DotNetBundleEntry entry;entry.index=i;
        if(!c.read64(entry.offset)||!c.read64(entry.size))return bundle_fail(out,c.error);
        if(out.major_version>=6&&!c.read64(entry.compressed_size))return bundle_fail(out,c.error);
        if((entry.offset>>63)||(entry.size>>63)||(entry.compressed_size>>63))return bundle_fail(out,"bundle entry contains a negative signed value");
        if(!c.byte(entry.type)||entry.type>=6)return bundle_fail(out,"bundle entry has an unknown file type");
        if(!c.path(entry.relative_path))return bundle_fail(out,c.error);
        if(!safe_relative_path(entry.relative_path))return bundle_fail(out,"bundle entry path is not strict normalized relative UTF-8");
        if(!paths.insert(entry.relative_path).second)return bundle_fail(out,"bundle manifest contains a duplicate normalized path");
        if(entry.offset==0)return bundle_fail(out,"bundle entry offset is zero");
        entry.compressed=entry.compressed_size!=0;entry.stored_size=entry.compressed?entry.compressed_size:entry.size;entry.type_name=type_name(entry.type);
        if(entry.compressed&&(out.major_version<6||entry.size==0||entry.compressed_size>=entry.size))return bundle_fail(out,"compressed bundle entry has invalid size geometry");
        std::uint64_t end=0;if(!add_ok(entry.offset,entry.stored_size,end)||entry.offset<sigs[0]+k_bundle_signature.size()||end>out.header_offset)return bundle_fail(out,"bundle entry span is outside the embedded-data region");
        spans.emplace_back(entry.offset,end);
        if(!add_ok(out.stored_bytes,entry.stored_size,out.stored_bytes)||!add_ok(out.uncompressed_bytes,entry.size,out.uncompressed_bytes))return bundle_fail(out,"bundle aggregate byte count overflow");
        if(entry.compressed)out.compressed_file_count++;
        if(entry.type==3){if(deps)return bundle_fail(out,"bundle has multiple deps.json manifest entries");deps={{entry.offset,entry.size}};}
        if(entry.type==4){if(config)return bundle_fail(out,"bundle has multiple runtimeconfig.json manifest entries");config={{entry.offset,entry.size}};}
        out.entries.push_back(std::move(entry));
    }
    std::sort(spans.begin(),spans.end());for(std::size_t i=1;i<spans.size();i++)if(spans[i].first<spans[i-1].second)return bundle_fail(out,"bundle entry spans overlap");
    const auto cached_ok=[](std::uint64_t off,std::uint64_t size,const std::optional<std::pair<std::uint64_t,std::uint64_t>>&entry){return entry?(off==entry->first&&size==entry->second):(off==0&&size==0);};
    if(!cached_ok(out.deps_json_offset,out.deps_json_size,deps)||!cached_ok(out.runtimeconfig_json_offset,out.runtimeconfig_json_size,config))return bundle_fail(out,"cached JSON locations do not exactly match unique manifest entries");
    out.manifest_end=c.p;out.trailing_bytes=data.size()-c.p;out.valid=true;
    out.integrity_state=out.compressed_file_count?"MEMBER_METADATA_ONLY_COMPRESSED_CONTENT_NOT_VALIDATED":"FORMAT_HAS_NO_PER_ENTRY_CRC_OR_HASH";
    if(out.trailing_bytes){out.state="PARTIAL";out.error="validated manifest has unexplained trailing bytes";}else out.state="CONFIRMED";
    return out;
}

Finding dotnet_bundle_finding(const DotNetBundleInfo& i){
    Finding f;f.kind="container";f.family=".NET single-file bundle";f.variant="v"+std::to_string(i.major_version)+"."+std::to_string(i.minor_version);f.state=i.state;
    if(!i.valid){if(!i.error.empty())f.negative_evidence.push_back(i.error);return f;}
    f.evidence={"unique apphost locator and header offset validated","manifest version, count, paths, cached JSON locations, and non-overlapping member spans validated"};
    f.fields["bundle_id"]=i.bundle_id;f.fields["files"]=std::to_string(i.file_count);f.fields["compressed_files"]=std::to_string(i.compressed_file_count);f.fields["integrity_state"]=i.integrity_state;
    if(i.compressed_file_count)f.negative_evidence.push_back("compressed member content was not decompressed or validated; only bundle metadata is reported");
    if(i.trailing_bytes)f.negative_evidence.push_back(i.error);
    f.ranges.push_back(file_offset_range(i.header_offset,i.manifest_end-i.header_offset,".NET bundle header and manifest"));f.suggested_actions={"extract validated bundle member spans","analyze extracted managed assemblies separately"};return f;
}

NativeAotInfo detect_native_aot(std::span<const std::uint8_t> data,const PeInfo& pe,const ElfInfo& elf){
    NativeAotInfo out;
    if(pe.valid){
        out.platform="PE";
        std::vector<const PeSection*> modules;
        for(const auto&s:pe.sections)if(s.name==".modules")modules.push_back(&s);
        if(pe.pe64&&!pe.clr.present&&modules.size()==1){
            const auto&m=*modules.front();
            if(m.vsize==8&&m.raw_size>=8&&span_ok(data.size(),m.raw_offset,8)){
                const auto pointer=u64(data,m.raw_offset);const auto mapped=pe_va_to_file(pe,pointer);
                if(mapped&&rtr_shape(data,*mapped)){
                    out.candidate=true;out.state="PENDING_WINDOWS_VALIDATION";out.error="PE .modules pointer/RTR structure is intentionally unconfirmed pending an official Windows NativeAOT fixture";
                    out.modules_offset=m.raw_offset;out.modules_size=8;out.header_va=pointer;out.header_offset=*mapped;
                    out.major_version=u16(data,*mapped+4);out.minor_version=u16(data,*mapped+6);out.section_count=u16(data,*mapped+12);out.entry_size=data[*mapped+14];out.entry_type=data[*mapped+15];
                    for(std::size_t i=0;i+4<=data.size();i++)if(u32(data,i)==0x00525452){out.raw_rtr_magic_count++;if(rtr_shape(data,i))out.valid_rtr_header_count++;}
                }
            }
        }
        return out;
    }
    if(!elf.valid)return out;
    out.platform="ELF";
    if(!elf.elf64||!elf.little_endian)return out;
    std::vector<const ElfSection*> modules;
    for(const auto&s:elf.sections){if(s.name=="__modules")modules.push_back(&s);if(s.name=="__managedcode"&&(s.flags&2)&&(s.flags&4)&&s.size)out.has_managed_code_section=true;if(s.name==".dotnet_eh_table"&&(s.flags&2)&&s.size)out.has_dotnet_eh_table=true;if(s.name==".hydrated"&&(s.flags&2)&&s.type==8&&s.size)out.has_hydrated_section=true;}
    if(modules.empty())return out;
    out.candidate=true;
    if(modules.size()!=1)return native_fail(out,"ELF contains multiple __modules sections");
    const auto&m=*modules.front();out.modules_offset=m.offset;out.modules_size=m.size;
    if(m.type!=1||m.size!=8||!span_ok(data.size(),m.offset,m.size))return native_fail(out,"__modules is not one file-backed 64-bit pointer");
    out.header_va=u64(data,m.offset);const auto mapped=va_to_file(elf,out.header_va);if(!mapped)return native_fail(out,"__modules pointer does not map to file-backed ELF data");out.header_offset=*mapped;
    for(std::size_t i=0;i+4<=data.size();i++)if(u32(data,i)==0x00525452){out.raw_rtr_magic_count++;if(rtr_shape(data,i))out.valid_rtr_header_count++;}
    if(out.valid_rtr_header_count!=1||!rtr_shape(data,out.header_offset))return native_fail(out,"__modules does not resolve to the unique bounded legal NativeAOT R2R header");
    out.major_version=u16(data,out.header_offset+4);out.minor_version=u16(data,out.header_offset+6);out.section_count=u16(data,out.header_offset+12);out.entry_size=data[out.header_offset+14];out.entry_type=data[out.header_offset+15];
    std::set<std::uint32_t> ids;bool has_type_manager=false,has_initializer=false,has_blob=false;
    std::uint64_t p=out.header_offset+16;
    for(std::uint16_t n=0;n<out.section_count;n++,p+=24){
        NativeAotSectionRow row;row.id=u32(data,p);row.flags=u32(data,p+4);row.start_va=u64(data,p+8);row.end_va=u64(data,p+16);
        if(!ids.insert(row.id).second)return native_fail(out,"NativeAOT R2R table has duplicate section IDs");
        if(!native_id(row.id))return native_fail(out,"R2R table contains a non-NativeAOT section ID");
        if((row.flags&~std::uint32_t{1})!=0)return native_fail(out,"NativeAOT R2R row contains unknown flags");
        if(!va_in_memory(elf,row.start_va))return native_fail(out,"NativeAOT R2R start pointer is outside ELF load memory");
        if(row.flags&1){if(row.end_va<row.start_va||!va_in_memory(elf,row.end_va,true))return native_fail(out,"NativeAOT R2R end pointer is outside ELF load memory");}
        else if(row.end_va!=0)return native_fail(out,"NativeAOT R2R row without HasEndPointer has a nonzero end pointer");
        out.native_section_id_count++;has_type_manager|=row.id==204;has_initializer|=row.id==205||row.id==213;has_blob|=row.id>=300&&row.id<=399;out.sections.push_back(row);
    }
    if(out.native_section_id_count<4||!has_type_manager||!has_initializer||!has_blob)return native_fail(out,"R2R table lacks the required combined NativeAOT section-ID evidence");
    if(!out.has_managed_code_section||!out.has_dotnet_eh_table||!out.has_hydrated_section)return native_fail(out,"ELF lacks the required __managedcode/.dotnet_eh_table/.hydrated section combination");
    out.valid=true;out.state="CONFIRMED";return out;
}

Finding native_aot_finding(const NativeAotInfo&i){
    Finding f;f.kind="runtime";f.family=".NET NativeAOT";f.variant=i.platform+" R2R v"+std::to_string(i.major_version)+"."+std::to_string(i.minor_version);f.state=i.state;
    if(!i.valid){if(!i.error.empty())f.negative_evidence.push_back(i.error);return f;}
    f.evidence={"unique file-backed __modules pointer resolves to the unique bounded legal R2R header","NativeAOT 24-byte pointer rows, official section IDs, and ELF load-memory pointers validated","__managedcode, .dotnet_eh_table, and NOBITS .hydrated sections jointly validated"};
    f.fields["sections"]=std::to_string(i.section_count);f.fields["native_section_ids"]=std::to_string(i.native_section_id_count);f.fields["raw_rtr_magic_count"]=std::to_string(i.raw_rtr_magic_count);f.fields["valid_rtr_header_count"]=std::to_string(i.valid_rtr_header_count);
    if(i.raw_rtr_magic_count>1)f.evidence.push_back("additional raw RTR magic was rejected as a structural decoy");
    f.negative_evidence.push_back("native-image recognition does not recover IL or source code");f.ranges.push_back(file_offset_range(i.modules_offset,i.modules_size,"ELF __modules pointer"));f.ranges.push_back(file_offset_range(i.header_offset,16+static_cast<std::uint64_t>(i.section_count)*i.entry_size,"NativeAOT R2R header/table"));return f;
}
} // namespace prts
