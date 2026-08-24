#include "prts/macho.hpp"
#include "prts/sha256.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <set>
#include <span>
#include <string_view>
#include <unordered_map>

namespace prts {

std::string macho_load_command_name(std::uint32_t command) {
    switch (command) {
    case 0x00000001u:return "LC_SEGMENT";
    case 0x00000002u:return "LC_SYMTAB";
    case 0x00000003u:return "LC_SYMSEG";
    case 0x00000004u:return "LC_THREAD";
    case 0x00000005u:return "LC_UNIXTHREAD";
    case 0x00000006u:return "LC_LOADFVMLIB";
    case 0x00000007u:return "LC_IDFVMLIB";
    case 0x00000008u:return "LC_IDENT";
    case 0x00000009u:return "LC_FVMFILE";
    case 0x0000000au:return "LC_PREPAGE";
    case 0x0000000bu:return "LC_DYSYMTAB";
    case 0x0000000cu:return "LC_LOAD_DYLIB";
    case 0x0000000du:return "LC_ID_DYLIB";
    case 0x0000000eu:return "LC_LOAD_DYLINKER";
    case 0x0000000fu:return "LC_ID_DYLINKER";
    case 0x00000010u:return "LC_PREBOUND_DYLIB";
    case 0x00000011u:return "LC_ROUTINES";
    case 0x00000012u:return "LC_SUB_FRAMEWORK";
    case 0x00000013u:return "LC_SUB_UMBRELLA";
    case 0x00000014u:return "LC_SUB_CLIENT";
    case 0x00000015u:return "LC_SUB_LIBRARY";
    case 0x00000016u:return "LC_TWOLEVEL_HINTS";
    case 0x00000017u:return "LC_PREBIND_CKSUM";
    case 0x80000018u:return "LC_LOAD_WEAK_DYLIB";
    case 0x00000019u:return "LC_SEGMENT_64";
    case 0x0000001au:return "LC_ROUTINES_64";
    case 0x0000001bu:return "LC_UUID";
    case 0x8000001cu:return "LC_RPATH";
    case 0x0000001du:return "LC_CODE_SIGNATURE";
    case 0x0000001eu:return "LC_SEGMENT_SPLIT_INFO";
    case 0x8000001fu:return "LC_REEXPORT_DYLIB";
    case 0x00000020u:return "LC_LAZY_LOAD_DYLIB";
    case 0x00000021u:return "LC_ENCRYPTION_INFO";
    case 0x00000022u:return "LC_DYLD_INFO";
    case 0x80000022u:return "LC_DYLD_INFO_ONLY";
    case 0x80000023u:return "LC_LOAD_UPWARD_DYLIB";
    case 0x00000024u:return "LC_VERSION_MIN_MACOSX";
    case 0x00000025u:return "LC_VERSION_MIN_IPHONEOS";
    case 0x00000026u:return "LC_FUNCTION_STARTS";
    case 0x00000027u:return "LC_DYLD_ENVIRONMENT";
    case 0x80000028u:return "LC_MAIN";
    case 0x00000029u:return "LC_DATA_IN_CODE";
    case 0x0000002au:return "LC_SOURCE_VERSION";
    case 0x0000002bu:return "LC_DYLIB_CODE_SIGN_DRS";
    case 0x0000002cu:return "LC_ENCRYPTION_INFO_64";
    case 0x0000002du:return "LC_LINKER_OPTION";
    case 0x0000002eu:return "LC_LINKER_OPTIMIZATION_HINT";
    case 0x0000002fu:return "LC_VERSION_MIN_TVOS";
    case 0x00000030u:return "LC_VERSION_MIN_WATCHOS";
    case 0x00000031u:return "LC_NOTE";
    case 0x00000032u:return "LC_BUILD_VERSION";
    case 0x80000033u:return "LC_DYLD_EXPORTS_TRIE";
    case 0x80000034u:return "LC_DYLD_CHAINED_FIXUPS";
    case 0x80000035u:return "LC_FILESET_ENTRY";
    case 0x00000036u:return "LC_ATOM_INFO";
    default:return {};
    }
}

std::string macho_architecture_name(std::int32_t cpu,std::int32_t subtype) {
    const auto c=static_cast<std::uint32_t>(cpu);
    const auto s=static_cast<std::uint32_t>(subtype);
    if(c==0x0100000cu)return (s&0x00ffffffu)==2u?"arm64e":"arm64";
    return macho_cpu_name(cpu);
}

namespace {

constexpr std::uint32_t kMaxTypes=4096;
constexpr std::uint32_t kMaxFieldDescriptors=4096;
constexpr std::uint32_t kMaxFields=65536;
constexpr std::uint32_t kMaxPointers=131072;
constexpr std::uint32_t kMaxStrings=65536;
constexpr std::uint64_t kMaxStringBytes=4ull*1024*1024;
constexpr std::size_t kMaxString=4096;
constexpr std::uint32_t kMaxContextDepth=64;

template<class T>T swapv(T value){T out=0;for(std::size_t i=0;i<sizeof(T);++i){out=static_cast<T>((out<<8)|(value&0xff));value=static_cast<T>(value>>8);}return out;}

template<class T>bool read_local(std::span<const std::uint8_t> data,std::size_t offset,bool little,T& value){
    if(offset>data.size()||sizeof(T)>data.size()-offset)return false;
    std::memcpy(&value,data.data()+offset,sizeof(T));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    if(!little)value=swapv(value);
#else
    if(little)value=swapv(value);
#endif
    return true;
}

bool zerofill(std::uint32_t flags){const auto type=flags&0xffu;return type==1u||type==0xcu||type==0x12u;}

bool starts_with(std::string_view value,std::string_view prefix){return value.size()>=prefix.size()&&value.substr(0,prefix.size())==prefix;}

bool add_u64(std::uint64_t a,std::uint64_t b,std::uint64_t& out){if(a>std::numeric_limits<std::uint64_t>::max()-b)return false;out=a+b;return true;}

bool ranges_overlap(std::uint64_t a,std::uint64_t as,std::uint64_t b,std::uint64_t bs){
    if(!as||!bs)return false;
    std::uint64_t ae=0,be=0;
    if(!add_u64(a,as,ae)||!add_u64(b,bs,be))return true;
    return a<be&&b<ae;
}

bool valid_utf8(std::span<const std::uint8_t> bytes){
    std::size_t i=0;
    while(i<bytes.size()){
        const auto c=bytes[i];
        if(c<0x20u||c==0x7fu)return false;
        if(c<0x80u){++i;continue;}
        std::size_t n=0;std::uint32_t cp=0;
        if((c&0xe0u)==0xc0u){n=2;cp=c&0x1fu;if(cp<2)return false;}
        else if((c&0xf0u)==0xe0u){n=3;cp=c&0x0fu;}
        else if((c&0xf8u)==0xf0u){n=4;cp=c&0x07u;if(cp>4)return false;}
        else return false;
        if(n>bytes.size()-i)return false;
        for(std::size_t j=1;j<n;++j){const auto t=bytes[i+j];if((t&0xc0u)!=0x80u)return false;cp=(cp<<6)|(t&0x3fu);}
        if((n==3&&cp<0x800u)||(n==4&&cp<0x10000u)||cp>0x10ffffu||(cp>=0xd800u&&cp<=0xdfffu))return false;
        i+=n;
    }
    return true;
}

struct ParsedMangledName {
    bool present=false,plain_text=false;
    std::string text,sha256;
    std::uint32_t byte_length=0,symbolic_references=0;
};

struct ParsedFieldDescriptor {
    std::uint64_t offset=0;
    std::uint16_t kind=0;
    ParsedMangledName mangled_type;
    std::vector<MachOSwiftField> fields;
};

class SwiftParser {
public:
    SwiftParser(std::span<const std::uint8_t> bytes,std::uint64_t base,MachOSlice& slice)
        :data(bytes),absolute_base(base),out(slice),swift(slice.swift){}

    void run(){
        inventory();
        if(!swift.present)return;
        swift.state="SWIFT_PRESENCE";swift.evidence_level="SWIFT_PRESENCE";
        const MachOSection* fieldmd=unique_section("__swift5_fieldmd");
        auto type_sections=sections_named("__swift5_types");
        if(type_sections.empty())return;
        if(!fieldmd){partial("__swift5_types is present without a unique __swift5_fieldmd section");return;}
        if(section_encrypted(*fieldmd)){partial("__swift5_fieldmd overlaps the encrypted file interval");return;}
        if(!parse_field_descriptors(*fieldmd))return;
        for(const auto* section:type_sections){
            if(section_encrypted(*section)){partial("__swift5_types overlaps the encrypted file interval");continue;}
            parse_types(*section);
        }
        if(swift.types.empty()){partial("no complete module-to-type-to-field relationship closure was established");return;}
        swift.structured=true;swift.state="SWIFT_STRUCTURED";swift.evidence_level="SWIFT_STRUCTURED";swift.coverage_state="STRUCTURED";
        if(!swift.reasons.empty())swift.coverage_state="PARTIAL";
        for(auto& section:swift.sections)if(section.name=="__swift5_types"||section.name=="__swift5_fieldmd")section.state="STRUCTURED";
    }

private:
    std::span<const std::uint8_t> data;
    std::uint64_t absolute_base;
    MachOSlice& out;
    MachOSwiftInfo& swift;
    std::vector<const MachOSection*> swift_sections;
    std::vector<ParsedFieldDescriptor> descriptors;
    std::unordered_map<std::uint64_t,std::size_t> descriptor_by_offset;
    std::set<std::uint64_t> type_targets;
    std::set<std::string> type_relations;

    void partial(const std::string& reason,bool limited=false){
        swift.coverage_state="PARTIAL";swift.analysis_limited=swift.analysis_limited||limited;
        if(swift.error.empty())swift.error=reason;
        if(swift.reasons.size()<64&&std::find(swift.reasons.begin(),swift.reasons.end(),reason)==swift.reasons.end())swift.reasons.push_back(reason);
    }

    bool local_offset(std::uint64_t absolute,std::size_t need,std::size_t& local)const{
        if(absolute<absolute_base)return false;
        const auto delta=absolute-absolute_base;
        if(delta>data.size()||need>data.size()-static_cast<std::size_t>(delta))return false;
        local=static_cast<std::size_t>(delta);return true;
    }

    const MachOSection* section_for_file(std::uint64_t absolute,std::size_t need)const{
        for(const auto& section:out.sections){
            if(zerofill(section.flags)||absolute<section.offset)continue;
            const auto delta=absolute-section.offset;
            if(delta<=section.size&&need<=section.size-delta)return &section;
        }
        return nullptr;
    }

    bool encrypted(std::uint64_t absolute,std::uint64_t size)const{return out.encrypted&&ranges_overlap(absolute,size,out.crypt_offset,out.crypt_size);}
    bool section_encrypted(const MachOSection& section)const{return encrypted(section.offset,section.size);}

    bool file_to_va(std::uint64_t absolute,std::uint64_t& va)const{
        const auto* section=section_for_file(absolute,1);if(!section)return false;
        const auto delta=absolute-section->offset;if(!add_u64(section->address,delta,va))return false;return true;
    }

    bool va_to_file(std::uint64_t va,std::size_t need,std::uint64_t& absolute)const{
        for(const auto& section:out.sections){
            if(zerofill(section.flags)||va<section.address)continue;
            const auto delta=va-section.address;
            if(delta>section.size||need>section.size-delta)continue;
            if(!add_u64(section.offset,delta,absolute))return false;
            std::size_t ignored=0;return local_offset(absolute,need,ignored);
        }
        return false;
    }

    template<class T>bool read_abs(std::uint64_t absolute,T& value,const char* what){
        if(encrypted(absolute,sizeof(T))){partial(std::string(what)+" overlaps the encrypted file interval");return false;}
        std::size_t local=0;if(!local_offset(absolute,sizeof(T),local)||!section_for_file(absolute,sizeof(T))){partial(std::string(what)+" exceeds a file-backed section");return false;}
        if(!read_local(data,local,out.little_endian,value)){partial(std::string(what)+" is truncated");return false;}return true;
    }

    bool relative_target(std::uint64_t field,std::uint32_t clear_mask,bool nullable,std::uint64_t& target,const char* what){
        if(swift.relative_pointers_used>=kMaxPointers){partial("Swift relative-pointer budget exceeded",true);return false;}
        ++swift.relative_pointers_used;
        std::uint32_t opaque=0;if(!read_abs(field,opaque,what))return false;
        const auto masked=opaque&~clear_mask;
        if(nullable&&masked==0){target=0;return true;}
        std::uint64_t field_va=0;if(!file_to_va(field,field_va)){partial(std::string(what)+" field is not file-backed");return false;}
        const auto relative=static_cast<std::int32_t>(masked);
        std::uint64_t target_va=0;
        if(relative<0){const auto magnitude=static_cast<std::uint64_t>(-static_cast<std::int64_t>(relative));if(field_va<magnitude){partial(std::string(what)+" underflows address space");return false;}target_va=field_va-magnitude;}
        else if(!add_u64(field_va,static_cast<std::uint32_t>(relative),target_va)){partial(std::string(what)+" overflows address space");return false;}
        if(!va_to_file(target_va,1,target)){partial(std::string(what)+" target is not in a file-backed section");return false;}
        return true;
    }

    bool string_from_pointer(std::uint64_t field,bool nullable,std::string& value,const char* what){
        std::uint64_t target=0;if(!relative_target(field,0,nullable,target,what))return false;
        if(!target){value.clear();return true;}
        const auto* section=section_for_file(target,1);if(!section){partial(std::string(what)+" string target is not file-backed");return false;}
        if(section_encrypted(*section)){partial(std::string(what)+" string section overlaps the encrypted file interval");return false;}
        if(swift.strings_used>=kMaxStrings){partial("Swift string-count budget exceeded",true);return false;}
        const auto available=section->size-(target-section->offset);
        const auto bounded=static_cast<std::size_t>(std::min<std::uint64_t>(available,kMaxString+1));
        std::size_t local=0;if(!local_offset(target,bounded,local)){partial(std::string(what)+" string range is truncated");return false;}
        std::size_t length=0;while(length<bounded&&data[local+length])++length;
        if(length==bounded){partial(std::string(what)+" string is not NUL-terminated within budget");return false;}
        const auto bytes=data.subspan(local,length);if(!valid_utf8(bytes)){partial(std::string(what)+" string is not strict UTF-8 text");return false;}
        if(swift.string_bytes_used>kMaxStringBytes-(length+1)){partial("Swift string-byte budget exceeded",true);return false;}
        ++swift.strings_used;swift.string_bytes_used+=length+1;
        value.assign(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        if(!nullable&&value.empty()){partial(std::string(what)+" string is empty");return false;}
        return true;
    }

    template<class T>static void copy_mangled(const ParsedMangledName& source,T& destination){
        destination.mangled_type_name=source.text;
        destination.mangled_type_sha256=source.sha256;
        destination.mangled_type_byte_length=source.byte_length;
        destination.mangled_type_symbolic_references=source.symbolic_references;
        destination.mangled_type_present=source.present;
        destination.mangled_type_plain_text=source.plain_text;
    }

    bool mangled_from_pointer(std::uint64_t field,bool nullable,ParsedMangledName& value,const char* what){
        std::uint64_t target=0;if(!relative_target(field,0,nullable,target,what))return false;
        if(!target){if(!nullable){partial(std::string(what)+" is absent");return false;}++swift.mangled_type_names_absent;return true;}
        value.present=true;
        const auto* section=section_for_file(target,1);if(!section){partial(std::string(what)+" target is not file-backed");return false;}
        if(section_encrypted(*section)){partial(std::string(what)+" overlaps the encrypted file interval");return false;}
        if(swift.strings_used>=kMaxStrings){partial("Swift string-count budget exceeded",true);return false;}
        const auto available=section->size-(target-section->offset);
        const auto bounded=static_cast<std::size_t>(std::min<std::uint64_t>(available,kMaxString+1));
        std::size_t local=0;if(!local_offset(target,bounded,local)){partial(std::string(what)+" range is truncated");return false;}
        std::size_t cursor=0,plain_start=0;
        while(cursor<bounded){
            const auto byte=data[local+cursor];
            if(!byte){
                if(!cursor){partial(std::string(what)+" is empty");return false;}
                if(!valid_utf8(data.subspan(local+plain_start,cursor-plain_start))){partial(std::string(what)+" has invalid UTF-8 outside symbolic references");return false;}
                if(swift.string_bytes_used>kMaxStringBytes-(cursor+1)){partial("Swift string-byte budget exceeded",true);return false;}
                const auto bytes=data.subspan(local,cursor);value.byte_length=static_cast<std::uint32_t>(cursor);value.sha256=sha256_bytes(bytes);
                value.plain_text=value.symbolic_references==0;
                if(value.plain_text)value.text.assign(reinterpret_cast<const char*>(bytes.data()),bytes.size());
                else ++swift.mangled_type_names_symbolic;
                ++swift.strings_used;swift.string_bytes_used+=cursor+1;return true;
            }
            if(byte>=0x01u&&byte<=0x1fu){
                if(!valid_utf8(data.subspan(local+plain_start,cursor-plain_start))){partial(std::string(what)+" has invalid UTF-8 outside symbolic references");return false;}
                const std::size_t payload=byte<=0x17u?sizeof(std::uint32_t):(out.macho64?sizeof(std::uint64_t):sizeof(std::uint32_t));
                if(payload+1>bounded-cursor){partial(std::string(what)+" symbolic reference is truncated within the bounded section range");return false;}
                ++value.symbolic_references;cursor+=payload+1;plain_start=cursor;continue;
            }
            ++cursor;
        }
        partial(std::string(what)+" is not NUL-terminated within budget");return false;
    }

    void inventory(){
        for(const auto& section:out.sections){
            if(section.segment=="__LLVM"&&section.name=="__bundle"){out.bitcode_present=true;out.bitcode_state="BITCODE_PRESENT";}
            if(!starts_with(section.name,"__swift5_")&&section.name!="__swift_modhash")continue;
            swift.present=true;swift_sections.push_back(&section);
            const bool overlap=section_encrypted(section);
            swift.sections.push_back({section.segment,section.name,overlap?"ENCRYPTED_CONTENT":"PRESENCE_ONLY",section.offset,section.size,overlap});
            if(overlap)partial("Swift section "+section.segment+","+section.name+" overlaps the encrypted file interval");
        }
    }

    std::vector<const MachOSection*> sections_named(std::string_view name)const{
        std::vector<const MachOSection*> result;for(const auto* section:swift_sections)if(section->name==name)result.push_back(section);return result;
    }

    const MachOSection* unique_section(std::string_view name){
        auto matches=sections_named(name);if(matches.size()>1){partial("duplicate Swift section "+std::string(name));return nullptr;}return matches.empty()?nullptr:matches.front();
    }

    bool parse_field_descriptors(const MachOSection& section){
        std::uint64_t cursor=section.offset,end=0;if(!add_u64(section.offset,section.size,end)){partial("__swift5_fieldmd range overflow");return false;}
        while(cursor<end){
            if(swift.field_descriptors_used>=kMaxFieldDescriptors){partial("Swift field-descriptor budget exceeded",true);return false;}
            if(end-cursor<16){partial("__swift5_fieldmd descriptor header is truncated");return false;}
            std::uint16_t kind=0,stride=0;std::uint32_t count=0;
            if(!read_abs(cursor+8,kind,"Swift field descriptor kind")||!read_abs(cursor+10,stride,"Swift field record stride")||!read_abs(cursor+12,count,"Swift field record count"))return false;
            if(stride<12||stride%4){partial("Swift field record stride is invalid");return false;}
            if(count>kMaxFields-swift.field_records_used){partial("Swift field-record budget exceeded",true);return false;}
            const auto record_bytes=std::uint64_t(count)*stride;if(record_bytes>end-cursor-16){partial("Swift field records exceed __swift5_fieldmd");return false;}
            if(kind>7){
                partial("Swift field descriptor kind is unknown");++swift.field_descriptors_used;++swift.field_descriptors_skipped;++swift.field_descriptors_partial;
                swift.field_records_used+=count;swift.field_records_skipped+=count;swift.field_records_partial+=count;cursor+=16+record_bytes;continue;
            }
            ParsedFieldDescriptor descriptor;descriptor.offset=cursor;descriptor.kind=kind;bool descriptor_ok=true;
            if(!mangled_from_pointer(cursor,true,descriptor.mangled_type,"Swift field-descriptor mangled type"))descriptor_ok=false;
            ParsedMangledName superclass;if(!mangled_from_pointer(cursor+4,true,superclass,"Swift field-descriptor superclass"))descriptor_ok=false;
            descriptor.fields.reserve(count);
            for(std::uint32_t i=0;i<count;++i){
                const auto record=cursor+16+std::uint64_t(i)*stride;MachOSwiftField field;field.record_offset=record;bool record_ok=true;
                if(!read_abs(record,field.flags,"Swift field flags"))record_ok=false;
                ParsedMangledName mangled;if(!mangled_from_pointer(record+4,true,mangled,"Swift field mangled type"))record_ok=false;else copy_mangled(mangled,field);
                if(!string_from_pointer(record+8,false,field.name,"Swift field name"))record_ok=false;
                ++swift.field_records_used;
                if(record_ok)descriptor.fields.push_back(std::move(field));
                else{descriptor_ok=false;++swift.field_records_skipped;++swift.field_records_partial;}
            }
            ++swift.field_descriptors_used;
            if(descriptor_ok){descriptor_by_offset.emplace(cursor,descriptors.size());descriptors.push_back(std::move(descriptor));}
            else{++swift.field_descriptors_skipped;++swift.field_descriptors_partial;}
            cursor+=16+record_bytes;
        }
        return !swift.analysis_limited;
    }

    bool module_for_type(std::uint64_t type,std::string& module){
        std::set<std::uint64_t> visited;std::uint64_t current=type;
        for(std::uint32_t depth=0;depth<kMaxContextDepth;++depth){
            if(!visited.insert(current).second){partial("Swift context parent cycle detected");return false;}
            std::uint32_t flags=0;if(!read_abs(current,flags,"Swift context flags"))return false;
            const auto kind=flags&0x1fu;
            if(kind==0u)return string_from_pointer(current+8,false,module,"Swift module name");
            std::uint32_t parent_opaque=0;if(!read_abs(current+4,parent_opaque,"Swift context parent"))return false;
            if(!parent_opaque){partial("Swift context chain terminates before a module");return false;}
            if(parent_opaque&1u){partial("Swift indirect context parent is unresolved");return false;}
            if(!relative_target(current+4,1,false,current,"Swift context parent"))return false;
        }
        partial("Swift context-parent depth budget exceeded",true);return false;
    }

    static std::string context_kind(std::uint32_t kind){if(kind==16)return "class";if(kind==17)return "struct";if(kind==18)return "enum";return "context_"+std::to_string(kind);}

    bool parse_types(const MachOSection& section){
        if(section.size%4){partial("__swift5_types size is not a multiple of four");return false;}
        const auto count=section.size/4;if(count>kMaxTypes-swift.type_records_used){partial("Swift type-record budget exceeded",true);return false;}
        for(std::uint64_t i=0;i<count;++i){
            ++swift.type_records_used;
            const auto skip_partial=[&](bool unsupported=false){++swift.type_records_skipped;++swift.type_records_partial;if(unsupported)++swift.type_records_unsupported;};
            const auto record=section.offset+i*4;std::uint32_t opaque=0;if(!read_abs(record,opaque,"Swift type metadata record")){skip_partial();continue;}
            if((opaque&3u)!=0u){partial("Swift type metadata record is not a direct type descriptor");skip_partial(true);continue;}
            std::uint64_t target=0;if(!relative_target(record,3,false,target,"Swift type metadata record")){skip_partial();continue;}
            if(!type_targets.insert(target).second){partial("duplicate Swift type descriptor relation");skip_partial();continue;}
            std::uint32_t flags=0;if(!read_abs(target,flags,"Swift type context flags")){skip_partial();continue;}const auto kind=flags&0x1fu;
            if(kind<16u||kind>18u){partial("Swift type metadata record does not reference a class/struct/enum descriptor");skip_partial(true);continue;}
            MachOSwiftType type;type.type_descriptor_offset=target;type.kind=context_kind(kind);
            if(!module_for_type(target,type.module_name)||!string_from_pointer(target+8,false,type.type_name,"Swift type name")){skip_partial();continue;}
            std::uint64_t fields=0;if(!relative_target(target+16,0,true,fields,"Swift type fields")){skip_partial();continue;}
            if(!fields){++swift.type_records_skipped;continue;}
            const auto found=descriptor_by_offset.find(fields);if(found==descriptor_by_offset.end()){partial("Swift type fields pointer does not target a complete __swift5_fieldmd descriptor start");skip_partial();continue;}
            const auto& descriptor=descriptors[found->second];if(descriptor.fields.empty()){++swift.type_records_skipped;continue;}
            const bool descriptor_kind_matches=(kind==16u&&descriptor.kind==1u)||
                (kind==17u&&descriptor.kind==0u)||
                (kind==18u&&(descriptor.kind==2u||descriptor.kind==3u));
            if(!descriptor_kind_matches){partial("Swift type and field-descriptor kinds do not match");skip_partial();continue;}
            type.field_descriptor_offset=fields;copy_mangled(descriptor.mangled_type,type);type.fields=descriptor.fields;
            const auto relation=type.module_name+"\0"+type.type_name;if(!type_relations.insert(relation).second){partial("duplicate Swift module/type relation");skip_partial();continue;}
            swift.types.push_back(std::move(type));++swift.complete_type_closures;
        }
        return !swift.analysis_limited;
    }

};

}

void analyze_macho_swift(std::span<const std::uint8_t> data,std::uint64_t absolute_base,MachOSlice& out){SwiftParser(data,absolute_base,out).run();}

}
