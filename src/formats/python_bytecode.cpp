#include "prts/python_bytecode.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <optional>
#include <string_view>

namespace prts { namespace {

struct MagicRegistryRow {
    std::uint16_t value;
    int minor;
    const char* family;
    const char* tag;
    const char* path;
};

// Final release-family magic numbers from official CPython source.  A magic
// authenticates a bytecode *minor family*, not an exact patch release.
constexpr std::array<MagicRegistryRow,7> kMagicRegistry{{
    {3413,8, "3.8",  "v3.8.0",  "Lib/importlib/_bootstrap_external.py"},
    {3425,9, "3.9",  "v3.9.0",  "Lib/importlib/_bootstrap_external.py"},
    {3439,10,"3.10", "v3.10.0", "Lib/importlib/_bootstrap_external.py"},
    {3495,11,"3.11", "v3.11.0", "Lib/importlib/_bootstrap_external.py"},
    {3531,12,"3.12", "v3.12.0", "Lib/importlib/_bootstrap_external.py"},
    {3571,13,"3.13", "v3.13.0", "Lib/importlib/_bootstrap_external.py"},
    {3627,14,"3.14", "v3.14.0", "Include/internal/pycore_magic_number.h"},
}};

std::uint32_t u32(std::span<const std::uint8_t>d,std::size_t o){
    return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);
}
std::string hex_bytes(std::span<const std::uint8_t>d){
    static constexpr char h[]="0123456789abcdef";std::string out;out.reserve(d.size()*2);
    for(auto b:d){out.push_back(h[b>>4]);out.push_back(h[b&15]);}return out;
}
std::string csv(std::string_view s){
    std::string out="\"";for(char c:s){if(c=='\"')out+="\"\"";else if(c=='\r'||c=='\n')out+=' ';else out+=c;}out+='\"';return out;
}
std::string bounded_text(std::string_view s,std::size_t cap=4096){
    if(s.size()<=cap)return std::string(s);
    std::string out(s.substr(0,cap));out+="...[truncated]";return out;
}
bool ident_start(char c){auto u=static_cast<unsigned char>(c);return std::isalpha(u)||c=='_';}
bool ident_char(char c){auto u=static_cast<unsigned char>(c);return std::isalnum(u)||c=='_';}
bool token_present(std::string_view text,std::string_view id){
    if(id.empty())return false;
    std::size_t p=0;while((p=text.find(id,p))!=std::string_view::npos){
        const bool left=p==0||!ident_char(text[p-1]);const auto e=p+id.size();const bool right=e==text.size()||!ident_char(text[e]);
        if(left&&right)return true;
        p=e;
    }return false;
}
std::string trim_copy(std::string_view s){std::size_t a=0,b=s.size();while(a<b&&std::isspace(static_cast<unsigned char>(s[a])))++a;while(b>a&&std::isspace(static_cast<unsigned char>(s[b-1])))--b;return std::string(s.substr(a,b-a));}

std::vector<std::uint8_t> python_code_mask(std::string_view src){
    std::vector<std::uint8_t> code(src.size(),1);std::size_t i=0;
    while(i<src.size()){
        if(src[i]=='#'){
            auto e=src.find('\n',i);if(e==std::string_view::npos)e=src.size();std::fill(code.begin()+static_cast<std::ptrdiff_t>(i),code.begin()+static_cast<std::ptrdiff_t>(e),0);i=e;continue;
        }
        if(src[i]!='\''&&src[i]!='\"'){++i;continue;}
        const char q=src[i];const bool triple=i+2<src.size()&&src[i+1]==q&&src[i+2]==q;auto a=i;i+=triple?3:1;bool esc=false;
        while(i<src.size()){
            char c=src[i];if(esc){esc=false;++i;continue;}if(c=='\\'){esc=true;++i;continue;}
            if(triple){if(i+2<src.size()&&src[i]==q&&src[i+1]==q&&src[i+2]==q){i+=3;break;}++i;continue;}
            if(c==q){++i;break;}if(c=='\n')break;++i;
        }
        std::fill(code.begin()+static_cast<std::ptrdiff_t>(a),code.begin()+static_cast<std::ptrdiff_t>(i),0);
    }return code;
}
std::size_t find_code_token(std::string_view src,std::span<const std::uint8_t>mask,std::string_view token,std::size_t start=0){
    for(auto p=src.find(token,start);p!=std::string_view::npos;p=src.find(token,p+1)){
        bool ok=p+token.size()<=mask.size();for(std::size_t j=0;ok&&j<token.size();++j)ok=mask[p+j]!=0;if(ok)return p;
    }return std::string_view::npos;
}

struct Binding {std::string name;std::size_t value_offset=0,value_size=0;};
std::optional<std::string> lhs_identifier(std::string_view line){
    std::size_t p=0;while(p<line.size()&&std::isspace(static_cast<unsigned char>(line[p])))++p;
    if(p>=line.size()||!ident_start(line[p]))return{};
    auto a=p++;while(p<line.size()&&ident_char(line[p]))++p;auto id=line.substr(a,p-a);while(p<line.size()&&std::isspace(static_cast<unsigned char>(line[p])))++p;
    if(p>=line.size()||line[p]!='=')return{};
    return std::string(id);
}
std::vector<Binding> embedded_bytes_bindings(std::string_view src,std::span<const std::uint8_t>mask){
    std::vector<Binding> out;std::size_t line_start=0;
    while(line_start<src.size()){
        auto nl=src.find('\n',line_start);if(nl==std::string_view::npos)nl=src.size();auto line=src.substr(line_start,nl-line_start);std::size_t first=0;while(first<line.size()&&std::isspace(static_cast<unsigned char>(line[first])))++first;const bool code_line=line_start+first<mask.size()&&mask[line_start+first];auto id=code_line?lhs_identifier(line):std::optional<std::string>{};
        if(id){
            auto eq=line.find('=');std::size_t p=eq+1;while(p<line.size()&&std::isspace(static_cast<unsigned char>(line[p])))++p;
            if(p+1<line.size()&&line[p]=='b'&&(line[p+1]=='\''||line[p+1]=='\"')){
                const char q=line[p+1];auto start=p;std::size_t z=p+2;bool esc=false;
                for(;z<line.size();++z){char c=line[z];if(esc){esc=false;continue;}if(c=='\\'){esc=true;continue;}if(c==q){++z;break;}}
                if(z<=line.size()&&z>p+2)out.push_back({*id,line_start+start,z-start});
            }
        }
        line_start=nl==src.size()?src.size():nl+1;
    }return out;
}
std::vector<std::string> source_dependent_bindings(std::string_view src,std::span<const std::uint8_t>mask){
    std::vector<std::string> out;std::size_t line_start=0;
    while(line_start<src.size()){
        auto nl=src.find('\n',line_start);if(nl==std::string_view::npos)nl=src.size();auto line=src.substr(line_start,nl-line_start);
        const auto a=find_code_token(src,mask,"inspect.getsource(",line_start),b=find_code_token(src,mask,"inspect.getsourcefile(",line_start);
        if((a<nl||b<nl)){if(auto id=lhs_identifier(line))out.push_back(*id);}
        line_start=nl==src.size()?src.size():nl+1;
    }return out;
}
std::string call_argument(std::string_view src,std::size_t open,std::size_t&end){
    if(open>=src.size()||src[open]!='(')return{};
    std::size_t depth=1,a=open+1;char quote=0;bool esc=false;
    for(std::size_t p=a;p<src.size()&&p-a<65536;++p){char c=src[p];if(quote){if(esc){esc=false;continue;}if(c=='\\'){esc=true;continue;}if(c==quote)quote=0;continue;}if(c=='\''||c=='\"'){quote=c;continue;}if(c=='(')++depth;else if(c==')'&&--depth==0){end=p+1;return trim_copy(src.substr(a,p-a));}}
    return{};
}
std::string transform_name(std::string_view expr){auto s=trim_copy(expr);std::size_t p=0;if(p<s.size()&&ident_start(s[p])){++p;while(p<s.size()&&ident_char(s[p]))++p;if(p<s.size()&&s[p]=='(')return s.substr(0,p);}return{};}
std::string version_hint(std::string_view src){
    for(int minor=8;minor<=14;++minor){auto family="3."+std::to_string(minor);if(src.find("python"+family)!=std::string_view::npos||src.find("python "+family)!=std::string_view::npos||src.find("Python "+family)!=std::string_view::npos)return family;}
    return{};
}
bool version_conflicts(std::string_view a,std::string_view b){return !a.empty()&&!b.empty()&&a!=b;}

} // namespace

CPythonPycMagicInfo identify_cpython_pyc_magic(std::span<const std::uint8_t>d){
    CPythonPycMagicInfo out;
    if(d.size()<4)return out;
    out.bytes={d[0],d[1],d[2],d[3]};
    if(d[2]!=0x0d||d[3]!=0x0a)return out;
    out.magic_number=std::uint16_t(d[0])|(std::uint16_t(d[1])<<8);
    for(const auto&r:kMagicRegistry)if(r.value==out.magic_number){out.known=true;out.python_minor=r.minor;out.version_family=r.family;out.provenance_tag=r.tag;out.provenance_path=r.path;break;}
    return out;
}

PythonBytecodeInfo detect_python_bytecode(std::span<const std::uint8_t>d,bool filename_hint){
    PythonBytecodeInfo out;out.filename_hint=filename_hint;out.file_size=d.size();out.magic=identify_cpython_pyc_magic(d);out.candidate=filename_hint||out.magic.known;
    if(!out.candidate)return out;
    if(d.size()<4){out.error="truncated CPython pyc magic";out.error_offset=d.size();return out;}
    if(!out.magic.known){out.error="unknown or unsupported CPython pyc magic; filename alone does not authenticate bytecode";return out;}
    if(d.size()<16){out.error="truncated CPython pyc header: PEP 552-era header requires 16 bytes";out.error_offset=d.size();return out;}
    out.flags=u32(d,4);if(out.flags&~3u){out.error="invalid CPython pyc flags: only the first two PEP 552 bits are defined";out.error_offset=4;return out;}
    if(out.flags&1u){out.hash_checked=(out.flags&2u)!=0;out.header_kind=out.hash_checked?"PEP552_HASH_CHECKED":"PEP552_HASH_UNCHECKED";std::copy_n(d.begin()+8,8,out.source_hash.begin());}
    else{out.header_kind=(out.flags&2u)?"TIMESTAMP_NONCANONICAL_CHECK_SOURCE_BIT":"TIMESTAMP";out.timestamp=u32(d,8);out.source_size=u32(d,12);}
    out.marshal_offset=16;auto payload=d.subspan(16);const int version=300+out.magic.python_minor;
    out.marshal=semantic_hash_python_marshal(payload,version);if(!out.marshal.valid){out.error="pyc header authenticated but marshal/code-object validation failed: "+out.marshal.error;out.error_offset=16+out.marshal.error_offset;return out;}
    out.root=inspect_python_marshal_root_code(payload,version);if(!out.root.valid){out.error="pyc marshal root parsed but root code-object inspection failed: "+out.root.error;out.error_offset=16+out.root.error_offset;return out;}
    out.opcode_inventory_complete=true;
    for(const auto&r:out.marshal.code_ranges){
        if(r.offset>payload.size()||r.size>payload.size()-r.offset||(r.size&1u)){out.opcode_inventory_complete=false;continue;}
        for(std::uint64_t p=0;p<r.size;p+=2){++out.opcode_counts[payload[static_cast<std::size_t>(r.offset+p)]];++out.code_units;}
    }
    out.valid=true;return out;
}

Finding python_bytecode_finding(const PythonBytecodeInfo&i){
    Finding f;f.kind="bytecode";f.family="CPython bytecode";f.variant=i.magic.known?i.magic.version_family+" .pyc":"unvalidated .pyc";
    if(!i.valid){f.state="FAILED";if(!i.error.empty())f.negative_evidence.push_back(i.error);f.fields["filename_hint"]=i.filename_hint?"true":"false";if(i.magic.known){f.fields["version_family"]=i.magic.version_family;f.fields["magic_authentication"]="OFFICIAL_MAGIC_FAMILY_MATCH";}return f;}
    f.state="CONFIRMED";f.evidence={"official CPython release-family magic matched exactly","PEP 552-era 16-byte header geometry and defined flag bits validated","bytes after the header parse completely as exactly one top-level marshal code object under the authenticated minor-family layout","root co_code/co_consts/co_names structure validated without executing marshal data"};
    f.fields["version_family"]=i.magic.version_family;f.fields["version_authentication"]="MAGIC_MINOR_FAMILY_AUTHENTICATED";f.fields["patch_version_state"]="AMBIGUOUS_WITHIN_MINOR_FAMILY";
    f.fields["pyc_magic"]=hex_bytes(std::span<const std::uint8_t>(i.magic.bytes));f.fields["pyc_magic_decimal"]=std::to_string(i.magic.magic_number);f.fields["magic_provenance"]="CPython "+i.magic.provenance_tag+" "+i.magic.provenance_path;f.fields["header_kind"]=i.header_kind;f.fields["flags"]=std::to_string(i.flags);f.fields["marshal_offset"]=std::to_string(i.marshal_offset);f.fields["marshal_valid"]="true";f.fields["top_level_code_object_valid"]="true";f.fields["marshal_objects"]=std::to_string(i.marshal.object_count);f.fields["code_objects"]=std::to_string(i.marshal.code_object_count);f.fields["root_names"]=std::to_string(i.root.names.size());f.fields["root_constants"]=std::to_string(i.root.constants.size());f.fields["root_code_bytes"]=std::to_string(i.root.code.size());f.fields["bytecode_inventory_complete"]=i.opcode_inventory_complete?"true":"false";f.fields["code_units"]=std::to_string(i.code_units);std::uint64_t unique_opcodes=0;for(auto n:i.opcode_counts)if(n)++unique_opcodes;f.fields["unique_opcodes"]=std::to_string(unique_opcodes);f.fields["source_decompilation_authoritative"]="false";f.fields["arbitrary_marshal_execution"]="false";
    if(i.flags&1u){f.fields["source_hash"]=hex_bytes(std::span<const std::uint8_t>(i.source_hash));f.fields["hash_check_mode"]=i.hash_checked?"checked":"unchecked";}else{f.fields["timestamp"]=std::to_string(i.timestamp);f.fields["source_size"]=std::to_string(i.source_size);if(i.flags&2u)f.negative_evidence.push_back("check_source flag is set without hash-based mode; CPython's classifier tolerates this but its canonical writers do not emit this combination");}
    f.ranges.push_back(file_offset_range(0,16,"CPython .pyc header"));f.ranges.push_back(file_offset_range(16,i.file_size>=16?i.file_size-16:0,"CPython marshal payload"));
    for(std::size_t n=0;n<std::min<std::size_t>(i.marshal.code_ranges.size(),128);++n){const auto&r=i.marshal.code_ranges[n];f.ranges.push_back(file_offset_range(16+r.offset,r.size,"serialized co_code: "+(r.qualname.empty()?r.name:r.qualname)));}
    f.suggested_actions={"use the emitted code-object/name/constant map and a CPython "+i.magic.version_family+"-compatible disassembler/decompiler for selected code objects","treat decompiled source as a derived aid; serialized code-object structure and authenticated bytecode family remain the authoritative evidence"};return f;
}

PythonBytecodeExtractResult extract_python_bytecode_maps(const PythonBytecodeInfo&i,const std::filesystem::path&code_csv){
    PythonBytecodeExtractResult out;if(!i.valid){out.error="CPython bytecode is not validated";return out;}out.code_objects_csv=code_csv;out.root_symbols_csv=code_csv.parent_path()/"root-symbols.csv";out.opcode_inventory_csv=code_csv.parent_path()/"opcode-inventory.csv";
    std::ofstream co(out.code_objects_csv,std::ios::binary|std::ios::trunc);if(!co){out.error="cannot create CPython code-object map";return out;}co<<"index,file_offset,marshal_offset,size,name,qualname,filename,first_line\n";
    for(std::size_t n=0;n<i.marshal.code_ranges.size();++n){const auto&r=i.marshal.code_ranges[n];co<<n<<','<<(16+r.offset)<<','<<r.offset<<','<<r.size<<','<<csv(bounded_text(r.name))<<','<<csv(bounded_text(r.qualname))<<','<<csv(bounded_text(r.filename))<<','<<r.first_line<<"\n";++out.rows;}if(!co){out.error="CPython code-object map write failed";return out;}
    std::ofstream sy(out.root_symbols_csv,std::ios::binary|std::ios::trunc);if(!sy){out.error="cannot create CPython root-symbol map";return out;}sy<<"kind,index,value\n";
    for(std::size_t n=0;n<i.root.names.size();++n){sy<<"name,"<<n<<','<<csv(bounded_text(i.root.names[n]))<<"\n";++out.rows;}
    for(std::size_t n=0;n<i.root.constants.size();++n){const auto&v=i.root.constants[n];sy<<"constant,"<<n<<',';if(v.kind==PythonMarshalScalarKind::Integer)sy<<csv(std::to_string(v.integer));else if(v.kind==PythonMarshalScalarKind::String)sy<<csv(bounded_text(v.text));else sy<<csv("<non-scalar-or-nested-code>");sy<<"\n";++out.rows;}if(!sy){out.error="CPython root-symbol map write failed";return out;}
    std::ofstream op(out.opcode_inventory_csv,std::ios::binary|std::ios::trunc);if(!op){out.error="cannot create CPython opcode inventory";return out;}op<<"opcode,count,semantic_name_state\n";for(std::size_t n=0;n<i.opcode_counts.size();++n)if(i.opcode_counts[n]){op<<n<<','<<i.opcode_counts[n]<<",UNAUTHENTICATED_NUMERIC_ONLY\n";++out.rows;}if(!op){out.error="CPython opcode inventory write failed";return out;}out.success=true;return out;
}

CPythonMarshalLoaderInfo inspect_cpython_marshal_loader_source(std::span<const std::uint8_t>d){
    CPythonMarshalLoaderInfo out;
    if(d.empty()||d.size()>16ull*1024*1024||std::find(d.begin(),d.end(),std::uint8_t(0))!=d.end())return out;
    std::string src(reinterpret_cast<const char*>(d.data()),d.size());auto code=python_code_mask(src);std::size_t p=find_code_token(src,code,"marshal.loads(");std::size_t open=std::string::npos;
    if(p!=std::string::npos){out.loader_api="marshal.loads";open=p+std::string("marshal.loads").size();}
    else if(auto imp=find_code_token(src,code,"from marshal import loads");imp!=std::string::npos){p=find_code_token(src,code,"loads(",imp+std::string_view("from marshal import loads").size());if(p!=std::string::npos){out.loader_api="marshal.loads (imported loads)";open=p+5;}}
    if(p==std::string::npos||open==std::string::npos)return out;
    out.candidate=true;out.loader_confirmed=true;out.loader_offset=p;
    std::size_t end=0;out.payload_expression=call_argument(src,open,end);
    if(out.payload_expression.empty())return out;
    out.loader_size=end>p?end-p:out.loader_api.size();out.transform_callable=transform_name(out.payload_expression);out.runtime_version_hint=version_hint(src);
    auto bindings=embedded_bytes_bindings(src,code);for(const auto&b:bindings)if(token_present(out.payload_expression,b.name)){out.payload_binding=b.name;out.payload_source_offset=b.value_offset;out.payload_source_size=b.value_size;out.payload_source_kind=(trim_copy(out.payload_expression)==b.name)?"EMBEDDED_BYTES_LITERAL":"TRANSFORMED_EMBEDDED_BYTES_LITERAL";out.payload_relation_confirmed=true;break;}
    auto deps=source_dependent_bindings(src,code);for(const auto&id:deps)if(token_present(out.payload_expression,id)){out.source_integrity_dependency=true;out.source_key_binding=id;break;}
    // Direct nesting is strong enough to state that the deserialized object flows to exec.
    auto before=src.rfind("exec(",p);if(before!=std::string::npos&&before<code.size()&&code[before]){auto between=src.substr(before+5,p-(before+5));if(std::all_of(between.begin(),between.end(),[](unsigned char c){return std::isspace(c);}))out.exec_closure=true;}
    CPythonRuntimePayloadRelationInput ri;ri.payload_present=out.payload_relation_confirmed;ri.payload_loader_confirmed=out.loader_confirmed;ri.payload_version_family=out.runtime_version_hint;ri.unknown_custom_semantics=out.payload_source_kind=="TRANSFORMED_EMBEDDED_BYTES_LITERAL";out.runtime_relation_state=assess_cpython_runtime_payload_relation(ri).state;return out;
}

Finding cpython_marshal_loader_finding(const CPythonMarshalLoaderInfo&i){
    Finding f;f.kind="bytecode_loader";f.family="CPython marshal ingress";f.variant=i.loader_api;if(!i.loader_confirmed){f.state="FAILED";return f;}f.state=i.payload_relation_confirmed?"CONFIRMED":"LIKELY";
    f.evidence.push_back("Python source contains an explicit "+i.loader_api+" deserialization call");if(i.payload_relation_confirmed)f.evidence.push_back("the marshal argument has a bounded static data-flow relation to a local embedded bytes literal"+(i.transform_callable.empty()?std::string():" through transform "+i.transform_callable));if(i.exec_closure)f.evidence.push_back("the marshal.loads result is directly nested into exec, confirming loader-to-execution closure without executing it");if(i.source_integrity_dependency)f.evidence.push_back("the transformation input depends on inspect.getsource/getsourcefile-derived source text, making source mutation an explicit payload-decoding dependency");
    if(!i.payload_relation_confirmed)f.negative_evidence.push_back("marshal.loads is confirmed, but a bounded static payload source was not closed");
    f.negative_evidence.push_back("no runtime patch, anti-tamper NOP, arbitrary marshal execution, memory dump, or custom-opcode interpretation was performed");
    f.fields["loader_api"]=i.loader_api;f.fields["payload_relation_state"]=i.payload_relation_confirmed?"SOURCE_TO_MARSHAL_LOADS_CONFIRMED":"PAYLOAD_SOURCE_UNRESOLVED";f.fields["payload_source_kind"]=i.payload_source_kind.empty()?"UNRESOLVED":i.payload_source_kind;f.fields["payload_binding"]=i.payload_binding;f.fields["payload_expression"]=bounded_text(i.payload_expression,512);f.fields["transform_callable"]=i.transform_callable;f.fields["exec_closure"]=i.exec_closure?"true":"false";f.fields["source_integrity_dependency"]=i.source_integrity_dependency?"true":"false";f.fields["source_key_binding"]=i.source_key_binding;f.fields["runtime_version_hint"]=i.runtime_version_hint.empty()?"UNAUTHENTICATED":i.runtime_version_hint;f.fields["runtime_payload_relation"]=i.runtime_relation_state;f.fields["automatic_runtime_patch"]="false";f.fields["automatic_marshal_execution"]="false";
    f.ranges.push_back(file_offset_range(i.loader_offset,i.loader_size,"marshal loader expression"));if(i.payload_source_size)f.ranges.push_back(file_offset_range(i.payload_source_offset,i.payload_source_size,"embedded bytes payload source"));
    f.suggested_actions={"observe/capture the byte sequence immediately before marshal.loads under an explicitly chosen matching CPython runtime when static transforms do not expose it completely","authenticate runtime version and any modified opcode semantics before interpreting captured code objects; do not infer a runtime/payload relation from directory proximity"};return f;
}

CPythonRuntimePayloadRelation assess_cpython_runtime_payload_relation(const CPythonRuntimePayloadRelationInput&i){
    CPythonRuntimePayloadRelation out;
    if(!i.payload_present||!i.payload_loader_confirmed){out.state=i.runtime_present?"RUNTIME_WITHOUT_BOUND_MARSHAL_PAYLOAD":"NO_BOUND_MARSHAL_PAYLOAD";out.negative_evidence.push_back("no explicit loader-bound marshal payload is available");return out;}
    if(!i.runtime_present){out.state="REQUIRES_NATIVE_RUNTIME_BYTECODE_OBSERVATION";out.evidence.push_back("marshal payload ingress is present but no authenticated runtime is bound to it");return out;}
    if(!i.runtime_authenticated){out.state="RUNTIME_UNAUTHENTICATED";out.negative_evidence.push_back("a runtime candidate exists but its CPython identity/version is not authenticated");return out;}
    if(version_conflicts(i.runtime_version_family,i.payload_version_family)){out.state="VERSION_CONFLICT";out.negative_evidence.push_back("authenticated runtime family conflicts with the payload/loader version family");return out;}
    if(!i.explicit_runtime_payload_binding){out.state="UNBOUND_RUNTIME_PAYLOAD";out.negative_evidence.push_back("runtime and payload have no explicit application relation; same-directory/name proximity is not evidence");return out;}
    if(i.unknown_custom_semantics){out.state="REQUIRES_NATIVE_RUNTIME_BYTECODE_OBSERVATION";out.evidence.push_back("runtime and payload are explicitly related, but custom/unknown semantics prevent stock-bytecode interpretation");return out;}
    out.closed=true;out.state="BOUNDED_RUNTIME_PAYLOAD_RELATION";out.evidence.push_back("authenticated runtime and loader-bound payload have an explicit relation with no version conflict");return out;
}

} // namespace prts
