#include "prts/wasm.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace prts { namespace {
struct Reader {
    std::span<const std::uint8_t> d;
    std::size_t p=0,end=0;
    WasmInfo* out=nullptr;
    Reader(std::span<const std::uint8_t>x,std::size_t a,std::size_t b,WasmInfo*o):d(x),p(a),end(std::min(b,x.size())),out(o){}
    bool fail(std::string s){if(out&&out->error.empty()){out->error=std::move(s);out->error_offset=p;}return false;}
    bool need(std::size_t n){return n<=end-std::min(p,end)||fail("WebAssembly structure truncated");}
    bool byte(std::uint8_t&v){if(!need(1))return false;v=d[p++];return true;}
    bool u32(std::uint32_t&v){v=0;for(unsigned i=0;i<5;i++){std::uint8_t b=0;if(!byte(b))return false;if(i==4&&(b&0xf0))return fail("u32 LEB128 overflow");v|=std::uint32_t(b&0x7f)<<(7*i);if(!(b&0x80))return true;}return fail("u32 LEB128 too long");}
    bool u64(std::uint64_t&v){v=0;for(unsigned i=0;i<10;i++){std::uint8_t b=0;if(!byte(b))return false;if(i==9&&(b&0xfe))return fail("u64 LEB128 overflow");v|=std::uint64_t(b&0x7f)<<(7*i);if(!(b&0x80))return true;}return fail("u64 LEB128 too long");}
    bool s64(std::int64_t&v,unsigned bits=64){std::uint64_t x=0;unsigned shift=0;std::uint8_t b=0;unsigned max=(bits+6)/7;for(unsigned i=0;i<max;i++){if(!byte(b))return false;auto payload=std::uint64_t(b&0x7f);if(shift<64)x|=payload<<shift;shift+=7;if(!(b&0x80)){if(shift<64&&(b&0x40))x|=(~0ull)<<shift;v=static_cast<std::int64_t>(x);return true;}}return fail("signed LEB128 too long");}
};

bool utf8_ok(std::string_view s){
    for(std::size_t i=0;i<s.size();){unsigned c=static_cast<unsigned char>(s[i]);if(c<0x80){++i;continue;}unsigned n=0,min=0;if((c&0xe0)==0xc0){n=1;min=0x80;c&=0x1f;}else if((c&0xf0)==0xe0){n=2;min=0x800;c&=0x0f;}else if((c&0xf8)==0xf0){n=3;min=0x10000;c&=0x07;}else return false;if(i+n>=s.size())return false;unsigned cp=c;for(unsigned j=0;j<n;j++){unsigned q=static_cast<unsigned char>(s[++i]);if((q&0xc0)!=0x80)return false;cp=(cp<<6)|(q&0x3f);}++i;if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;}return true;
}
bool name(Reader&r,std::string&out){std::uint32_t n=0;if(!r.u32(n))return false;if(n>r.end-r.p)return r.fail("WebAssembly name length out of bounds");out.assign(reinterpret_cast<const char*>(r.d.data()+r.p),n);r.p+=n;if(!utf8_ok(out))return r.fail("WebAssembly name is not valid UTF-8");return true;}
std::string join_types(const std::vector<std::string>&v){std::string o;for(std::size_t i=0;i<v.size();++i){if(i)o+=",";o+=v[i];}return o;}
std::string signature(const std::vector<std::string>&p,const std::vector<std::string>&q){return "("+join_types(p)+")->"+(q.empty()?"void":q.size()==1?q[0]:"("+join_types(q)+")");}

bool valtype(Reader&r,std::string&out){std::uint8_t b=0;if(!r.byte(b))return false;switch(b){case 0x7f:out="i32";return true;case 0x7e:out="i64";return true;case 0x7d:out="f32";return true;case 0x7c:out="f64";return true;case 0x7b:out="v128";return true;case 0x70:out="funcref";return true;case 0x6f:out="externref";return true;case 0x6e:out="anyref";return true;case 0x6d:out="eqref";return true;case 0x6c:out="i31ref";return true;case 0x6b:out="structref";return true;case 0x6a:out="arrayref";return true;case 0x69:out="exnref";return true;case 0x71:out="noneref";return true;case 0x72:out="noexternref";return true;case 0x73:out="nofuncref";return true;case 0x74:out="noexnref";return true;case 0x64:case 0x63:{std::int64_t ht=0;if(!r.s64(ht,33))return false;out=std::string(b==0x63?"ref null ":"ref ")+std::to_string(ht);return true;}default:{std::ostringstream o;o<<"unsupported WebAssembly value type 0x"<<std::hex<<unsigned(b);return r.fail(o.str());}}
}
bool vec_types(Reader&r,std::vector<std::string>&v){std::uint32_t n=0;if(!r.u32(n))return false;if(n>1000000)return r.fail("WebAssembly type vector count unreasonable");v.reserve(n);for(std::uint32_t i=0;i<n;i++){std::string t;if(!valtype(r,t))return false;v.push_back(std::move(t));}return true;}

bool limits(Reader&r){std::uint8_t flags=0;if(!r.byte(flags))return false;if(flags!=0x00&&flags!=0x01&&flags!=0x04&&flags!=0x05)return r.fail("unsupported WebAssembly limits flags");std::uint64_t a=0,b=0;if(!r.u64(a))return false;if(flags&1u)if(!r.u64(b))return false;(void)a;(void)b;return true;}
bool table_type(Reader&r){std::string t;if(!valtype(r,t))return false;return limits(r);}
bool memory_type(Reader&r){return limits(r);}
bool global_type(Reader&r){std::string t;std::uint8_t mut=0;if(!valtype(r,t)||!r.byte(mut))return false;if(mut>1)return r.fail("invalid WebAssembly global mutability");return true;}
bool tag_type(Reader&r){std::uint8_t attr=0;std::uint32_t ti=0;if(!r.byte(attr)||!r.u32(ti))return false;if(attr!=0)return r.fail("unsupported WebAssembly tag attribute");return true;}

bool parse_type_section(Reader&r,WasmInfo&o){
    std::uint32_t n=0;if(!r.u32(n))return false;if(n>1000000)return r.fail("WebAssembly type count unreasonable");o.types.reserve(n);
    for(std::uint32_t i=0;i<n;i++){
        auto start=r.p;std::uint8_t form=0;if(!r.byte(form))return false;
        if(form!=0x60){o.type_parse_complete=false;std::ostringstream s;s<<"type section uses GC/recursive or unsupported type form 0x"<<std::hex<<unsigned(form)<<" at 0x"<<start;o.anomalies.push_back(s.str());r.p=r.end;return true;}
        WasmFuncType t;t.index=i;if(!vec_types(r,t.params)||!vec_types(r,t.results))return false;t.signature=signature(t.params,t.results);o.types.push_back(std::move(t));
    }
    return true;
}
bool parse_import_section(Reader&r,WasmInfo&o,std::vector<std::uint32_t>&import_type){
    std::uint32_t n=0;if(!r.u32(n))return false;if(n>1000000)return r.fail("WebAssembly import count unreasonable");
    std::array<std::uint32_t,5> idx{};
    for(std::uint32_t i=0;i<n;i++){WasmImport x;if(!name(r,x.module)||!name(r,x.name))return false;std::uint8_t k=0;if(!r.byte(k)||k>4)return r.fail("invalid WebAssembly import kind");x.index=idx[k]++;if(k==0){x.kind="function";if(!r.u32(x.type_index))return false;import_type.push_back(x.type_index);++o.imported_function_count;}else if(k==1){x.kind="table";if(!table_type(r))return false;}else if(k==2){x.kind="memory";if(!memory_type(r))return false;}else if(k==3){x.kind="global";if(!global_type(r))return false;}else{x.kind="tag";if(!tag_type(r))return false;}o.imports.push_back(std::move(x));}
    return true;
}
bool parse_function_section(Reader&r,WasmInfo&o,std::vector<std::uint32_t>&defined_type){std::uint32_t n=0;if(!r.u32(n))return false;if(n>10000000)return r.fail("WebAssembly function count unreasonable");defined_type.reserve(n);for(std::uint32_t i=0;i<n;i++){std::uint32_t t=0;if(!r.u32(t))return false;defined_type.push_back(t);}o.defined_function_count=n;return true;}
std::string kind_name(std::uint8_t k){static const char* a[]={"function","table","memory","global","tag"};return k<5?a[k]:"unknown";}
bool parse_export_section(Reader&r,WasmInfo&o){std::uint32_t n=0;if(!r.u32(n))return false;if(n>1000000)return r.fail("WebAssembly export count unreasonable");std::set<std::string>names;for(std::uint32_t i=0;i<n;i++){WasmExport x;if(!name(r,x.name))return false;std::uint8_t k=0;if(!r.byte(k)||k>4)return r.fail("invalid WebAssembly export kind");if(!r.u32(x.index))return false;if(!names.insert(x.name).second)return r.fail("duplicate WebAssembly export name");x.kind=kind_name(k);o.exports.push_back(std::move(x));}return true;}
bool parse_start_section(Reader&r,WasmInfo&o,std::uint64_t section_off){o.has_start=true;o.start_section_offset=section_off;o.start_index_offset=r.p;const auto before=r.p;if(!r.u32(o.start_function_index))return false;o.start_index_size=r.p-before;return true;}

bool parse_code_section(Reader&r,WasmInfo&o,std::vector<std::pair<std::uint64_t,std::uint64_t>>&bodies){
    std::uint32_t n=0;if(!r.u32(n))return false;if(n>10000000)return r.fail("WebAssembly code count unreasonable");bodies.reserve(n);
    for(std::uint32_t i=0;i<n;i++){std::uint32_t sz=0;if(!r.u32(sz))return false;if(sz>r.end-r.p)return r.fail("WebAssembly function body exceeds code section");auto body=r.p,bodyend=r.p+sz;if(!sz)return r.fail("empty WebAssembly function body");Reader b(r.d,body,bodyend,&o);std::uint32_t locals=0;if(!b.u32(locals))return false;if(locals>1000000)return b.fail("WebAssembly local declaration group count unreasonable");for(std::uint32_t j=0;j<locals;j++){std::uint32_t cnt=0;std::string t;if(!b.u32(cnt)||!valtype(b,t))return false;}if(r.d[bodyend-1]!=0x0b){b.p=bodyend-1;return b.fail("WebAssembly function body missing final end opcode");}bodies.emplace_back(body,sz);r.p=bodyend;}
    return true;
}

bool init_expr(Reader&r,std::optional<std::int64_t>&known){known.reset();bool first=true;while(r.p<r.end){std::uint8_t op=0;if(!r.byte(op))return false;if(op==0x0b)return true;if(op==0x41){std::int64_t v=0;if(!r.s64(v,32))return false;if(first)known=v;}else if(op==0x42){std::int64_t v=0;if(!r.s64(v,64))return false;}else if(op==0x43){if(!r.need(4))return false;r.p+=4;}else if(op==0x44){if(!r.need(8))return false;r.p+=8;}else if(op==0x23||op==0xd2){std::uint32_t x=0;if(!r.u32(x))return false;}else if(op==0xd0){std::int64_t ht=0;if(!r.s64(ht,33))return false;}else return r.fail("unsupported WebAssembly const-expression opcode");first=false;}return r.fail("WebAssembly const expression missing end");}
void collect_strings(std::span<const std::uint8_t>d,std::vector<std::string>&out,std::size_t cap=512){for(std::size_t p=0;p<d.size()&&out.size()<cap;){while(p<d.size()&&(d[p]<0x20||d[p]>0x7e))++p;auto s=p;while(p<d.size()&&d[p]>=0x20&&d[p]<=0x7e&&p-s<4096)++p;if(p-s>=4){std::string x(reinterpret_cast<const char*>(d.data()+s),p-s);if(std::find(out.begin(),out.end(),x)==out.end())out.push_back(std::move(x));}if(p==s)++p;}}
bool parse_data_section(Reader&r,WasmInfo&o){std::uint32_t n=0;if(!r.u32(n))return false;if(n>1000000)return r.fail("WebAssembly data segment count unreasonable");for(std::uint32_t i=0;i<n;i++){WasmDataSegment s;s.index=i;std::uint32_t mode=0;if(!r.u32(mode))return false;if(mode>2){o.data_parse_complete=false;o.anomalies.push_back("data section uses unsupported future segment mode");r.p=r.end;return true;}std::optional<std::int64_t> off;if(mode==0){if(!init_expr(r,off))return false;}else if(mode==1)s.passive=true;else{if(!r.u32(s.memory_index)||!init_expr(r,off))return false;}std::uint32_t sz=0;if(!r.u32(sz))return false;if(sz>r.end-r.p)return r.fail("WebAssembly data payload out of bounds");s.data_offset=r.p;s.size=sz;if(off){s.offset_known=true;s.offset=*off;}collect_strings(r.d.subspan(r.p,sz),o.string_hints);r.p+=sz;o.data_segments.push_back(std::move(s));}return true;}

void custom_clues(std::span<const std::uint8_t>d,const std::string&n,WasmInfo&o){if(n.rfind(".debug_",0)==0||n=="external_debug_info")o.dwarf_sections.push_back(n);if(n==".debug_str"||n=="sourceMappingURL"||n=="producers")collect_strings(d,o.string_hints,512);}
void parse_name_custom(std::span<const std::uint8_t>d,std::size_t a,std::size_t e,WasmInfo&o,std::map<std::uint32_t,std::string>&fnames){Reader r(d,a,e,nullptr);while(r.p<r.end){std::uint8_t id=0;if(!r.byte(id)){o.name_parse_complete=false;return;}std::uint32_t sz=0;if(!r.u32(sz)||sz>r.end-r.p){o.name_parse_complete=false;return;}auto se=r.p+sz;if(id==1){Reader s(d,r.p,se,nullptr);std::uint32_t n=0;if(!s.u32(n)||n>10000000){o.name_parse_complete=false;r.p=se;continue;}for(std::uint32_t i=0;i<n;i++){std::uint32_t idx=0;std::string nm;if(!s.u32(idx)||!name(s,nm)){o.name_parse_complete=false;break;}fnames[idx]=std::move(nm);}if(s.p!=s.end)o.name_parse_complete=false;}r.p=se;}}

bool user_name(std::string_view n){if(n.empty())return false;if(n.rfind("__",0)==0||n.rfind("_start",0)==0||n.rfind("emscripten_",0)==0||n.rfind("dynCall_",0)==0)return false;return true;}
std::string csvq(const std::string&s){std::string r="\"";for(char c:s){if(c=='\"')r+="\"\"";else r+=c;}return r+'\"';}
std::string exports_join(const std::vector<std::string>&v){std::string x;for(const auto&s:v){if(!x.empty())x+='|';x+=s;}return x;}
} // namespace

WasmInfo parse_wasm(std::span<const std::uint8_t>d){WasmInfo o;if(d.size()<4||d[0]!=0||d[1]!=0x61||d[2]!=0x73||d[3]!=0x6d)return o;o.candidate=true;if(d.size()<8){o.error="WebAssembly magic present but version is truncated";o.error_offset=4;return o;}o.version=std::uint32_t(d[4])|(std::uint32_t(d[5])<<8)|(std::uint32_t(d[6])<<16)|(std::uint32_t(d[7])<<24);if(o.version!=1){o.error="unsupported WebAssembly binary version";o.error_offset=4;return o;}
    std::vector<std::uint32_t>import_types,defined_types;std::vector<std::pair<std::uint64_t,std::uint64_t>>bodies;std::map<std::uint32_t,std::string>fnames;std::set<unsigned>seen;int last_rank=0;auto rank=[](unsigned id){switch(id){case 1:return 1;case 2:return 2;case 3:return 3;case 4:return 4;case 5:return 5;case 13:return 6;case 6:return 7;case 7:return 8;case 8:return 9;case 9:return 10;case 12:return 11;case 10:return 12;case 11:return 13;default:return 0;}};
    Reader m(d,8,d.size(),&o);while(m.p<m.end){auto section_off=m.p;std::uint8_t id=0;if(!m.byte(id))return o;std::uint32_t sz=0;if(!m.u32(sz))return o;if(sz>m.end-m.p){m.fail("WebAssembly section size exceeds file");return o;}auto payload=m.p,se=m.p+sz;++o.section_count;if(id!=0){if(!seen.insert(id).second){m.p=section_off;m.fail("duplicate WebAssembly standard section");return o;}auto rr=rank(id);if(rr&&rr<last_rank){m.p=section_off;m.fail("WebAssembly standard sections out of order");return o;}if(rr)last_rank=rr;else{o.anomalies.push_back("unknown/future standard section id "+std::to_string(id)+" skipped");m.p=se;continue;}}
        Reader s(d,payload,se,&o);bool ok=true;
        if(id==0){std::string n;if(!name(s,n)){o.error.clear();o.error_offset=0;o.anomalies.push_back("malformed custom section name at file offset "+std::to_string(payload));m.p=se;continue;}o.custom_sections.push_back({n,section_off,se-section_off});if(n=="name")parse_name_custom(d,s.p,se,o,fnames);custom_clues(d.subspan(s.p,se-s.p),n,o);s.p=se;}
        else if(id==1)ok=parse_type_section(s,o);else if(id==2)ok=parse_import_section(s,o,import_types);else if(id==3)ok=parse_function_section(s,o,defined_types);else if(id==7)ok=parse_export_section(s,o);else if(id==8)ok=parse_start_section(s,o,section_off);else if(id==10)ok=parse_code_section(s,o,bodies);else if(id==11)ok=parse_data_section(s,o);else if(id==12){o.has_data_count=true;ok=s.u32(o.data_count);}else s.p=se;
        if(!ok)return o;
        if(s.p!=se){s.fail("WebAssembly section parser did not consume declared payload");return o;}
        m.p=se;
    }
    if(defined_types.size()!=bodies.size()){o.error="WebAssembly function/code section count mismatch";o.error_offset=8;return o;}
    if(o.has_data_count&&o.data_count!=o.data_segments.size()){o.error="WebAssembly data count does not match data section";o.error_offset=8;return o;}
    o.functions.reserve(import_types.size()+defined_types.size());for(std::size_t i=0;i<import_types.size();++i){WasmFunction f;f.index=i;f.imported=true;f.type_index=import_types[i];for(const auto&im:o.imports)if(im.kind=="function"&&im.index==i){f.import_module=im.module;f.import_name=im.name;f.name=im.name;break;}o.functions.push_back(std::move(f));}
    for(std::size_t i=0;i<defined_types.size();++i){WasmFunction f;f.index=static_cast<std::uint32_t>(import_types.size()+i);f.type_index=defined_types[i];f.code_offset=bodies[i].first;f.code_size=bodies[i].second;o.functions.push_back(std::move(f));}
    std::map<std::uint32_t,std::vector<std::string>>exnames;for(const auto&e:o.exports)if(e.kind=="function")exnames[e.index].push_back(e.name);for(auto&f:o.functions){if(auto it=fnames.find(f.index);it!=fnames.end())f.name=it->second;if(auto it=exnames.find(f.index);it!=exnames.end())f.exports=it->second;if(f.name.empty()&&!f.exports.empty())f.name=f.exports.front();if(f.type_index<o.types.size())f.signature=o.types[f.type_index].signature;for(const auto&x:f.exports)if(user_name(x))f.user_like=true;if(!f.imported&&user_name(f.name))f.user_like=true;}
    if(o.has_start){
        if(o.start_function_index>=o.functions.size()){o.error="WebAssembly start section references missing function index";o.error_offset=o.start_index_offset;return o;}
        const auto&sf=o.functions[o.start_function_index];o.start_type_index=sf.type_index;o.start_imported=sf.imported;o.start_name=sf.name;o.start_signature=sf.signature;o.start_code_offset=sf.code_offset;o.start_code_size=sf.code_size;o.start_exports=sf.exports;o.start_exported=!sf.exports.empty();
        if(o.type_parse_complete){if(sf.type_index>=o.types.size()){o.error="WebAssembly start function references missing type index";o.error_offset=o.start_index_offset;return o;}const auto&t=o.types[sf.type_index];if(!t.params.empty()||!t.results.empty()){o.error="WebAssembly start function type must be ()->void";o.error_offset=o.start_index_offset;return o;}}
        auto&im=o.implicit_exec;ImplicitExecutionFact f;f.format="WebAssembly";f.ecosystem="Wasm";f.phase="module_instantiation";f.trigger="WASM_START_SECTION";f.relation="implicit_callback";f.source_kind="start_section";f.source_index=o.start_function_index;f.source_file_backed=true;f.source_file_offset=o.start_index_offset;f.source_size=o.start_index_size;f.target_kind=sf.imported?"imported_function_index":"defined_function_index";f.target_function_index=sf.index;f.target_name=sf.name;f.evidence_state=o.type_parse_complete?"EXACT":"PARTIAL_TYPE_SEMANTICS";f.mutability="IMMUTABLE_WASM_MODULE";f.execution_condition="WebAssembly engine invokes the start function during module instantiation after instance initialization and before the instance is made available to the embedder; the function body is not executed by analysis";f.priority="INFORMATIONAL";f.priority_reason=sf.exports.empty()?"non-exported start is an implicit module-instantiation entry worth inspecting before exported APIs; presence itself is normal":"start function is an ordinary module-instantiation surface and is also exported";std::ostringstream q;q<<"type_index="<<sf.type_index<<";signature="<<sf.signature<<";imported="<<(sf.imported?"true":"false")<<";code_offset=0x"<<std::hex<<sf.code_offset<<std::dec<<";code_size="<<sf.code_size<<";exports="<<exports_join(sf.exports);f.detail=q.str();f.index=0;im.facts.push_back(std::move(f));im.informational_count=1;im.state=o.type_parse_complete?"RESOLVED":"PARTIAL";if(!o.type_parse_complete)im.error="WebAssembly start target exists but its function type is in an unsupported type syntax";
    }
    o.named_function_count=static_cast<std::uint32_t>(std::count_if(o.functions.begin(),o.functions.end(),[](const auto&f){return !f.name.empty();}));
    if(o.type_parse_complete){for(const auto&f:o.functions)if(f.type_index>=o.types.size()){o.error="WebAssembly function references missing type index";o.error_offset=8;return o;}}
    o.valid=true;return o;
}

Finding wasm_finding(const WasmInfo&i){Finding f;f.kind="bytecode";f.family="WebAssembly";f.variant="binary v"+std::to_string(i.version);if(!i.valid){f.state="FAILED";if(!i.error.empty()){std::ostringstream x;x<<i.error<<" at 0x"<<std::hex<<i.error_offset;f.negative_evidence.push_back(x.str());}return f;}f.state="CONFIRMED";f.evidence={"WebAssembly magic/version and complete section bounds validated","function and code section cardinality validated"};if(i.type_parse_complete)f.evidence.push_back("function type signatures parsed and associated with imported/defined functions");if(i.named_function_count)f.evidence.push_back("function names recovered from name section and/or exports");f.fields["sections"]=std::to_string(i.section_count);f.fields["types"]=std::to_string(i.types.size());f.fields["functions"]=std::to_string(i.functions.size());f.fields["imported_functions"]=std::to_string(i.imported_function_count);f.fields["defined_functions"]=std::to_string(i.defined_function_count);f.fields["named_functions"]=std::to_string(i.named_function_count);f.fields["imports"]=std::to_string(i.imports.size());f.fields["exports"]=std::to_string(i.exports.size());f.fields["custom_sections"]=std::to_string(i.custom_sections.size());f.fields["data_segments"]=std::to_string(i.data_segments.size());if(i.has_data_count)f.fields["data_count"]=std::to_string(i.data_count);f.fields["string_hints"]=std::to_string(i.string_hints.size());if(!i.dwarf_sections.empty()){std::string x;for(const auto&s:i.dwarf_sections){if(!x.empty())x+=",";x+=s;}f.fields["debug_sections"]=x;}for(const auto&a:i.anomalies)f.negative_evidence.push_back(a);if(!i.type_parse_complete)f.negative_evidence.push_back("type section was not decoded completely; GC/recursive/future type syntax may be present");if(!i.name_parse_complete)f.negative_evidence.push_back("custom name subsection was malformed; core module remains valid");f.suggested_actions={"extract:wasm-function-map","inspect exported/user-named functions first","use wasm decompiler/disassembler for selected code bodies"};return f;}

WasmExtractResult extract_wasm(const WasmInfo&i,const std::filesystem::path&out){WasmExtractResult r;if(!i.valid){r.error="WebAssembly module not validated";return r;}std::ofstream f(out,std::ios::binary|std::ios::trunc);if(!f){r.error="cannot create WebAssembly function CSV";return r;}f<<"function_index,kind,type_index,signature,code_offset,code_size,name,exports,import_module,import_name,user_like\n";for(const auto&x:i.functions)f<<x.index<<','<<(x.imported?"import":"defined")<<','<<x.type_index<<','<<csvq(x.signature)<<",0x"<<std::hex<<x.code_offset<<std::dec<<','<<x.code_size<<','<<csvq(x.name)<<','<<csvq(exports_join(x.exports))<<','<<csvq(x.import_module)<<','<<csvq(x.import_name)<<','<<(x.user_like?"true":"false")<<"\n";if(!f){r.error="write WebAssembly function CSV failed";return r;}r.functions_csv=out;r.function_count=i.functions.size();auto sp=out;sp.replace_extension(".strings.txt");std::ofstream s(sp,std::ios::binary|std::ios::trunc);if(s){for(const auto&x:i.string_hints)s<<x<<'\n';if(s){r.strings_txt=sp;r.string_count=i.string_hints.size();}}r.success=true;return r;}
}
