#include "prts/cpython_introspection.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <map>
#include <string_view>
#include <utility>

namespace prts { namespace {
enum class JT { Null,Bool,Number,String,Array,Object };
struct J { JT type=JT::Null; bool b=false; std::string s; std::vector<J>a; std::map<std::string,J>o; const J*get(std::string_view k)const{auto i=o.find(std::string(k));return i==o.end()?nullptr:&i->second;} };
struct JP {
    std::string_view in; std::size_t p=0,depth=0,nodes=0,max_depth=64,max_nodes=65536; std::string error;
    void ws(){while(p<in.size()&&(in[p]==' '||in[p]=='\t'||in[p]=='\r'||in[p]=='\n'))++p;}
    bool fail(std::string x){if(error.empty())error=std::move(x);return false;}
    bool node(){return ++nodes<=max_nodes?true:fail("JSON node budget exceeded");}
    static bool hex(char c,unsigned&v){if(c>='0'&&c<='9'){v=c-'0';return true;}if(c>='a'&&c<='f'){v=c-'a'+10;return true;}if(c>='A'&&c<='F'){v=c-'A'+10;return true;}return false;}
    static void utf8(std::string&o,std::uint32_t c){if(c<=0x7f)o.push_back(char(c));else if(c<=0x7ff){o.push_back(char(0xc0|(c>>6)));o.push_back(char(0x80|(c&63)));}else if(c<=0xffff){o.push_back(char(0xe0|(c>>12)));o.push_back(char(0x80|((c>>6)&63)));o.push_back(char(0x80|(c&63)));}else{o.push_back(char(0xf0|(c>>18)));o.push_back(char(0x80|((c>>12)&63)));o.push_back(char(0x80|((c>>6)&63)));o.push_back(char(0x80|(c&63)));}}
    bool u16(std::uint32_t&v){if(p+4>in.size())return fail("truncated JSON unicode escape");v=0;for(int i=0;i<4;i++){unsigned h=0;if(!hex(in[p++],h))return fail("invalid JSON unicode escape");v=(v<<4)|h;}return true;}
    bool str(std::string&o){ws();if(p>=in.size()||in[p]!='\"')return fail("expected JSON string");++p;o.clear();while(p<in.size()){unsigned char c=static_cast<unsigned char>(in[p++]);if(c=='\"')return true;if(c<0x20)return fail("control byte in JSON string");if(c!='\\'){o.push_back(char(c));continue;}if(p>=in.size())return fail("truncated JSON escape");char e=in[p++];switch(e){case '\"':o.push_back('\"');break;case '\\':o.push_back('\\');break;case '/':o.push_back('/');break;case 'b':o.push_back('\b');break;case 'f':o.push_back('\f');break;case 'n':o.push_back('\n');break;case 'r':o.push_back('\r');break;case 't':o.push_back('\t');break;case 'u':{std::uint32_t cp=0;if(!u16(cp))return false;if(cp>=0xd800&&cp<=0xdbff){if(p+2>in.size()||in[p]!='\\'||in[p+1]!='u')return fail("unpaired high JSON surrogate");p+=2;std::uint32_t lo=0;if(!u16(lo))return false;if(lo<0xdc00||lo>0xdfff)return fail("invalid low JSON surrogate");cp=0x10000+((cp-0xd800)<<10)+(lo-0xdc00);}else if(cp>=0xdc00&&cp<=0xdfff)return fail("unpaired low JSON surrogate");utf8(o,cp);break;}default:return fail("invalid JSON escape");}}return fail("unterminated JSON string");}
    bool value(J&v){ws();if(depth>=max_depth)return fail("JSON depth budget exceeded");if(!node())return false;if(p>=in.size())return fail("unexpected end of JSON");char c=in[p];if(c=='\"'){v.type=JT::String;return str(v.s);}if(c=='{'){v.type=JT::Object;++p;++depth;ws();if(p<in.size()&&in[p]=='}'){++p;--depth;return true;}for(;;){std::string k;if(!str(k))return false;ws();if(p>=in.size()||in[p++]!=':')return fail("expected ':' in JSON object");J x;if(!value(x))return false;if(!v.o.emplace(std::move(k),std::move(x)).second)return fail("duplicate JSON object key");ws();if(p>=in.size())return fail("unterminated JSON object");char q=in[p++];if(q=='}'){--depth;return true;}if(q!=',')return fail("expected ',' in JSON object");}}
        if(c=='['){v.type=JT::Array;++p;++depth;ws();if(p<in.size()&&in[p]==']'){++p;--depth;return true;}for(;;){J x;if(!value(x))return false;v.a.push_back(std::move(x));ws();if(p>=in.size())return fail("unterminated JSON array");char q=in[p++];if(q==']'){--depth;return true;}if(q!=',')return fail("expected ',' in JSON array");}}
        if(in.substr(p,4)=="true"){v.type=JT::Bool;v.b=true;p+=4;return true;}if(in.substr(p,5)=="false"){v.type=JT::Bool;v.b=false;p+=5;return true;}if(in.substr(p,4)=="null"){v.type=JT::Null;p+=4;return true;}
        std::size_t b=p;if(in[p]=='-')++p;if(p>=in.size())return fail("bad JSON number");if(in[p]=='0')++p;else{if(!std::isdigit(static_cast<unsigned char>(in[p])))return fail("bad JSON number");while(p<in.size()&&std::isdigit(static_cast<unsigned char>(in[p])))++p;}if(p<in.size()&&in[p]=='.'){++p;if(p>=in.size()||!std::isdigit(static_cast<unsigned char>(in[p])))return fail("bad JSON fraction");while(p<in.size()&&std::isdigit(static_cast<unsigned char>(in[p])))++p;}if(p<in.size()&&(in[p]=='e'||in[p]=='E')){++p;if(p<in.size()&&(in[p]=='+'||in[p]=='-'))++p;if(p>=in.size()||!std::isdigit(static_cast<unsigned char>(in[p])))return fail("bad JSON exponent");while(p<in.size()&&std::isdigit(static_cast<unsigned char>(in[p])))++p;}v.type=JT::Number;v.s=std::string(in.substr(b,p-b));return true;}
    bool root(J&v){if(!value(v))return false;ws();return p==in.size()?true:fail("trailing bytes after JSON value");}
};
bool jstr(const J*j,std::string&o){if(!j||j->type!=JT::String)return false;o=j->s;return true;} bool jbool(const J*j,bool&o){if(!j||j->type!=JT::Bool)return false;o=j->b;return true;}
bool ju64(const J*j,std::uint64_t&o){if(!j||j->type!=JT::Number||j->s.empty()||j->s[0]=='-'||j->s.find_first_of(".eE")!=std::string::npos)return false;auto b=j->s.data(),e=b+j->s.size();auto r=std::from_chars(b,e,o);return r.ec==std::errc{}&&r.ptr==e;}
bool ji64(const J*j,std::int64_t&o){if(!j||j->type!=JT::Number||j->s.find_first_of(".eE")!=std::string::npos)return false;auto b=j->s.data(),e=b+j->s.size();auto r=std::from_chars(b,e,o);return r.ec==std::errc{}&&r.ptr==e;}
int rank_state(std::string_view s){if(s=="NOT_ATTEMPTED")return 0;if(s=="TRANSPORT_FAILED")return 1;if(s=="INTERPRETER_NOT_FOUND")return 2;if(s=="PROBE_LOADED")return 3;if(s=="HOOK_ARMED")return 4;if(s=="HOOK_TRIGGERED")return 5;if(s=="FRAME_SNAPSHOT_CAPTURED")return 6;if(s=="PARTIAL")return 7;if(s=="FAILED")return 8;return -1;}
bool controller_name(std::string_view s){return s=="NOT_ATTEMPTED"||s=="TRANSPORT_FAILED"||s=="INTERPRETER_NOT_FOUND"||s=="FAILED";}
void update_state(CPythonIntrospectionReport&r,const std::string&s){if(rank_state(s)>=0&&(r.runtime_state=="NOT_ATTEMPTED"||rank_state(s)>rank_state(r.runtime_state)))r.runtime_state=s;}
struct TriggerCorrelation {
    bool behavior_modified=false,behavior_modified_present=false;
    std::uint64_t thread_ident=0,thread_native_id=0;
    std::string scope,interpreter_runtime,interpreter_executable,interpreter_identity;
};
struct StreamState {
    std::string interpreter_runtime,interpreter_executable,interpreter_identity_kind,interpreter_identity;
    std::map<std::pair<std::string,std::string>,bool> armed;
    std::map<std::pair<std::string,std::string>,TriggerCorrelation> pending;
};
std::string effective_interpreter_identity(const CPythonIntrospectionEventFact&e){return !e.interpreter_identity.empty()?e.interpreter_identity:e.interpreter_modules_identity;}
bool bind_stream_field(std::string&baseline,const std::string&current,std::string_view name,std::string&err){
    if(current.empty())return true;
    if(baseline.empty()){baseline=current;return true;}
    if(baseline==current)return true;
    err="interpreter context changed within one protocol stream: "+std::string(name);return false;
}
bool equal_if_known(const std::string&a,const std::string&b){return a.empty()||b.empty()||a==b;}
bool joptional_string(const J*j,std::string&o,bool&present){
    present=false;
    if(!j||j->type==JT::Null)return false;
    if(j->type!=JT::String)return false;
    o=j->s;present=true;return true;
}
void string_list(const J*j,CPythonIntrospectionStringListFact&out,std::size_t cap){
    if(!j||j->type!=JT::Object)return;
    ju64(j->get("count"),out.count);ju64(j->get("scanned"),out.scanned);jbool(j->get("truncated"),out.truncated);jbool(j->get("unsupported"),out.unsupported);
    auto*items=j->get("items");if(!items||items->type!=JT::Array)return;
    for(const auto&x:items->a){if(x.type!=JT::String)continue;if(out.items.size()<cap)out.items.push_back(x.s);else out.consumer_truncated=true;}
}
bool primitive_summary(const J*j,CPythonIntrospectionPrimitiveSummaryFact&out){
    if(!j||j->type!=JT::Object||!jstr(j->get("kind"),out.kind))return false;
    auto*v=j->get("value");if(v&&v->type==JT::String)out.value=v->s;else if(v&&v->type==JT::Bool){out.bool_value=v->b;out.bool_value_present=true;}
    jstr(j->get("hex"),out.hex);ju64(j->get("length"),out.length);ju64(j->get("bit_length"),out.bit_length);ji64(j->get("sign"),out.sign);jbool(j->get("truncated"),out.truncated);jbool(j->get("value_omitted"),out.value_omitted);return true;
}
bool sample_fact(const J&j,CPythonIntrospectionSampleFact&out){
    if(j.type!=JT::Object)return false;
    auto*k=j.get("key");if(k){auto*v=j.get("value");if(!primitive_summary(k,out.key)||!primitive_summary(v,out.value))return false;out.has_key=true;return true;}
    return primitive_summary(&j,out.value);
}
void value_summary(const J*j,CPythonIntrospectionValueSummaryFact&out,std::size_t sample_cap){
    if(!j||j->type!=JT::Object)return;
    CPythonIntrospectionPrimitiveSummaryFact primitive;
    if(primitive_summary(j,primitive)){
        out.kind=primitive.kind;out.value=primitive.value;out.hex=primitive.hex;out.length=primitive.length;out.bit_length=primitive.bit_length;out.sign=primitive.sign;out.bool_value=primitive.bool_value;out.bool_value_present=primitive.bool_value_present;out.truncated=primitive.truncated;out.value_omitted=primitive.value_omitted;
    }else jstr(j->get("kind"),out.kind);
    jstr(j->get("address"),out.address);jstr(j->get("type"),out.type);jstr(j->get("name"),out.name);jstr(j->get("qualname"),out.qualname);jstr(j->get("module"),out.module);jstr(j->get("loader_type"),out.loader_type);jstr(j->get("backing"),out.backing);jstr(j->get("code_identity"),out.code_identity);
    out.file_present=joptional_string(j->get("file"),out.file,out.file_present);out.package_present=joptional_string(j->get("package"),out.package,out.package_present);out.origin_present=joptional_string(j->get("origin"),out.origin,out.origin_present);
    ju64(j->get("count"),out.count);ju64(j->get("sample_count"),out.sample_count);ju64(j->get("sample_scan_count"),out.sample_scan_count);ju64(j->get("globals_count"),out.globals_count);jbool(j->get("sample_scan_truncated"),out.sample_scan_truncated);jbool(j->get("partial"),out.partial);jbool(j->get("unsupported"),out.unsupported);
    auto*code=j->get("code");if(code&&code->type==JT::Object){jstr(code->get("identity"),out.code_identity);jstr(code->get("co_name"),out.name);jstr(code->get("co_qualname"),out.qualname);jstr(code->get("co_filename"),out.filename);ji64(code->get("co_firstlineno"),out.first_line);}
    auto*sample=j->get("primitive_sample");if(sample&&sample->type==JT::Array){for(const auto&x:sample->a){CPythonIntrospectionSampleFact f;if(!sample_fact(x,f))continue;if(out.primitive_sample.size()<sample_cap)out.primitive_sample.push_back(std::move(f));else out.consumer_sample_truncated=true;}}
}
bool module_fact(const J&j,CPythonIntrospectionModuleFact&out){
    if(j.type!=JT::Object)return false;
    std::string kind;
    if(!jstr(j.get("kind"),kind)||kind!="module")return false;
    jstr(j.get("name"),out.name);jstr(j.get("backing"),out.backing);jstr(j.get("address"),out.address);jstr(j.get("state"),out.state);jstr(j.get("type"),out.type);ju64(j.get("globals_count"),out.globals_count);
    out.file_present=joptional_string(j.get("file"),out.file,out.file_present);out.package_present=joptional_string(j.get("package"),out.package,out.package_present);out.loader_type_present=joptional_string(j.get("loader_type"),out.loader_type,out.loader_type_present);out.origin_present=joptional_string(j.get("origin"),out.origin,out.origin_present);return true;
}
void variables(const J*scope,std::vector<CPythonIntrospectionVariableFact>&out,std::uint64_t&count,std::uint64_t&scanned,bool&tr,bool&scan_truncated,bool&consumer_truncated,std::string&count_semantics,std::size_t cap,std::size_t sample_cap){
    if(!scope||scope->type!=JT::Object)return;
    ju64(scope->get("count"),count);ju64(scope->get("scanned"),scanned);jbool(scope->get("truncated"),tr);jbool(scope->get("scan_truncated"),scan_truncated);jstr(scope->get("count_semantics"),count_semantics);
    auto*v=scope->get("variables");if(!v||v->type!=JT::Array)return;
    for(const auto&x:v->a){if(x.type!=JT::Object)continue;if(out.size()>=cap){consumer_truncated=true;continue;}CPythonIntrospectionVariableFact f;jstr(x.get("name"),f.name);jstr(x.get("type"),f.type);value_summary(x.get("summary"),f.summary,sample_cap);f.summary_kind=f.summary.kind;f.summary_count=f.summary.count;f.sample_count=f.summary.sample_count;f.sample_scan_count=f.summary.sample_scan_count;f.summary_truncated=f.summary.truncated;f.sample_scan_truncated=f.summary.sample_scan_truncated;if(!f.name.empty())out.push_back(std::move(f));}
}
CPythonIntrospectionFrameFact frame(const J&j,const CPythonIntrospectionBudgets&b){
    CPythonIntrospectionFrameFact f;std::uint64_t d=0;ju64(j.get("depth"),d);f.depth=static_cast<std::uint32_t>(std::min<std::uint64_t>(d,std::numeric_limits<std::uint32_t>::max()));jstr(j.get("frame_identity"),f.frame_identity);jstr(j.get("caller_frame_identity"),f.caller_frame_identity);ji64(j.get("f_lineno"),f.line);ji64(j.get("f_lasti"),f.lasti);
    auto*c=j.get("code");if(c&&c->type==JT::Object){jstr(c->get("identity"),f.code_identity);jstr(c->get("co_name"),f.code_name);jstr(c->get("co_qualname"),f.code_qualname);jstr(c->get("co_filename"),f.filename);ji64(c->get("co_firstlineno"),f.first_line);ji64(c->get("co_argcount"),f.code_argcount);ji64(c->get("co_posonlyargcount"),f.code_posonlyargcount);ji64(c->get("co_kwonlyargcount"),f.code_kwonlyargcount);ji64(c->get("co_nlocals"),f.code_nlocals);ji64(c->get("co_stacksize"),f.code_stacksize);ji64(c->get("co_flags"),f.code_flags);string_list(c->get("co_names"),f.code_names,b.max_code_items_per_list);string_list(c->get("co_varnames"),f.code_varnames,b.max_code_items_per_list);string_list(c->get("co_freevars"),f.code_freevars,b.max_code_items_per_list);string_list(c->get("co_cellvars"),f.code_cellvars,b.max_code_items_per_list);}
    variables(j.get("locals"),f.locals,f.locals_count,f.locals_scanned,f.locals_truncated,f.locals_scan_truncated,f.locals_consumer_truncated,f.locals_count_semantics,b.max_variables_per_scope,b.max_container_samples_per_variable);variables(j.get("globals"),f.globals,f.globals_count,f.globals_scanned,f.globals_truncated,f.globals_scan_truncated,f.globals_consumer_truncated,f.globals_count_semantics,b.max_variables_per_scope,b.max_container_samples_per_variable);return f;
}
bool record(const J&j,CPythonIntrospectionReport&r,const CPythonIntrospectionBudgets&b,StreamState&stream,std::string&err){
    if(j.type!=JT::Object){err="protocol record is not an object";return false;}std::string proto;if(!jstr(j.get("protocol"),proto)||proto!="auto-refirst.cpython.introspection"){err="protocol identifier mismatch";return false;}std::uint64_t schema=0;if(!ju64(j.get("schema"),schema)||schema!=1){err="unsupported introspection schema";return false;}r.schema=1;r.protocol_valid=true;CPythonIntrospectionEventFact e;if(!jstr(j.get("event"),e.event)||!jstr(j.get("state"),e.state)){err="protocol record lacks event/state";return false;}if(rank_state(e.state)<0){err="unknown protocol state: "+e.state;return false;}
    const bool known_event=e.event=="probe_loaded"||e.event=="hook_armed"||e.event=="hook_triggered"||e.event=="frame_snapshot";if(!known_event){err="unknown schema-1 event: "+e.event;return false;}if(r.records_retained==0&&!(e.event=="probe_loaded"&&e.state=="PROBE_LOADED")){err="first protocol record must be probe_loaded/PROBE_LOADED";return false;}if(e.event=="probe_loaded"&&r.records_retained!=0){err="duplicate or late probe_loaded record";return false;}if((e.event=="hook_armed"&&e.state!="HOOK_ARMED")||(e.event=="hook_triggered"&&e.state!="HOOK_TRIGGERED")||(e.event=="frame_snapshot"&&e.state!="FRAME_SNAPSHOT_CAPTURED"&&e.state!="PARTIAL")){err="event/state mismatch for "+e.event;return false;}jstr(j.get("transport"),e.transport);if(r.transport.empty())r.transport=e.transport;else if(!e.transport.empty()&&r.transport!=e.transport){err="transport changed within one protocol stream";return false;}jstr(j.get("hook"),e.hook);jstr(j.get("trigger"),e.trigger);jstr(j.get("scope"),e.hook_scope);jstr(j.get("exception_type"),e.exception_type);e.behavior_modified_present=jbool(j.get("behavior_modified"),e.behavior_modified);
    const bool retaining_event=r.events.size()<b.max_events;if(!retaining_event)r.events_consumer_truncated=true;
    auto*i=j.get("interpreter");if(i&&i->type==JT::Object){jstr(i->get("runtime"),e.interpreter_runtime);jstr(i->get("executable"),e.interpreter_executable);jstr(i->get("identity_kind"),e.interpreter_identity_kind);jstr(i->get("identity"),e.interpreter_identity);jstr(i->get("sys_modules_identity"),e.interpreter_modules_identity);}auto*t=j.get("thread");if(t&&t->type==JT::Object){ju64(t->get("ident"),e.thread_ident);ju64(t->get("native_id"),e.thread_native_id);jstr(t->get("name"),e.thread_name);}
    const auto effective_identity=effective_interpreter_identity(e);
    if(!e.interpreter_identity.empty()&&!e.interpreter_modules_identity.empty()&&e.interpreter_identity!=e.interpreter_modules_identity){err="interpreter identity disagrees with sys_modules_identity";return false;}
    if(!bind_stream_field(stream.interpreter_runtime,e.interpreter_runtime,"runtime",err)||!bind_stream_field(stream.interpreter_executable,e.interpreter_executable,"executable",err)||!bind_stream_field(stream.interpreter_identity_kind,e.interpreter_identity_kind,"identity_kind",err)||!bind_stream_field(stream.interpreter_identity,effective_identity,"identity",err))return false;
    const auto correlation_key=std::make_pair(e.hook,e.trigger);
    if(e.event=="hook_armed")stream.armed[correlation_key]=true;
    if(e.event=="hook_triggered"){
        if((!e.behavior_modified_present||e.behavior_modified)&&!stream.armed[correlation_key]){err="behavior-modifying hook_triggered lacks prior matching hook_armed";return false;}
        TriggerCorrelation c;c.behavior_modified=e.behavior_modified;c.behavior_modified_present=e.behavior_modified_present;c.thread_ident=e.thread_ident;c.thread_native_id=e.thread_native_id;c.scope=e.hook_scope;c.interpreter_runtime=e.interpreter_runtime;c.interpreter_executable=e.interpreter_executable;c.interpreter_identity=effective_identity;stream.pending[correlation_key]=std::move(c);
    }
    if(e.event=="frame_snapshot"){
        auto pending_it=stream.pending.find(correlation_key);
        if(pending_it==stream.pending.end()){err="frame_snapshot lacks prior matching hook_triggered (trigger must be unconsumed)";return false;}
        const auto&pending=pending_it->second;
        if(pending.thread_ident&&e.thread_ident&&pending.thread_ident!=e.thread_ident){err="frame_snapshot thread ident differs from matching hook_triggered";return false;}
        if(pending.thread_native_id&&e.thread_native_id&&pending.thread_native_id!=e.thread_native_id){err="frame_snapshot native thread id differs from matching hook_triggered";return false;}
        if(!equal_if_known(pending.scope,e.hook_scope)){err="frame_snapshot scope differs from matching hook_triggered";return false;}
        if(pending.behavior_modified_present&&e.behavior_modified_present&&pending.behavior_modified!=e.behavior_modified){err="frame_snapshot behavior_modified differs from matching hook_triggered";return false;}
        if(!equal_if_known(pending.interpreter_runtime,e.interpreter_runtime)||!equal_if_known(pending.interpreter_executable,e.interpreter_executable)||!equal_if_known(pending.interpreter_identity,effective_identity)){err="frame_snapshot interpreter differs from matching hook_triggered";return false;}
        stream.pending.erase(pending_it);
    }
    if(e.event=="probe_loaded"){
        auto*rt=j.get("runtime");
        if(rt&&rt->type==JT::Object){
            jstr(rt->get("version"),r.runtime.version);jstr(rt->get("executable"),r.runtime.executable);jstr(rt->get("prefix"),r.runtime.prefix);jstr(rt->get("base_prefix"),r.runtime.base_prefix);
            auto*sp=rt->get("sys_path");
            if(sp&&sp->type==JT::Object){
                CPythonIntrospectionStringListFact paths;string_list(sp,paths,b.max_sys_path_items);
                r.runtime.sys_path_count=paths.count;r.runtime.sys_path_scanned=paths.scanned;r.runtime.sys_path_truncated=paths.truncated;r.runtime.sys_path_unsupported=paths.unsupported;r.runtime.sys_path_consumer_truncated=paths.consumer_truncated;r.runtime.sys_path_items=std::move(paths.items);
                jbool(sp->get("scan_truncated"),r.runtime.sys_path_scan_truncated);jstr(sp->get("count_semantics"),r.runtime.sys_path_count_semantics);
            }
            auto*m=rt->get("modules");
            if(m&&m->type==JT::Object){
                ju64(m->get("count"),r.runtime.module_count);ju64(m->get("scanned"),r.runtime.modules_scanned);jbool(m->get("truncated"),r.runtime.modules_truncated);jbool(m->get("scan_truncated"),r.runtime.modules_scan_truncated);jbool(m->get("unsupported"),r.runtime.modules_unsupported);jstr(m->get("count_semantics"),r.runtime.module_count_semantics);
                auto*items=m->get("items");
                if(items&&items->type==JT::Array){
                    for(const auto&x:items->a){CPythonIntrospectionModuleFact mf;if(!module_fact(x,mf))continue;if(r.runtime.modules.size()<b.max_runtime_modules)r.runtime.modules.push_back(std::move(mf));else r.runtime.modules_consumer_truncated=true;}
                }
            }
        }
    }else if(e.event=="hook_armed")++r.hook_armed_count;
    else if(e.event=="hook_triggered")++r.hook_triggered_count;
    else if(e.event=="frame_snapshot"){
        ++r.frame_snapshot_count;auto*s=j.get("snapshot");
        if(s&&s->type==JT::Object){
            jbool(s->get("truncated"),e.frames_truncated);
            auto*fs=s->get("frames");
            if(fs&&fs->type==JT::Array){for(const auto&x:fs->a){if(x.type!=JT::Object)continue;if(e.frames.size()<b.max_frames_per_event)e.frames.push_back(frame(x,b));else e.frames_consumer_truncated=true;}}
            auto*pr=s->get("partial_reasons");
            if(pr&&pr->type==JT::Array){for(const auto&x:pr->a){if(x.type!=JT::String)continue;if(e.partial_reasons.size()<b.max_partial_reasons)e.partial_reasons.push_back(x.s);else e.partial_reasons_consumer_truncated=true;}}
        }
    }
    update_state(r,e.state);if(retaining_event)r.events.push_back(std::move(e));return true;
}
}

CPythonIntrospectionReport cpython_introspection_controller_state(std::string state,std::string transport,std::string error){CPythonIntrospectionReport r;if(!controller_name(state)){r.attempted=true;r.state="FAILED";r.parser_state="FAILED";r.transport=std::move(transport);r.error="invalid controller state: "+state;return r;}r.attempted=state!="NOT_ATTEMPTED";r.state=std::move(state);r.transport=std::move(transport);r.error=std::move(error);return r;}

bool parse_cpython_introspection_jsonl(const std::filesystem::path&path,CPythonIntrospectionReport&r,std::string&error,const CPythonIntrospectionBudgets&b){
    r=CPythonIntrospectionReport{};r.attempted=true;r.state="FAILED";r.parser_state="FAILED";StreamState stream;std::ifstream f(path,std::ios::binary);if(!f){error="cannot open introspection JSONL";r.error=error;return false;}std::string line;std::uint64_t no=0;bool any=false;
    while(std::getline(f,line)){++no;if(!line.empty()&&line.back()=='\r')line.pop_back();if(line.empty())continue;any=true;++r.records_seen;if(line.size()>b.max_line_bytes){error="introspection JSONL line exceeds byte budget at line "+std::to_string(no);r.error=error;return false;}if(r.records_seen>b.max_records){r.records_truncated=true;continue;}J root;JP p{line,0,0,0,b.max_json_depth,b.max_json_nodes,{}};if(!p.root(root)){error="invalid introspection JSONL at line "+std::to_string(no)+": "+p.error;r.error=error;return false;}std::string re;if(!record(root,r,b,stream,re)){error="invalid introspection protocol at line "+std::to_string(no)+": "+re;r.error=error;return false;}++r.records_retained;}
    if(!f.eof()&&f.fail()){error="failed while reading introspection JSONL";r.error=error;return false;}if(!any){error="introspection JSONL is empty";r.error=error;return false;}if(r.runtime_state=="NOT_ATTEMPTED"){error="introspection stream contained no recognized runtime state";r.error=error;return false;}const bool consumer_partial=r.records_truncated||r.events_consumer_truncated;r.parser_state=consumer_partial?"PARTIAL":"COMPLETE";r.state=consumer_partial?"PARTIAL":r.runtime_state;r.error.clear();error.clear();return true;
}
}
