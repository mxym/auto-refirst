#include "prts/runtime_modality.hpp"
#include "prts/mapped_file.hpp"
#include "prts/orchestration.hpp"
#include "prts/path_utf8.hpp"
#include "prts/report.hpp"
extern "C" {
#include "Zydis.h"
}
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>
#include <vector>

namespace prts { namespace {
constexpr std::uint64_t kPcapInspectByteCap=32ull*1024*1024;
constexpr std::uint64_t kPcapPacketCap=16384;
constexpr std::uint64_t kDumpMemoryInspectCap=64ull*1024*1024;

std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();}
std::string lower_ascii(std::string s){for(char&c:s)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));return s;}
std::string path_key(const std::filesystem::path&p){return path_utf8(p.lexically_normal());}
std::string basename_ascii(std::string_view s){auto p=s.find_last_of("/\\");return std::string(p==std::string_view::npos?s:s.substr(p+1));}
void add_unique(std::vector<std::string>&v,std::string s){if(!s.empty()&&std::find(v.begin(),v.end(),s)==v.end())v.push_back(std::move(s));}
void add_artifact(std::vector<std::filesystem::path>&v,const std::filesystem::path&p){if(!p.empty()&&std::find(v.begin(),v.end(),p)==v.end())v.push_back(p);}
void add_requirement(RuntimeModalityGuidance&g,RuntimeModalityRequirement r){
    auto it=std::find_if(g.requirements.begin(),g.requirements.end(),[&](const auto&x){return x.modality==r.modality;});
    if(it==g.requirements.end()){g.requirements.push_back(std::move(r));return;}
    it->confidence=std::max(it->confidence,r.confidence);if(it->evidence_gate.empty())it->evidence_gate=std::move(r.evidence_gate);if(it->reason.empty())it->reason=std::move(r.reason);
    for(auto&s:r.evidence)add_unique(it->evidence,std::move(s));
    for(auto&s:r.negative_evidence)add_unique(it->negative_evidence,std::move(s));
    for(const auto&p:r.artifacts)add_artifact(it->artifacts,p);
}
RuntimeModalityRequirement req(std::string modality,double confidence,std::string gate,std::string reason){RuntimeModalityRequirement r;r.modality=std::move(modality);r.confidence=confidence;r.evidence_gate=std::move(gate);r.reason=std::move(reason);return r;}
struct BudgetState{bool exhausted=false;std::vector<std::string> reasons;void hit(std::string s){exhausted=true;add_unique(reasons,std::move(s));}};
void finish_guidance(RuntimeModalityGuidance&g,const BudgetState* budget=nullptr){
    if(g.requirements.empty()){
        if(budget&&budget->exhausted){
            auto r=req("UNRESOLVED_RUNTIME_MODALITY",0.0,"ANALYSIS_BUDGET_EXHAUSTED","Candidate-local static modality analysis exhausted a hard budget; no specific runtime modality is proven.");r.state="PARTIAL";
            r.negative_evidence=budget->reasons;r.negative_evidence.push_back("budget exhaustion is not evidence that runtime execution is required; no modality was guessed from truncated analysis");add_requirement(g,std::move(r));
        }else{
            auto r=req("STATIC_SUFFICIENT",0.80,"NO_EVIDENCE_GATED_RUNTIME_REQUIREMENT","No evidence-gated runtime observation modality was established; continue with static analysis unless later evidence proves a runtime dependency.");r.state="SUFFICIENT";
            r.negative_evidence.push_back("STATIC_SUFFICIENT is a routing statement, not proof that runtime behavior is impossible or irrelevant.");add_requirement(g,std::move(r));
        }
    }else if(budget&&budget->exhausted){
        auto r=req("UNRESOLVED_RUNTIME_MODALITY",0.0,"ANALYSIS_BUDGET_EXHAUSTED","A separate candidate-local modality path exhausted its hard budget; existing proven modalities remain valid, but no additional modality is inferred.");r.state="PARTIAL";r.negative_evidence=budget->reasons;add_requirement(g,std::move(r));
    }
    g.runtime_execution_authorized=false;g.static_evidence_only=true;g.policy="STATIC_GUIDANCE_ONLY";
}

struct XInsn{std::uint64_t va=0,file_offset=0;ZydisDecodedInstruction zi{};std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT>ops{};};
ZydisRegister large_reg(ZydisRegister r){return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);}
std::optional<std::uint64_t> relative_target(const XInsn&x){if(!x.zi.operand_count_visible)return{};const auto&o=x.ops[0];if(o.type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||!o.imm.is_relative)return{};auto t=static_cast<std::int64_t>(x.va+x.zi.length)+o.imm.value.s;if(t<0)return{};return static_cast<std::uint64_t>(t);}
std::optional<std::uint64_t> rip_memory_target(const XInsn&x,const ZydisDecodedOperand&o){if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||large_reg(o.mem.base)!=ZYDIS_REGISTER_RIP||o.mem.index!=ZYDIS_REGISTER_NONE)return{};auto t=static_cast<std::int64_t>(x.va+x.zi.length)+(o.mem.disp.has_displacement?o.mem.disp.value:0);if(t<0)return{};return static_cast<std::uint64_t>(t);}
bool is_call(const XInsn&x){return x.zi.meta.category==ZYDIS_CATEGORY_CALL;}
bool elf_exec_va(const ElfInfo&e,std::uint64_t va){for(const auto&s:e.segments)if((s.flags&1)&&va>=s.address&&va-s.address<s.memory_size)return true;return false;}
std::uint64_t executable_file_bytes(const ElfInfo&e){std::uint64_t n=0;for(const auto&s:e.segments)if(s.flags&1){if(s.file_size>std::numeric_limits<std::uint64_t>::max()-n)return std::numeric_limits<std::uint64_t>::max();n+=s.file_size;}return n;}
const ElfSegment* exec_segment_for_va(const ElfInfo&e,std::uint64_t va){for(const auto&s:e.segments)if((s.flags&1)&&va>=s.address&&va-s.address<s.file_size)return &s;return nullptr;}
const ElfUnwindFde* fde_for_va(const ElfInfo&e,std::uint64_t va){for(const auto&f:e.unwind.fdes)if(f.function_file_backed&&va>=f.function_start_va&&va<f.function_end_va)return &f;return nullptr;}
std::string elf_symbol_name(const ElfInfo&e,std::uint32_t idx){for(const auto&s:e.dynamic.symbols)if(s.index==idx)return s.name;return{};}

struct DecodeResult{bool stopped=false,exhausted=false;std::uint32_t instructions=0;};
template<class F>
DecodeResult stream_decode(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t begin,std::uint64_t end,std::uint32_t max_instructions,F&&fn){
    DecodeResult r;if(end<=begin)return r;const auto*s=exec_segment_for_va(e,begin);if(!s||end>s->address+s->file_size)return r;auto rel=begin-s->address;if(s->offset+rel>d.size())return r;auto n=std::min<std::uint64_t>(end-begin,d.size()-(s->offset+rel));
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return r;std::uint64_t pos=0;
    while(pos<n){if(r.instructions>=max_instructions){r.exhausted=true;break;}XInsn x;x.va=begin+pos;x.file_offset=s->offset+rel+pos;auto avail=static_cast<std::size_t>(std::min<std::uint64_t>(n-pos,ZYDIS_MAX_INSTRUCTION_LENGTH));if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+x.file_offset,avail,&x.zi,x.ops.data()))||!x.zi.length){++pos;continue;}++r.instructions;if(!fn(x)){r.stopped=true;break;}pos+=x.zi.length;}
    return r;
}

struct Value{enum class Kind{Unknown,Constant,ExecDerived};Kind kind=Kind::Unknown;std::uint64_t constant=0,anchor=0;};
using Values=std::map<ZydisRegister,Value>;
Value regval(const Values&v,ZydisRegister r){auto it=v.find(large_reg(r));return it==v.end()?Value{}:it->second;}
bool known_value(const Value&v){return v.kind!=Value::Kind::Unknown;}
void erase_call_clobbers(Values&v){for(auto r:{ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11})v.erase(r);}
Value mem_address_value(const XInsn&x,const ZydisDecodedOperand&o,const Values&v,const ElfInfo&e){
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY)return{};
    if(auto rip=rip_memory_target(x,o);rip){if(elf_exec_va(e,*rip))return {Value::Kind::ExecDerived,*rip,*rip};return {Value::Kind::Constant,*rip,0};}
    auto base=regval(v,o.mem.base),index=regval(v,o.mem.index);if(o.mem.base!=ZYDIS_REGISTER_NONE&&!known_value(base))return{};if(o.mem.index!=ZYDIS_REGISTER_NONE&&!known_value(index))return{};std::uint64_t value=known_value(base)?base.constant:0;
    if(known_value(index)){const auto scale=std::max<std::uint64_t>(1,o.mem.scale);if(index.constant>std::numeric_limits<std::uint64_t>::max()/scale)return{};auto scaled=index.constant*scale;if(scaled>std::numeric_limits<std::uint64_t>::max()-value)return{};value+=scaled;}
    if(o.mem.disp.has_displacement){auto disp=o.mem.disp.value;if(disp>=0){if(static_cast<std::uint64_t>(disp)>std::numeric_limits<std::uint64_t>::max()-value)return{};value+=static_cast<std::uint64_t>(disp);}else{auto mag=std::uint64_t(-(disp+1))+1;if(mag>value)return{};value-=mag;}}
    if(base.kind==Value::Kind::ExecDerived)return {Value::Kind::ExecDerived,value,base.anchor};
    if(index.kind==Value::Kind::ExecDerived)return {Value::Kind::ExecDerived,value,index.anchor};
    return {Value::Kind::Constant,value,0};
}
void abstract_step(const XInsn&x,Values&v,const ElfInfo&e,bool preserve_call_saved=true){
    if(is_call(x)){if(preserve_call_saved)erase_call_clobbers(v);else v.clear();return;}if(!x.zi.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)return;auto dst=large_reg(x.ops[0].reg.value);Value next;bool set=false;
    if(x.zi.mnemonic==ZYDIS_MNEMONIC_MOV&&x.zi.operand_count_visible>=2){const auto&s=x.ops[1];if(s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!s.imm.is_relative){next.kind=Value::Kind::Constant;next.constant=s.imm.value.u;set=true;}else if(s.type==ZYDIS_OPERAND_TYPE_REGISTER){next=regval(v,s.reg.value);set=known_value(next);}}
    else if(x.zi.mnemonic==ZYDIS_MNEMONIC_LEA&&x.zi.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){next=mem_address_value(x,x.ops[1],v,e);set=known_value(next);}
    else if(x.zi.mnemonic==ZYDIS_MNEMONIC_XOR&&x.zi.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&large_reg(x.ops[1].reg.value)==dst){next.kind=Value::Kind::Constant;next.constant=0;set=true;}
    else if((x.zi.mnemonic==ZYDIS_MNEMONIC_ADD||x.zi.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.zi.operand_count_visible>=2){auto lhs=regval(v,dst);Value rhs;if(x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){rhs.kind=Value::Kind::Constant;rhs.constant=x.ops[1].imm.value.u;}else if(x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER)rhs=regval(v,x.ops[1].reg.value);if(known_value(lhs)&&known_value(rhs)){next=lhs;next.constant=x.zi.mnemonic==ZYDIS_MNEMONIC_ADD?lhs.constant+rhs.constant:lhs.constant-rhs.constant;if(next.kind!=Value::Kind::ExecDerived&&rhs.kind==Value::Kind::ExecDerived){next.kind=Value::Kind::ExecDerived;next.anchor=rhs.anchor;}set=true;}}
    else if(x.zi.mnemonic==ZYDIS_MNEMONIC_NEG){next=regval(v,dst);if(known_value(next)){next.constant=~next.constant+1;set=true;}}
    else if((x.zi.mnemonic==ZYDIS_MNEMONIC_AND||x.zi.mnemonic==ZYDIS_MNEMONIC_SHR||x.zi.mnemonic==ZYDIS_MNEMONIC_SAR||x.zi.mnemonic==ZYDIS_MNEMONIC_SHL)&&x.zi.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){next=regval(v,dst);if(known_value(next)){auto n=static_cast<unsigned>(x.ops[1].imm.value.u&63);if(x.zi.mnemonic==ZYDIS_MNEMONIC_AND)next.constant&=x.ops[1].imm.value.u;else if(x.zi.mnemonic==ZYDIS_MNEMONIC_SHR)next.constant>>=n;else if(x.zi.mnemonic==ZYDIS_MNEMONIC_SHL)next.constant<<=n;else next.constant=static_cast<std::uint64_t>(static_cast<std::int64_t>(next.constant)>>n);set=true;}}
    if(set)v[dst]=next;else v.erase(dst);
}

struct SelfModProof{bool confirmed=false;std::uint64_t mprotect_va=0,target_va=0,store_va=0,transfer_va=0,length=0,prot=0;};
struct ImportRoute{std::set<std::uint64_t> mprotect_got,all_got,mprotect_stubs,import_stubs;std::vector<std::uint64_t> callsites;};
ImportRoute selfmod_prefilter(std::span<const std::uint8_t>d,const ElfInfo&e,BudgetState&budget){
    ImportRoute q;for(const auto&r:e.dynamic.relocations){if(r.symbol_imported)q.all_got.insert(r.target_va);if(elf_symbol_name(e,r.symbol_index)=="mprotect")q.mprotect_got.insert(r.target_va);}if(q.mprotect_got.empty())return q;
    for(const auto&s:e.segments){if(!(s.flags&1)||!s.file_size||s.offset>=d.size())continue;auto n=std::min<std::uint64_t>(s.file_size,d.size()-s.offset);for(std::uint64_t pos=0;pos+6<=n;++pos){if(d[s.offset+pos]!=0xff||d[s.offset+pos+1]!=0x25)continue;std::int32_t disp=0;std::memcpy(&disp,d.data()+s.offset+pos+2,4);auto end=s.address+pos+6;auto t=static_cast<std::uint64_t>(static_cast<std::int64_t>(end)+disp);if(q.mprotect_got.count(t))q.mprotect_stubs.insert(s.address+pos);if(q.all_got.count(t))q.import_stubs.insert(s.address+pos);}}
    if(q.mprotect_stubs.empty())return q;
    for(const auto&s:e.segments){if(!(s.flags&1)||!s.file_size||s.offset>=d.size())continue;auto n=std::min<std::uint64_t>(s.file_size,d.size()-s.offset);for(std::uint64_t pos=0;pos+5<=n;++pos){if(d[s.offset+pos]!=0xe8)continue;std::int32_t disp=0;std::memcpy(&disp,d.data()+s.offset+pos+1,4);auto end=s.address+pos+5;auto t=static_cast<std::uint64_t>(static_cast<std::int64_t>(end)+disp);if(q.mprotect_stubs.count(t))q.callsites.push_back(s.address+pos);}}
    std::sort(q.callsites.begin(),q.callsites.end());q.callsites.erase(std::unique(q.callsites.begin(),q.callsites.end()),q.callsites.end());if(q.callsites.size()>RuntimeModalityBudgets::max_candidate_windows){budget.hit("self-modifying candidate window budget exhausted before causal proof (callsites="+std::to_string(q.callsites.size())+", max="+std::to_string(RuntimeModalityBudgets::max_candidate_windows)+")");q.callsites.clear();}return q;
}
SelfModProof analyze_selfmod_call(std::span<const std::uint8_t>d,const ElfInfo&e,const ImportRoute&q,std::uint64_t call_va,BudgetState&budget){
    SelfModProof p;auto*f=fde_for_va(e,call_va);if(!f||!f->function_file_backed)return p;if(f->function_size>RuntimeModalityBudgets::max_function_window_bytes){budget.hit("self-modifying caller window exceeds max_function_window_bytes");return p;}
    Values v;bool seen=false;std::uint32_t after=0;std::uint64_t low=0,high=0,length=0,prot=0;std::optional<std::uint64_t>target;
    auto dr=stream_decode(d,e,f->function_start_va,f->function_end_va,RuntimeModalityBudgets::max_instructions_per_window,[&](const XInsn&x){
        if(!seen&&x.va==call_va){auto ct=relative_target(x);if(!is_call(x)||!ct||!q.mprotect_stubs.count(*ct))return false;auto addr=regval(v,ZYDIS_REGISTER_RDI),len=regval(v,ZYDIS_REGISTER_RSI),pr=regval(v,ZYDIS_REGISTER_RDX);if(addr.kind!=Value::Kind::ExecDerived||len.kind!=Value::Kind::Constant||pr.kind!=Value::Kind::Constant||!(pr.constant&2)||!(pr.constant&4)||!len.constant||len.constant>16ull*1024*1024)return false;if(len.constant>std::numeric_limits<std::uint64_t>::max()-addr.constant)return false;low=addr.constant;high=low+len.constant;length=len.constant;prot=pr.constant;seen=true;abstract_step(x,v,e);return true;}
        if(seen){if(++after>64||x.zi.mnemonic==ZYDIS_MNEMONIC_RET)return false;if(is_call(x)){auto t=relative_target(x);if(t&&!q.import_stubs.count(*t)&&*t>=low&&*t<high&&elf_exec_va(e,*t)){target=*t;return false;}}}
        abstract_step(x,v,e);return true;
    });
    if(dr.exhausted){budget.hit("self-modifying caller instruction budget exhausted before causal proof");return p;}if(!target)return p;auto*s=exec_segment_for_va(e,*target);if(!s)return p;auto end=std::min<std::uint64_t>(s->address+s->file_size,*target+RuntimeModalityBudgets::max_function_window_bytes);
    Values body;std::optional<std::uint64_t>store;std::uint64_t transfer=0;bool stack_top_zero=false,pending_push=false,pending_zero=false;Value pending_value;std::uint64_t pending_va=0;std::uint32_t hops=0;
    auto br=stream_decode(d,e,*target,end,RuntimeModalityBudgets::max_instructions_per_window,[&](const XInsn&x){
        if(++hops>RuntimeModalityBudgets::max_local_provenance_hops)return false;
        if(pending_push){if(x.zi.mnemonic==ZYDIS_MNEMONIC_RET){if(store&&pending_value.kind==Value::Kind::ExecDerived&&pending_value.constant>=low&&pending_value.constant<high){transfer=pending_va;return false;}stack_top_zero=pending_zero;pending_push=false;return true;}stack_top_zero=false;pending_push=false;}
        for(std::uint8_t oi=0;oi<x.zi.operand_count_visible;++oi){const auto&o=x.ops[oi];if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||(o.actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;auto a=mem_address_value(x,o,body,e);if(a.kind==Value::Kind::ExecDerived&&a.constant>=low&&a.constant<high&&!store)store=x.va;}
        bool add_zero=false;if(stack_top_zero&&x.zi.mnemonic==ZYDIS_MNEMONIC_ADD&&x.zi.operand_count_visible>=2&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){const auto&m=x.ops[1].mem;if(large_reg(m.base)==ZYDIS_REGISTER_RSP&&m.index==ZYDIS_REGISTER_NONE&&(!m.disp.has_displacement||m.disp.value==0)&&known_value(regval(body,x.ops[0].reg.value)))add_zero=true;}
        if(x.zi.mnemonic==ZYDIS_MNEMONIC_PUSH){if(x.zi.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[0].imm.is_relative&&x.ops[0].imm.value.u==0)stack_top_zero=true;else if(x.zi.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){pending_push=true;pending_zero=stack_top_zero;pending_value=regval(body,x.ops[0].reg.value);pending_va=x.va;}else stack_top_zero=false;}
        else if(x.zi.mnemonic==ZYDIS_MNEMONIC_RET||x.zi.mnemonic==ZYDIS_MNEMONIC_POP||x.zi.mnemonic==ZYDIS_MNEMONIC_LEAVE||x.zi.mnemonic==ZYDIS_MNEMONIC_ENTER)stack_top_zero=false;
        else if(!is_call(x))for(std::uint8_t oi=0;oi<x.zi.operand_count_visible;++oi){const auto&o=x.ops[oi];if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE)&&large_reg(o.reg.value)==ZYDIS_REGISTER_RSP)stack_top_zero=false;if(o.type==ZYDIS_OPERAND_TYPE_MEMORY&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE)&&large_reg(o.mem.base)==ZYDIS_REGISTER_RSP&&o.mem.index==ZYDIS_REGISTER_NONE&&(!o.mem.disp.has_displacement||o.mem.disp.value==0))stack_top_zero=false;}
        if(!add_zero)abstract_step(x,body,e);
        return true;
    });
    if((br.exhausted||hops>RuntimeModalityBudgets::max_local_provenance_hops)&&!transfer){budget.hit("self-modifying body/local provenance budget exhausted before write->execute proof");return p;}if(!store||!transfer)return p;p.confirmed=true;p.mprotect_va=call_va;p.target_va=*target;p.store_va=*store;p.transfer_va=transfer;p.length=length;p.prot=prot;return p;
}
SelfModProof detect_elf_self_mod(std::span<const std::uint8_t>d,const ElfInfo&e,BudgetState&budget){auto q=selfmod_prefilter(d,e,budget);if(q.callsites.empty())return{};for(auto va:q.callsites){auto p=analyze_selfmod_call(d,e,q,va,budget);if(p.confirmed)return p;}return{};}

struct CInsn{std::uint64_t va=0;ZydisMnemonic mnemonic=ZYDIS_MNEMONIC_INVALID;std::uint8_t category=0,op0_type=0,op1_type=0;ZydisRegister op0_reg=ZYDIS_REGISTER_NONE,op1_reg=ZYDIS_REGISTER_NONE,mem0_base=ZYDIS_REGISTER_NONE,mem0_index=ZYDIS_REGISTER_NONE,mem1_base=ZYDIS_REGISTER_NONE,mem1_index=ZYDIS_REGISTER_NONE;std::uint8_t mem1_scale=0;bool mem1_disp=false,op1_relative=false,target_valid=false;std::int64_t mem1_disp_value=0;std::uint64_t op1_imm=0,target=0;};
CInsn compact(const XInsn&x){CInsn c;c.va=x.va;c.mnemonic=x.zi.mnemonic;c.category=static_cast<std::uint8_t>(x.zi.meta.category);if(x.zi.operand_count_visible){const auto&o=x.ops[0];c.op0_type=static_cast<std::uint8_t>(o.type);if(o.type==ZYDIS_OPERAND_TYPE_REGISTER)c.op0_reg=large_reg(o.reg.value);if(o.type==ZYDIS_OPERAND_TYPE_MEMORY){c.mem0_base=large_reg(o.mem.base);c.mem0_index=large_reg(o.mem.index);}}if(x.zi.operand_count_visible>=2){const auto&o=x.ops[1];c.op1_type=static_cast<std::uint8_t>(o.type);if(o.type==ZYDIS_OPERAND_TYPE_REGISTER)c.op1_reg=large_reg(o.reg.value);if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){c.op1_relative=o.imm.is_relative;c.op1_imm=o.imm.value.u;}if(o.type==ZYDIS_OPERAND_TYPE_MEMORY){c.mem1_base=large_reg(o.mem.base);c.mem1_index=large_reg(o.mem.index);c.mem1_scale=o.mem.scale;c.mem1_disp=o.mem.disp.has_displacement;c.mem1_disp_value=o.mem.disp.value;}}if(auto t=relative_target(x)){c.target_valid=true;c.target=*t;}return c;}
bool ccond(const CInsn&x){return x.category==ZYDIS_CATEGORY_COND_BR;}
bool creg_mem_index(const CInsn&x,ZydisRegister r){r=large_reg(r);return x.mem0_base==r||x.mem0_index==r||x.mem1_base==r||x.mem1_index==r;}
std::optional<std::size_t> cindex_for_va(const std::vector<CInsn>&v,std::uint64_t va){auto it=std::lower_bound(v.begin(),v.end(),va,[](const CInsn&a,std::uint64_t b){return a.va<b;});if(it==v.end()||it->va!=va)return{};return static_cast<std::size_t>(it-v.begin());}
bool raw_small_bound(std::span<const std::uint8_t>b){for(std::size_t i=0;i+6<b.size();++i){auto j=i+(b[i]>=0x40&&b[i]<=0x4f?1:0);if(j+2<b.size()&&b[j]==0x83){auto m=b[j+1];if((m>>6)==3&&((m>>3)&7)==7&&b[j+2]>=2&&b[j+2]<=64)return true;}if(j+5<b.size()&&b[j]==0x81){auto m=b[j+1];if((m>>6)==3&&((m>>3)&7)==7){std::uint32_t x=0;std::memcpy(&x,b.data()+j+2,4);if(x>=2&&x<=256)return true;}}}return false;}
std::uint32_t raw_backward_branches(std::span<const std::uint8_t>b){std::uint32_t n=0;for(std::size_t i=0;i<b.size();++i){if(i+5<=b.size()&&b[i]==0xe9){std::int32_t d=0;std::memcpy(&d,b.data()+i+1,4);if(d<-32)++n;}else if(i+6<=b.size()&&b[i]==0x0f&&b[i+1]>=0x80&&b[i+1]<=0x8f){std::int32_t d=0;std::memcpy(&d,b.data()+i+2,4);if(d<-32)++n;}}return n;}
struct PerfProof{bool confirmed=false;std::uint64_t loop_head=0,index_compare=0,early_exit=0,nested_loop=0,back_edge=0;std::uint64_t iterations=0;};
PerfProof detect_perf_compact(const std::vector<CInsn>&v){PerfProof p;for(std::size_t bi=0;bi<v.size();++bi){if(v[bi].mnemonic!=ZYDIS_MNEMONIC_JMP||!v[bi].target_valid||v[bi].target>=v[bi].va)continue;auto head=v[bi].target,span=v[bi].va-head;if(span<128||span>65536)continue;auto hi=cindex_for_va(v,head);if(!hi||bi<=*hi||bi-*hi<128)continue;ZydisRegister idx=ZYDIS_REGISTER_NONE;std::uint64_t bound=0,normal_exit=0;std::size_t cmp_bound=0;
        for(std::size_t j=*hi;j<bi&&j<=*hi+64;++j){const auto&x=v[j];if(x.mnemonic!=ZYDIS_MNEMONIC_CMP||x.op0_type!=ZYDIS_OPERAND_TYPE_REGISTER||x.op1_type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||x.op1_relative||x.op1_imm<2||x.op1_imm>256)continue;for(std::size_t k=j+1;k<bi&&k<=j+2;++k)if(ccond(v[k])&&v[k].target_valid&&(v[k].target>v[bi].va||v[k].target<head)){idx=x.op0_reg;bound=x.op1_imm;normal_exit=v[k].target;cmp_bound=j;break;}if(idx!=ZYDIS_REGISTER_NONE)break;}if(idx==ZYDIS_REGISTER_NONE)continue;
        bool induction=false;ZydisRegister temp=ZYDIS_REGISTER_NONE;auto ib=cmp_bound>12?std::max(*hi,cmp_bound-12):*hi;for(std::size_t j=ib;j<cmp_bound;++j){const auto&x=v[j];if(x.mnemonic==ZYDIS_MNEMONIC_INC&&x.op0_type==ZYDIS_OPERAND_TYPE_REGISTER&&x.op0_reg==idx)induction=true;if((x.mnemonic==ZYDIS_MNEMONIC_ADD||x.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.op0_type==ZYDIS_OPERAND_TYPE_REGISTER&&x.op0_reg==idx&&x.op1_type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&x.op1_imm==1)induction=true;if(x.mnemonic==ZYDIS_MNEMONIC_LEA&&x.op0_type==ZYDIS_OPERAND_TYPE_REGISTER&&x.op1_type==ZYDIS_OPERAND_TYPE_MEMORY&&x.mem1_base==idx&&x.mem1_index==ZYDIS_REGISTER_NONE&&x.mem1_disp&&x.mem1_disp_value==1)temp=x.op0_reg;if(temp!=ZYDIS_REGISTER_NONE&&x.mnemonic==ZYDIS_MNEMONIC_MOV&&x.op0_type==ZYDIS_OPERAND_TYPE_REGISTER&&x.op0_reg==idx&&x.op1_type==ZYDIS_OPERAND_TYPE_REGISTER&&x.op1_reg==temp)induction=true;}if(!induction)continue;
        std::uint64_t early=0,index_cmp=0;for(std::size_t j=*hi;j<cmp_bound;++j){const auto&x=v[j];if(x.mnemonic!=ZYDIS_MNEMONIC_CMP||!creg_mem_index(x,idx))continue;for(std::size_t k=j+1;k<cmp_bound&&k<=j+2;++k)if(ccond(v[k])&&v[k].target_valid&&v[k].target!=normal_exit&&(v[k].target>v[bi].va||v[k].target<head)){early=v[k].target;index_cmp=x.va;break;}if(early)break;}if(!early)continue;
        std::uint64_t nested=0;for(std::size_t j=std::max(*hi,cmp_bound);j<bi;++j){if(!ccond(v[j])&&v[j].mnemonic!=ZYDIS_MNEMONIC_JMP)continue;if(v[j].target_valid&&v[j].target>=head&&v[j].target<v[j].va&&v[j].va-v[j].target>=32){nested=v[j].va;break;}}if(!nested)continue;p.confirmed=true;p.loop_head=head;p.index_compare=index_cmp;p.early_exit=early;p.nested_loop=nested;p.back_edge=v[bi].va;p.iterations=bound;return p;}return p;}
PerfProof detect_elf_variable_work_oracle(std::span<const std::uint8_t>d,const ElfInfo&e,BudgetState&budget){
    std::vector<const ElfUnwindFde*> candidates;std::uint64_t candidate_bytes=0;std::set<std::pair<std::uint64_t,std::uint64_t>>seen;
    for(const auto&f:e.unwind.fdes){if(!f.function_file_backed||f.function_size<128||f.function_size>RuntimeModalityBudgets::max_function_window_bytes||f.function_file_offset>d.size()||f.function_size>d.size()-f.function_file_offset)continue;auto key=std::make_pair(f.function_start_va,f.function_end_va);if(!seen.insert(key).second)continue;auto bytes=d.subspan(static_cast<std::size_t>(f.function_file_offset),static_cast<std::size_t>(f.function_size));if(!raw_small_bound(bytes)||raw_backward_branches(bytes)<2)continue;if(f.function_size>std::numeric_limits<std::uint64_t>::max()-candidate_bytes){budget.hit("perf candidate byte accounting overflow");return{};}candidate_bytes+=f.function_size;candidates.push_back(&f);if(candidates.size()>RuntimeModalityBudgets::max_candidate_functions||candidate_bytes>RuntimeModalityBudgets::max_candidate_function_bytes){budget.hit("perf candidate-function budget exhausted before semantic proof (functions="+std::to_string(candidates.size())+", bytes="+std::to_string(candidate_bytes)+")");return{};}}
    for(const auto*f:candidates){std::vector<CInsn>v;v.reserve(std::min<std::uint64_t>(f->function_size/2+1,RuntimeModalityBudgets::max_retained_compact_records));auto dr=stream_decode(d,e,f->function_start_va,f->function_end_va,RuntimeModalityBudgets::max_instructions_per_window,[&](const XInsn&x){if(v.size()>=RuntimeModalityBudgets::max_retained_compact_records)return false;v.push_back(compact(x));return true;});if(dr.exhausted||(dr.stopped&&v.size()>=RuntimeModalityBudgets::max_retained_compact_records)){budget.hit("perf compact-record/instruction budget exhausted inside candidate function at "+hx(f->function_start_va));continue;}auto p=detect_perf_compact(v);if(p.confirmed)return p;}
    return{};
}
std::uint16_t rd16(const std::uint8_t*p,bool le){return le?std::uint16_t(p[0])|(std::uint16_t(p[1])<<8):std::uint16_t(p[1])|(std::uint16_t(p[0])<<8);}
std::uint16_t rd16be(const std::uint8_t*p){return (std::uint16_t(p[0])<<8)|p[1];}
std::uint32_t rd32(const std::uint8_t*p,bool le){if(le)return std::uint32_t(p[0])|(std::uint32_t(p[1])<<8)|(std::uint32_t(p[2])<<16)|(std::uint32_t(p[3])<<24);return std::uint32_t(p[3])|(std::uint32_t(p[2])<<8)|(std::uint32_t(p[1])<<16)|(std::uint32_t(p[0])<<24);}
std::uint64_t rd64le(const std::uint8_t*p){std::uint64_t v=0;for(unsigned i=0;i<8;++i)v|=std::uint64_t(p[i])<<(i*8);return v;}
bool range_ok(std::size_t off,std::size_t len,std::size_t n){return off<=n&&len<=n-off;}
std::string ascii_utf16le_string(std::span<const std::uint8_t>d,std::uint32_t rva){if(!range_ok(rva,4,d.size()))return{};auto n=rd32(d.data()+rva,true);if(n>4096||!range_ok(std::size_t(rva)+4,n,d.size()))return{};std::string s;s.reserve(n/2);for(std::size_t i=0;i+1<n;i+=2){auto lo=d[rva+4+i],hi=d[rva+4+i+1];s.push_back(hi?('?'):static_cast<char>(lo));}return s;}

struct DumpProbe{bool valid=false,runtime_state=false,network_runtime=false;std::filesystem::path path;std::string image;std::vector<std::pair<std::uint64_t,std::uint64_t>>memory_ranges;std::uint64_t memory_data_rva=0;};
DumpProbe probe_minidump(std::span<const std::uint8_t>d,const std::filesystem::path&p){DumpProbe q;q.path=p;if(d.size()<32||std::memcmp(d.data(),"MDMP",4)!=0)return q;auto n=rd32(d.data()+8,true),dir=rd32(d.data()+12,true);if(n==0||n>1024||!range_ok(dir,std::size_t(n)*12,d.size()))return q;std::map<std::uint32_t,std::pair<std::uint32_t,std::uint32_t>>streams;for(std::uint32_t i=0;i<n;++i){auto b=dir+i*12;auto type=rd32(d.data()+b,true),sz=rd32(d.data()+b+4,true),rva=rd32(d.data()+b+8,true);if(range_ok(rva,sz,d.size()))streams[type]={sz,rva};}
    auto mi=streams.find(4);if(mi==streams.end())return q;auto [msz,mrva]=mi->second;if(msz<4||!range_ok(mrva,4,d.size()))return q;auto mods=rd32(d.data()+mrva,true);const auto module_bytes=std::uint64_t{4}+std::uint64_t(mods)*108;if(!mods||mods>512||module_bytes>msz||!range_ok(mrva,static_cast<std::size_t>(module_bytes),d.size()))return q;for(std::uint32_t i=0;i<mods;++i){auto off=std::size_t(mrva)+4+std::size_t(i)*108;auto name=ascii_utf16le_string(d,rd32(d.data()+off+20,true));if(i==0)q.image=name;auto low=lower_ascii(name);if(low.find("ws2_32.dll")!=std::string::npos||low.find("winhttp.dll")!=std::string::npos||low.find("wininet.dll")!=std::string::npos)q.network_runtime=true;}
    auto m64=streams.find(9);if(m64==streams.end()||m64->second.first<16)return q;auto [m64sz,rva]=m64->second;if(!range_ok(rva,16,d.size()))return q;auto count=rd64le(d.data()+rva),base=rd64le(d.data()+rva+8);if(!count||count>1000000||count>(std::numeric_limits<std::uint64_t>::max()-16)/16)return q;const auto desc_bytes=std::uint64_t{16}+count*16;if(desc_bytes>m64sz||desc_bytes>std::numeric_limits<std::size_t>::max()||!range_ok(rva,static_cast<std::size_t>(desc_bytes),d.size())||base>=d.size())return q;std::uint64_t total=0;for(std::uint64_t i=0;i<count;++i){auto off=std::size_t(rva)+16+std::size_t(i)*16,start=rd64le(d.data()+off),sz=rd64le(d.data()+off+8);if(sz>std::numeric_limits<std::uint64_t>::max()-total)return q;q.memory_ranges.push_back({start,sz});total+=sz;}if(total>d.size()-static_cast<std::size_t>(base))return q;
    q.memory_data_rva=base;q.runtime_state=streams.count(7)&&streams.count(16)&&!q.image.empty()&&!q.memory_ranges.empty();q.valid=q.runtime_state;return q;
}

struct PcapProbe{bool valid=false,http_schema=false;std::filesystem::path path;std::set<std::string>endpoints;std::uint64_t inspected_bytes=0,packets=0;};
bool ascii_packet_has_http(std::span<const std::uint8_t>s){static constexpr std::array<std::string_view,7>m={"GET ","POST ","PUT ","HEAD ","DELETE ","OPTIONS ","HTTP/1."};for(auto x:m)if(std::search(s.begin(),s.end(),x.begin(),x.end())!=s.end())return true;return false;}
std::vector<std::string> http_hosts(std::span<const std::uint8_t>s){
    std::vector<std::string>out;if(!ascii_packet_has_http(s))return out;const std::string_view key="Host:";auto it=s.begin();
    while(it<s.end()){
        it=std::search(it,s.end(),key.begin(),key.end());if(it==s.end())break;auto pos=static_cast<std::size_t>(it-s.begin())+key.size();while(pos<s.size()&&(s[pos]==' '||s[pos]=='\t'))++pos;
        std::string host;while(pos<s.size()&&host.size()<255){char c=static_cast<char>(s[pos]);if(c=='\r'||c=='\n'||c==' '||c=='\t')break;if(!(std::isalnum(static_cast<unsigned char>(c))||c=='.'||c=='-'||c==':'||c=='['||c==']'))break;host.push_back(c);++pos;}
        if(!host.empty())out.push_back(std::move(host));
        it=s.begin()+std::min(pos+1,s.size());
    }
    return out;
}
std::string ipv4_text(const std::uint8_t*p){return std::to_string(p[0])+"."+std::to_string(p[1])+"."+std::to_string(p[2])+"."+std::to_string(p[3]);}
void collect_tcp_http_endpoint(std::span<const std::uint8_t>packet,std::uint16_t linktype,PcapProbe&q){
    if(linktype!=1||packet.size()<14)return;
    std::size_t ip=14;auto eth=rd16be(packet.data()+12);
    if((eth==0x8100||eth==0x88a8)&&packet.size()>=18){eth=rd16be(packet.data()+16);ip=18;}if(eth!=0x0800||packet.size()<ip+20)return;
    const auto ver_ihl=packet[ip];if((ver_ihl>>4)!=4)return;const std::size_t ihl=std::size_t(ver_ihl&0x0f)*4;if(ihl<20||packet.size()<ip+ihl||packet[ip+9]!=6)return;
    if((rd16be(packet.data()+ip+6)&0x3fff)!=0)return;
    const auto src_ip=ipv4_text(packet.data()+ip+12),dst_ip=ipv4_text(packet.data()+ip+16);const std::size_t tcp=ip+ihl;if(packet.size()<tcp+20)return;
    const auto src_port=rd16be(packet.data()+tcp),dst_port=rd16be(packet.data()+tcp+2);const std::size_t thl=std::size_t(packet[tcp+12]>>4)*4;if(thl<20||packet.size()<tcp+thl)return;
    auto payload=packet.subspan(tcp+thl);auto hosts=http_hosts(payload);if(hosts.empty())return;const auto src=src_ip+":"+std::to_string(src_port),dst=dst_ip+":"+std::to_string(dst_port);
    for(auto host:hosts){if(host.find(':')==std::string::npos){if(src_port==80&&host==src_ip)host=src;if(dst_port==80&&host==dst_ip)host=dst;}if(host==src||host==dst){q.endpoints.insert(host);q.http_schema=true;}}
}
PcapProbe probe_pcapng(std::span<const std::uint8_t>d,const std::filesystem::path&p){
    PcapProbe q;q.path=p;if(d.size()<28||rd32(d.data(),true)!=0x0a0d0d0a)return q;std::size_t pos=0;bool le=true,have_shb=false;std::vector<std::uint16_t>linktypes;
    while(pos+12<=d.size()&&pos<kPcapInspectByteCap&&q.packets<kPcapPacketCap){
        auto type=rd32(d.data()+pos,le);if(type==0x0a0d0d0a){if(!range_ok(pos+8,4,d.size()))break;auto bom=rd32(d.data()+pos+8,true);if(bom==0x1a2b3c4d)le=true;else if(bom==0x4d3c2b1a)le=false;else break;have_shb=true;linktypes.clear();type=0x0a0d0d0a;}
        auto len=rd32(d.data()+pos+4,le);if(len<12||len>128ull*1024*1024||!range_ok(pos,len,d.size())||pos+len>kPcapInspectByteCap)break;if(rd32(d.data()+pos+len-4,le)!=len)break;
        if(type==1&&len>=20)linktypes.push_back(rd16(d.data()+pos+8,le));
        else if(type==6&&len>=32){auto iid=rd32(d.data()+pos+8,le),cap=rd32(d.data()+pos+20,le);if(iid<linktypes.size()&&cap<=len-32){auto dataoff=pos+28;collect_tcp_http_endpoint(d.subspan(dataoff,cap),linktypes[iid],q);++q.packets;}}
        q.inspected_bytes=pos+len;pos+=len;
    }
    q.valid=have_shb&&q.packets>0;return q;
}
std::set<std::string> dump_endpoint_hits(std::span<const std::uint8_t>d,const DumpProbe&q,const std::set<std::string>&patterns){std::set<std::string>hits;if(!q.valid||patterns.empty())return hits;std::uint64_t file=q.memory_data_rva,inspected=0;for(const auto&mr:q.memory_ranges){auto take=std::min<std::uint64_t>(mr.second,kDumpMemoryInspectCap-inspected);if(!take)break;if(file>=d.size()||take>d.size()-file)break;auto s=d.subspan(static_cast<std::size_t>(file),static_cast<std::size_t>(take));for(const auto&p:patterns)if(!p.empty()&&std::search(s.begin(),s.end(),p.begin(),p.end())!=s.end())hits.insert(p);file+=mr.second;inspected+=take;if(inspected>=kDumpMemoryInspectCap)break;}return hits;}

const DirectoryRelationship* find_rel(const DirectoryPlan&plan,const std::filesystem::path&a,const std::filesystem::path&b){auto ak=path_key(a),bk=path_key(b);for(const auto&r:plan.relationships)if(r.directed&&r.kind=="elf_loader_dependency"&&r.state=="BOUNDED"&&path_key(r.first)==ak&&path_key(r.second)==bk)return &r;return nullptr;}
bool has_needed(const DirectoryReportIndex&r,const std::string&name){return std::find(r.elf_needed.begin(),r.elf_needed.end(),name)!=r.elf_needed.end();}
void detect_supplied_runtime(const DirectoryPlan&plan,const std::vector<DirectoryReportIndex>&reports,RuntimeModalityGuidance&g){
    for(const auto&root:reports){if(!root.elf_valid||root.elf_interpreter.empty())continue;auto loader_name=basename_ascii(root.elf_interpreter);if(loader_name.empty())continue;for(const auto&libc:reports){if(&libc==&root||!libc.elf_valid||libc.elf_soname.empty()||!has_needed(root,libc.elf_soname)||!find_rel(plan,root.input,libc.input))continue;for(const auto&ld:reports){if(&ld==&root||&ld==&libc||!ld.elf_valid||ld.elf_soname!=loader_name||!has_needed(libc,ld.elf_soname)||!find_rel(plan,libc.input,ld.input))continue;auto r=req("REQUIRES_SUPPLIED_RUNTIME_ENVIRONMENT",0.99,"PT_INTERP_PLUS_EXACT_DT_NEEDED_RELATION_CHAIN","The executable is bound to a supplied dynamic-linker/libc environment by exact ELF metadata; reproduce that environment when runtime behavior is later observed.");r.evidence={"root PT_INTERP basename exactly matches supplied loader DT_SONAME: "+loader_name,"root DT_NEEDED("+libc.elf_soname+") has one BOUNDED in-directory ELF loader relationship to the supplied libc","supplied libc DT_NEEDED("+ld.elf_soname+") has one BOUNDED relationship to that exact loader"};r.negative_evidence={"same-directory filenames alone are not sufficient, and actual runtime loader search/namespace selection remains unobserved"};r.artifacts={root.input,libc.input,ld.input};add_requirement(g,std::move(r));add_unique(g.priority_guidance,"Static reversing is incomplete with respect to loader semantics; if runtime confirmation is needed, use the exact supplied PT_INTERP/DT_NEEDED-linked loader and libc rather than the host defaults. This guidance does not authorize execution.");return;}}}
}
void detect_dump_pcap(const DirectoryPlan&plan,RuntimeModalityGuidance&g){
    for(const auto&dc:plan.candidates){MappedFile dm(dc.path);if(!dm.valid())continue;auto dp=probe_minidump(dm.bytes(),dc.path);if(!dp.valid||!dp.network_runtime)continue;for(const auto&pc:plan.candidates){if(path_key(pc.path)==path_key(dc.path))continue;MappedFile pm(pc.path);if(!pm.valid())continue;auto pp=probe_pcapng(pm.bytes(),pc.path);if(!pp.valid||!pp.http_schema||pp.endpoints.empty())continue;auto hits=dump_endpoint_hits(dm.bytes(),dp,pp.endpoints);if(hits.empty())continue;auto endpoint=*hits.begin();auto m=req("REQUIRES_MEMORY_DUMP_CORRELATION",0.99,"MINIDUMP_IDENTITY_PLUS_RUNTIME_MEMORY_ENDPOINT_MATCH","The decisive state is present in a validated process memory dump and must be correlated in that runtime-state plane before treating carved/static bytes as process truth.");m.evidence={"validated MiniDump contains ModuleList/SystemInfo/MemoryInfo/Memory64 runtime-state streams","dump process image identity: "+dp.image,"a bounded 64 MiB Memory64 scan contains the exact application endpoint also recovered from the PCAP HTTP schema: "+endpoint,"dump module list contains an independent Windows networking runtime module (ws2_32/winhttp/wininet)"};m.negative_evidence={"a .dmp filename or carved executable alone is not decisive; the image/runtime-state and cross-plane endpoint relation are required"};m.artifacts={dc.path,pc.path};add_requirement(g,std::move(m));auto n=req("REQUIRES_NETWORK_SIDECAR_CORRELATION",0.99,"PCAP_TCP_HTTP_ENDPOINT_PLUS_EXACT_RUNTIME_MEMORY_ENDPOINT_MATCH","The packet capture is a separate network observation plane whose HTTP endpoint/schema must be correlated with the runtime memory state.");n.evidence={"validated pcapng Ethernet/IPv4/TCP packet structure with HTTP request/response schema and Host endpoint matching the observed TCP tuple","exact HTTP Host endpoint also exists in bounded dump Memory64 state: "+endpoint,"PCAP inspection is bounded to at most "+std::to_string(kPcapInspectByteCap)+" bytes / "+std::to_string(kPcapPacketCap)+" packets"};n.negative_evidence={"same-directory placement is not evidence","PCAP traffic corroborates network behavior but is not runtime-memory truth and does not replace dump-state validation"};n.artifacts={pc.path,dc.path};add_requirement(g,std::move(n));add_unique(g.priority_guidance,"Static carving is incomplete; inspect the validated memory-dump runtime state and correlate only the exact HTTP endpoint/schema shared with the PCAP. Treat the PCAP as a separate network sidecar, not as memory truth.");return;}}
    }
}

RuntimeModalityGuidance build_runtime_modality_guidance(const AnalysisReport&r){RuntimeModalityGuidance g;BudgetState budget;bool timing_proven=false;
    for(const auto&f:r.findings){auto si=f.fields.find("source_instruction"),cd=f.fields.find("control_dependency_state");if(f.family=="Execution prerequisite"&&f.state=="CONFIRMED"&&si!=f.fields.end()&&si->second=="TIMESTAMP_DELTA"&&cd!=f.fields.end()&&cd->second=="CONFIRMED"){timing_proven=true;auto x=req("REQUIRES_PERF_TIMING_ORACLE",0.98,"TIMESTAMP_DELTA_CONTROL_DEPENDENCY","A proven timestamp delta controls program selection; observing the concrete threshold outcome requires a timing/performance oracle.");x.evidence={"two timestamp sources feed an explicit delta/threshold/selector chain already confirmed by the execution-prerequisite detector"};x.negative_evidence={"timing-related strings or timestamp instruction presence alone do not satisfy this gate"};x.artifacts={r.input};add_requirement(g,std::move(x));auto n=req("REQUIRES_NATIVE_EXECUTION",0.95,"TIMING_ORACLE_REQUIRES_RUNTIME_OBSERVATION","The timing-dependent selector is statically proven, but a concrete timing observation exists only under execution in a controlled native environment.");n.evidence={"the confirmed timestamp-delta prerequisite is an execution-time quantity"};n.negative_evidence={"this is guidance only; it does not set runtime.requested or authorize execution"};n.artifacts={r.input};add_requirement(g,std::move(n));add_unique(g.priority_guidance,"Static evidence proves a timing-dependent control gate; use a real timing/performance observation only if the concrete runtime outcome matters. No execution or perf collection is authorized automatically.");}}
    if(r.elf.valid&&r.elf.elf64&&r.elf.machine==62&&r.input_snapshot.size<=128ull*1024*1024){
        const auto exec_bytes=executable_file_bytes(r.elf);
        if(exec_bytes>RuntimeModalityBudgets::max_executable_bytes_inspected){budget.hit("x86-64 ELF executable-byte budget exceeded before candidate routing (bytes="+std::to_string(exec_bytes)+", max="+std::to_string(RuntimeModalityBudgets::max_executable_bytes_inspected)+")");}
        else{MappedFile mf(r.input);if(mf.valid()){
            auto sm=detect_elf_self_mod(mf.bytes(),r.elf,budget);if(sm.confirmed){auto x=req("REQUIRES_SELF_MODIFYING_STATE",0.99,"RWX_PROTECTION_TO_EXECUTABLE_WRITE_TO_LATER_TRANSFER","Static control flow proves a path that makes code writable+executable, writes through an address derived from that executable region, and later transfers control through a derived address; post-write state is the required observation plane.");x.evidence={"mprotect call at "+hx(sm.mprotect_va)+" receives write+execute protection and an address derived from executable code","direct protected code target is entered at "+hx(sm.target_va),"a code-derived store occurs at "+hx(sm.store_va),"a later code-derived PUSH/RET transfer occurs at "+hx(sm.transfer_va)};x.negative_evidence={"mprotect/VirtualProtect import presence alone is insufficient; this requirement is emitted only after bounded causal address-flow closure"};x.artifacts={r.input};add_requirement(g,std::move(x));auto y=req("REQUIRES_FIRST_EXECUTION_MATERIALIZATION",0.97,"POST_WRITE_EXECUTABLE_BYTES_BEFORE_TRANSFER","The first execution of bytes after the proven executable-region write is semantically distinct from the on-disk image and should be materialized/observed if dynamic confirmation is performed.");y.evidence={"write-to-executable-region and later execution are both statically linked in one bounded causal chain"};y.negative_evidence={"static evidence establishes the need for post-write observation, not the concrete bytes produced at runtime"};y.artifacts={r.input};add_requirement(g,std::move(y));add_unique(g.priority_guidance,"Static reversing is incomplete across the self-modifying boundary; inspect the post-write executable bytes and their first execution. Do not infer those bytes from the original file, and do not auto-run the target.");}
            if(!timing_proven){auto pf=detect_elf_variable_work_oracle(mf.bytes(),r.elf,budget);if(pf.confirmed){auto x=req("REQUIRES_PERF_TIMING_ORACLE",0.97,"VARIABLE_WORK_PREFIX_LOOP_WITH_EARLY_INDEXED_EXIT","A bounded loop has an indexed comparison that can exit before a large nested-work body; repeated work/instruction-count observations can therefore reveal prefix progress that static one-shot output does not expose.");x.evidence={"bounded outer loop head "+hx(pf.loop_head)+" with iteration bound "+std::to_string(pf.iterations),"indexed compare at "+hx(pf.index_compare)+" has a distinct early exit","large loop body contains a nested backward work loop at "+hx(pf.nested_loop)+" and outer back-edge at "+hx(pf.back_edge)};x.negative_evidence={"the detector does not consult debug symbols, strings, or words such as perf/timing; instruction/control geometry is required"};x.artifacts={r.input};add_requirement(g,std::move(x));auto y=req("REQUIRES_NATIVE_EXECUTION",0.94,"PERF_ORACLE_REQUIRES_REPEATED_NATIVE_OBSERVATION","The proven variable-work oracle is meaningful only under repeated execution with a controlled performance/timing observation plane.");y.evidence={"static analysis establishes variable work, but not the measured counter values for candidate inputs"};y.negative_evidence={"this requirement is guidance only and does not grant runtime permission"};y.artifacts={r.input};add_requirement(g,std::move(y));add_unique(g.priority_guidance,"Static reversing identifies a variable-work prefix oracle; if exploiting it, use repeated isolated native executions with a real instruction-count/perf or timing observation. Strings alone never trigger this route, and execution remains opt-in.");}}
        }}
    }
    finish_guidance(g,&budget);return g;}

RuntimeModalityGuidance build_directory_runtime_modality_guidance(const DirectoryPlan&plan,const std::vector<DirectoryReportIndex>&reports){RuntimeModalityGuidance g;detect_supplied_runtime(plan,reports,g);detect_dump_pcap(plan,g);finish_guidance(g);return g;}
}
