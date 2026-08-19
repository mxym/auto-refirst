#include "prts/exception_flow.hpp"
#include "prts/pe.hpp"
#include "prts/elf.hpp"
#include "prts/dwarf_expression_surface.hpp"
extern "C" {
#include "Zydis.h"
}

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>

namespace prts {
namespace {
std::string csvq(const std::string& s) {
    std::string out(1, '"');
    for (const auto c : s) out += c == '"' ? "\"\"" : std::string(1, c);
    out += '"';
    return out;
}

const char* space_name(CoordinateSpace s) {
    switch (s) {
    case CoordinateSpace::FILE_OFFSET: return "FILE_OFFSET";
    case CoordinateSpace::RVA: return "RVA";
    case CoordinateSpace::VA: return "VA";
    case CoordinateSpace::SERIALIZED_OFFSET: return "SERIALIZED_OFFSET";
    case CoordinateSpace::MEMORY_REGION_RELATIVE: return "MEMORY_REGION_RELATIVE";
    case CoordinateSpace::TOKEN: return "TOKEN";
    case CoordinateSpace::INDEX: return "INDEX";
    default: return "UNKNOWN";
    }
}
const char* basis_name(CoordinateBasis b) {
    switch (b) {
    case CoordinateBasis::CURRENT_INPUT_FILE: return "CURRENT_INPUT_FILE";
    case CoordinateBasis::CURRENT_INPUT_IMAGE: return "CURRENT_INPUT_IMAGE";
    case CoordinateBasis::ARTIFACT_FILE: return "ARTIFACT_FILE";
    case CoordinateBasis::ARTIFACT_IMAGE: return "ARTIFACT_IMAGE";
    case CoordinateBasis::PROCESS_IMAGE: return "PROCESS_IMAGE";
    case CoordinateBasis::MEMORY_REGION: return "MEMORY_REGION";
    default: return "UNKNOWN";
    }
}

void range_header(std::ofstream& f, const char* p) {
    f << p << "_value," << p << "_size," << p << "_coordinate_space," << p << "_basis,"
      << p << "_artifact_identity," << p << "_process_uid," << p << "_image_base," << p << "_label";
}
void range_row(std::ofstream& f, const std::optional<RangeRef>& r) {
    if (!r) { f << ",,,,,,,"; return; }
    f << "0x" << std::hex << r->offset << std::dec << ',' << r->size << ','
      << csvq(space_name(r->coordinate_space)) << ',' << csvq(basis_name(r->basis)) << ','
      << csvq(r->artifact_identity) << ',';
    if (r->process_uid) f << *r->process_uid;
    f << ',';
    if (r->image_base) f << "0x" << std::hex << *r->image_base << std::dec;
    f << ',' << csvq(r->label);
}

struct PeDecoded {
    std::uint32_t rva=0;
    ZydisDecodedInstruction ins{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{};
};
struct PeFuncRange { std::uint32_t begin=0,end=0; };
struct PeApiCall {
    std::string module,name,transfer;
    std::uint32_t callsite=0,func_begin=0,func_end=0,iat_rva=0,instruction_size=0;
    bool call=true;
};

ZydisRegister pe_large(ZydisRegister r) {
    return r==ZYDIS_REGISTER_NONE ? r : ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);
}
std::optional<std::size_t> pe_rva_off(const PeInfo& pe,std::uint32_t rva,std::size_t n) {
    if(rva<pe.headers_size&&rva<n)return std::size_t(rva);
    for(const auto&s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva<s.rva||std::uint64_t(rva)>=std::uint64_t(s.rva)+span)continue;
        const auto delta=std::uint64_t(rva)-s.rva;
        if(delta>=s.raw_size)return{};
        const auto off=std::uint64_t(s.raw_offset)+delta;
        if(off<n)return static_cast<std::size_t>(off);
    }
    return{};
}
bool pe_executable_rva(const PeInfo& pe,std::uint32_t rva) {
    for(const auto&s:pe.sections){
        if((s.characteristics&0x20000000u)==0)continue;
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span)return true;
    }
    return false;
}
PeFuncRange pe_runtime_func(const PeInfo& pe,std::uint32_t rva) {
    for(const auto&f:pe.exception.runtime_functions)if(f.begin_rva<=rva&&rva<f.end_rva)return{f.begin_rva,f.end_rva};
    return{};
}
std::vector<PeDecoded> pe_decode_range(std::span<const std::uint8_t>d,const PeInfo&pe,PeFuncRange f) {
    std::vector<PeDecoded> out;
    if(!f.end||f.end<=f.begin||f.end-f.begin>(1u<<20))return out;
    ZydisDecoder dec;
    if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return out;
    auto cur=f.begin;
    while(cur<f.end&&out.size()<8192){
        const auto o=pe_rva_off(pe,cur,d.size());
        if(!o||*o>=d.size())break;
        PeDecoded x;x.rva=cur;
        const auto avail=std::min<std::size_t>({ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*o,std::size_t(f.end-cur)});
        if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*o,avail,&x.ins,x.ops.data()))||!x.ins.length)break;
        out.push_back(x);cur+=x.ins.length;
    }
    if(cur!=f.end)out.clear();
    return out;
}
std::optional<PeDecoded> pe_decode_one(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva) {
    const auto o=pe_rva_off(pe,rva,d.size());if(!o||*o>=d.size())return{};
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return{};
    PeDecoded x;x.rva=rva;const auto avail=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*o);
    if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*o,avail,&x.ins,x.ops.data()))||!x.ins.length)return{};
    return x;
}
std::optional<std::uint32_t> pe_rel_target(const PeDecoded&x) {
    if(!x.ins.operand_count_visible)return{};
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||!o.imm.is_relative)continue;
        const auto t=std::int64_t(x.rva+x.ins.length)+o.imm.value.s;
        if(t<0||t>0xffffffffll)return{};
        return static_cast<std::uint32_t>(t);
    }
    return{};
}
std::optional<std::uint32_t> pe_rip_mem_rva(const PeDecoded&x,const ZydisDecodedOperand&o) {
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||pe_large(o.mem.base)!=ZYDIS_REGISTER_RIP)return{};
    const auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;
    const auto t=std::int64_t(x.rva+x.ins.length)+disp;
    if(t<0||t>0xffffffffll)return{};
    return static_cast<std::uint32_t>(t);
}
RangeRef pe_rva_ref(std::uint64_t rva,std::uint64_t size,std::string label,const std::string&artifact) {
    return typed_range(rva,size,std::move(label),CoordinateSpace::RVA,CoordinateBasis::CURRENT_INPUT_IMAGE,artifact);
}
void exceptional_add(ExceptionalExecutionInfo&out,ExceptionalExecutionFact f) {
    constexpr std::size_t max_facts=65536;
    if(out.facts.size()>=max_facts){out.analysis_limited=true;if(out.error.empty())out.error="exceptional execution fact budget exceeded";return;}
    // Keep the X ladder deterministic for pre-AI producers while allowing
    // mechanism-specific code to override it when it closes a stronger tier.
    if(f.evidence_level.empty()) {
        if(f.evidence_state=="SEMANTIC_EXCEPTION_CLOSURE") f.evidence_level="X5";
        else if(f.evidence_state=="CONTEXT_PC_REWRITE_CONFIRMED"||f.evidence_state=="HANDLER_OUTCOME_EXACT") f.evidence_level="X4";
        else if(f.evidence_state=="TRIGGER_HANDLER_CORRELATED") f.evidence_level="X3";
        else if(f.evidence_state=="TRIGGER_PROVEN") f.evidence_level="X2";
        else if(f.evidence_state=="REGISTRATION_HANDLER_EXACT") f.evidence_level="X1";
        else f.evidence_level="X0";
    }
    if(f.proof_plane.empty()) f.proof_plane="STATIC_PROVEN";
    f.index=static_cast<std::uint32_t>(out.facts.size());
    if(f.priority=="HIGH")++out.high_priority_count;else if(f.priority=="REVIEW")++out.review_count;else ++out.informational_count;
    out.facts.push_back(std::move(f));
}
void exceptional_finish(ExceptionalExecutionInfo&out) {
    if(!out.facts.empty())out.state=out.analysis_limited?"PARTIAL":"RESOLVED";
    else if(out.analysis_limited)out.state="PARTIAL";
    else out.state="NOT_PRESENT";
}
std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();}

bool pe_interesting_exception_api(std::string_view n) {
    return n=="AddVectoredExceptionHandler"||n=="RemoveVectoredExceptionHandler"||
           n=="SetUnhandledExceptionFilter"||n=="RaiseException"||n=="SetThreadContext";
}
std::vector<PeApiCall> pe_api_calls(std::span<const std::uint8_t>d,const PeInfo&pe) {
    std::vector<PeApiCall>out;
    if(!pe.valid||!pe.pe64||pe.machine!=0x8664)return out;
    std::map<std::uint32_t,std::pair<std::string,std::string>>iat;
    for(const auto&m:pe.imports)for(std::size_t i=0;i<m.functions.size();++i){
        const auto&fn=m.functions[i];if(fn.by_ordinal||!pe_interesting_exception_api(fn.name))continue;
        iat[m.iat_rva+static_cast<std::uint32_t>(i)*8]={m.name,fn.name};
    }
    if(iat.empty())return out;

    // scale repair: retain only the compact thunk map.  The old
    // implementation stored every decoded RuntimeFunction simultaneously, which
    // amplified UnityPlayer-class images into multi-GiB RSS.  Decode one bounded
    // function at a time, discard it, then perform the call pass the same way.
    std::map<std::uint32_t,std::uint32_t>thunks;
    for(const auto&rf:pe.exception.runtime_functions){
        const auto ins=pe_decode_range(d,pe,{rf.begin_rva,rf.end_rva});if(ins.empty())continue;
        for(const auto&x:ins){
            if(x.ins.meta.category!=ZYDIS_CATEGORY_UNCOND_BR||!x.ins.operand_count_visible)continue;
            const auto&q=x.ops[0];auto slot=pe_rip_mem_rva(x,q);if(slot&&iat.count(*slot))thunks[x.rva]=*slot;
        }
    }

    std::set<std::uint32_t>seen;
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    for(const auto&rf:pe.exception.runtime_functions){
        const auto ins=pe_decode_range(d,pe,{rf.begin_rva,rf.end_rva});if(ins.empty())continue;
        std::map<ZydisRegister,std::uint32_t>aliases;
        for(const auto&x:ins){
            bool emitted_call=false;
            if((x.ins.meta.category==ZYDIS_CATEGORY_CALL||x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR)&&x.ins.operand_count_visible){
                const auto&q=x.ops[0];std::uint32_t slot=0;std::string transfer;
                if(auto r=pe_rip_mem_rva(x,q);r&&iat.count(*r)){slot=*r;transfer=x.ins.meta.category==ZYDIS_CATEGORY_CALL?"call_iat":"tail_jmp_iat";}
                else if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&q.imm.is_relative){if(auto t=pe_rel_target(x);t){auto z=thunks.find(*t);if(z!=thunks.end()){slot=z->second;transfer=x.ins.meta.category==ZYDIS_CATEGORY_CALL?"call_thunk":"tail_jmp_thunk";}}}
                else if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&q.type==ZYDIS_OPERAND_TYPE_REGISTER){auto z=aliases.find(pe_large(q.reg.value));if(z!=aliases.end()){slot=z->second;transfer="call_iat_register";}}
                if(slot&&seen.insert(x.rva).second){const auto&nm=iat.at(slot);out.push_back({nm.first,nm.second,transfer,x.rva,rf.begin_rva,rf.end_rva,slot,x.ins.length,x.ins.meta.category==ZYDIS_CATEGORY_CALL});emitted_call=x.ins.meta.category==ZYDIS_CATEGORY_CALL;}
            }
            if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
                const auto dst=pe_large(x.ops[0].reg.value);std::optional<std::uint32_t>v;
                if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){auto z=aliases.find(pe_large(q.reg.value));if(z!=aliases.end())v=z->second;}else if(auto r=pe_rip_mem_rva(x,q);r&&iat.count(*r))v=*r;}
                if(v)aliases[dst]=*v;else aliases.erase(dst);
            }
            if(emitted_call){
                for(auto it=aliases.begin();it!=aliases.end();){if(volatile_reg(it->first))it=aliases.erase(it);else ++it;}
            }
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return std::tie(a.func_begin,a.callsite)<std::tie(b.func_begin,b.callsite);});
    return out;
}
std::vector<PeApiCall> pe_exception_calls(std::span<const std::uint8_t>d,const PeInfo&pe) {return pe_api_calls(d,pe);}

std::optional<std::uint32_t> pe_pointer_arg(std::span<const std::uint8_t>d,const PeInfo&pe,const PeApiCall&c,int arg) {
    if(arg<0||arg>3||!c.func_end)return{};
    const auto ins=pe_decode_range(d,pe,{c.func_begin,c.func_end});if(ins.empty())return{};
    auto cur=pe_large(std::array<ZydisRegister,4>{ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9}[arg]);
    std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].rva==c.callsite){at=i;break;}if(at==ins.size())return{};
    std::int64_t add=0;std::size_t seen=0;
    for(std::size_t z=at;z-->0&&seen++<128;){
        const auto&x=ins[z];
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&(cur==ZYDIS_REGISTER_RAX||cur==ZYDIS_REGISTER_RCX||cur==ZYDIS_REGISTER_RDX||cur==ZYDIS_REGISTER_R8||cur==ZYDIS_REGISTER_R9||cur==ZYDIS_REGISTER_R10||cur==ZYDIS_REGISTER_R11))return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&q=x.ops[1];
            if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(q.reg.value);continue;}
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative){auto va=q.imm.value.u;if(x.ops[0].size==64&&q.size==32)va=static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(va)));const auto v=static_cast<std::int64_t>(va)+add;if(v<0||static_cast<std::uint64_t>(v)<pe.image_base||static_cast<std::uint64_t>(v)-pe.image_base>0xffffffffull)return{};return static_cast<std::uint32_t>(static_cast<std::uint64_t>(v)-pe.image_base);}
            if(auto slot=pe_rip_mem_rva(x,q);slot){const auto off=pe_rva_off(pe,*slot,d.size());if(!off||*off+8>d.size())return{};std::uint64_t va=0;std::memcpy(&va,d.data()+*off,8);const auto v=static_cast<std::int64_t>(va)+add;if(v<0||static_cast<std::uint64_t>(v)<pe.image_base||static_cast<std::uint64_t>(v)-pe.image_base>0xffffffffull)return{};return static_cast<std::uint32_t>(static_cast<std::uint64_t>(v)-pe.image_base);}
            return{};
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){
            const auto&m=x.ops[1].mem;if(m.index!=ZYDIS_REGISTER_NONE)return{};const auto disp=m.disp.has_displacement?m.disp.value:0;
            if(pe_large(m.base)==ZYDIS_REGISTER_RIP){const auto r=std::int64_t(x.rva+x.ins.length)+disp+add;if(r<0||r>0xffffffffll)return{};return static_cast<std::uint32_t>(r);}
            if(m.base!=ZYDIS_REGISTER_NONE){cur=pe_large(m.base);add+=disp;continue;}return{};
        }
        if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative){const auto v=x.ops[1].imm.value.s;add+=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?v:-v;continue;}
        return{};
    }
    return{};
}

std::optional<std::uint64_t> pe_scalar_arg(std::span<const std::uint8_t>d,const PeInfo&pe,const PeApiCall&c,int arg) {
    if(arg<0||arg>3||!c.func_end)return{};
    const auto ins=pe_decode_range(d,pe,{c.func_begin,c.func_end});if(ins.empty())return{};
    auto cur=pe_large(std::array<ZydisRegister,4>{ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9}[arg]);
    std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].rva==c.callsite){at=i;break;}if(at==ins.size())return{};
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    std::size_t seen=0;for(std::size_t z=at;z-->0&&seen++<128;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&volatile_reg(cur))return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(q.reg.value);continue;}if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)return q.imm.value.u;return{};}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_XOR&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(x.ops[1].reg.value)==cur)return 0;
        return{};
    }return{};
}

struct PeCfg {
    std::vector<PeDecoded> ins;
    std::map<std::uint32_t,std::size_t> by_rva;
    std::vector<std::vector<std::size_t>> edges;
};
PeCfg pe_cfg(std::span<const std::uint8_t>d,const PeInfo&pe,PeFuncRange f) {
    PeCfg g;g.ins=pe_decode_range(d,pe,f);g.edges.resize(g.ins.size());for(std::size_t i=0;i<g.ins.size();++i)g.by_rva[g.ins[i].rva]=i;
    auto edge=[&](std::size_t a,std::uint32_t r){auto it=g.by_rva.find(r);if(it!=g.by_rva.end())g.edges[a].push_back(it->second);};
    for(std::size_t i=0;i<g.ins.size();++i){const auto&x=g.ins[i];const auto fall=i+1<g.ins.size()?std::optional<std::uint32_t>(g.ins[i+1].rva):std::nullopt;
        if(x.ins.meta.category==ZYDIS_CATEGORY_RET)continue;
        if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR){if(auto t=pe_rel_target(x))edge(i,*t);continue;}
        if(x.ins.meta.category==ZYDIS_CATEGORY_COND_BR){if(auto t=pe_rel_target(x))edge(i,*t);if(fall)edge(i,*fall);continue;}
        if(fall)edge(i,*fall);
    }
    return g;
}
bool pe_reachable(const PeCfg&g,std::size_t start,std::size_t goal,std::optional<std::size_t>blocked={}) {
    if(start>=g.ins.size()||goal>=g.ins.size()||blocked==start)return false;
    std::vector<std::uint8_t>seen(g.ins.size());std::vector<std::size_t>q{start};seen[start]=1;
    for(std::size_t p=0;p<q.size();++p){const auto u=q[p];if(u==goal)return true;for(const auto v:g.edges[u])if(!seen[v]&&(!blocked||v!=*blocked)){seen[v]=1;q.push_back(v);}}
    return false;
}
bool pe_dominates(const PeCfg&g,std::size_t dom,std::size_t node) {
    if(g.ins.empty()||dom>=g.ins.size()||node>=g.ins.size()||!pe_reachable(g,0,node))return false;
    if(dom==0)return true;
    return !pe_reachable(g,0,node,dom);
}
bool pe_barrier_between(const PeCfg&g,std::size_t reg,std::size_t trigger,const std::set<std::uint32_t>&barriers) {
    for(const auto r:barriers){auto it=g.by_rva.find(r);if(it==g.by_rva.end())continue;const auto b=it->second;if(pe_reachable(g,reg,b)&&pe_reachable(g,b,trigger))return true;}
    return false;
}
std::string pe_trap_kind(const PeDecoded&x) {
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_INT3)return "INT3_BREAKPOINT";
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_INT1)return "INT1_ICEBP";
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_UD2)return "UD2_ILLEGAL_INSTRUCTION";
    if(x.ins.mnemonic==ZYDIS_MNEMONIC_INT&&x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&x.ops[0].imm.value.u==0x2d)return "INT2D_DEBUG_EXCEPTION";
    return{};
}

struct PeUnwindHandler { std::uint32_t handler_rva=0;std::uint32_t unwind_rva=0;std::uint8_t flags=0;std::uint32_t chain_hops=0; };
std::optional<PeUnwindHandler> pe_unwind_handler(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t unwind,std::string&error) {
    std::set<std::uint32_t>seen;
    for(std::uint32_t hop=0;hop<8;++hop){
        if(!unwind||!seen.insert(unwind).second){error="cyclic/null chained UNWIND_INFO";return{};}
        const auto o=pe_rva_off(pe,unwind,d.size());if(!o||*o+4>d.size()){error="UNWIND_INFO header is not file-backed";return{};}
        const auto vf=d[*o];
        const auto version=static_cast<unsigned>(vf&7u);
        const auto flags=static_cast<std::uint8_t>(vf>>3);
        const auto count=d[*o+2];
        if(version!=1&&version!=2){error="unsupported UNWIND_INFO version";return{};}
        std::size_t extra=4+std::size_t(count)*2;extra=(extra+3)&~std::size_t(3);if(extra>d.size()-*o){error="truncated UNWIND_INFO codes";return{};}
        if(flags&4u){if((flags&3u)!=0||extra+12>d.size()-*o){error="malformed chained UNWIND_INFO";return{};}std::uint32_t chained=0;std::memcpy(&chained,d.data()+*o+extra+8,4);unwind=chained;continue;}
        if(flags&3u){if(extra+4>d.size()-*o){error="truncated UNWIND_INFO handler RVA";return{};}std::uint32_t handler=0;std::memcpy(&handler,d.data()+*o+extra,4);if(!handler){error="null UNWIND_INFO handler RVA";return{};}return PeUnwindHandler{handler,unwind,flags,hop};}
        return{};
    }
    error="UNWIND_INFO chain depth exceeds limit";return{};
}

struct ElfDecoded {
    std::uint64_t va=0;
    ZydisDecodedInstruction ins{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{};
};
struct ElfFuncRange { std::uint64_t begin=0,end=0; };
struct ElfApiCall {
    std::string name;
    std::uint64_t callsite=0,func_begin=0,func_end=0,instruction_size=0;
};

std::optional<std::pair<std::uint64_t,std::uint64_t>> elf_va_extent(const ElfInfo&elf,std::uint64_t va) {
    for(const auto&s:elf.segments){
        if(s.type!=1||va<s.address||va-s.address>=s.file_size)continue;
        const auto delta=va-s.address;
        return std::pair<std::uint64_t,std::uint64_t>{s.offset+delta,s.file_size-delta};
    }
    return{};
}
std::optional<std::size_t> elf_va_off(const ElfInfo&elf,std::uint64_t va,std::size_t n) {
    auto ex=elf_va_extent(elf,va);if(!ex||ex->first>=n)return{};return static_cast<std::size_t>(ex->first);
}
bool elf_exec_va(const ElfInfo&elf,std::uint64_t va,std::uint64_t size=1) {
    if(!size)return false;
    for(const auto&s:elf.segments){
        if(s.type!=1||(s.flags&1u)==0||va<s.address)continue;
        const auto delta=va-s.address;
        if(delta<=s.memory_size&&size<=s.memory_size-delta)return true;
    }
    return false;
}
RangeRef elf_va_ref(std::uint64_t va,std::uint64_t size,std::string label,const std::string&artifact) {
    return typed_range(va,size,std::move(label),CoordinateSpace::VA,CoordinateBasis::CURRENT_INPUT_IMAGE,artifact);
}
const ElfUnwindFde* elf_fde_func(const ElfInfo&elf,std::uint64_t va) {
    for(const auto&f:elf.unwind.fdes)if(f.function_start_va<=va&&va<f.function_end_va)return &f;
    return nullptr;
}
std::vector<ElfDecoded> elf_decode_range(std::span<const std::uint8_t>d,const ElfInfo&elf,ElfFuncRange f) {
    std::vector<ElfDecoded>out;
    if(!f.end||f.end<=f.begin||f.end-f.begin>(1u<<20))return out;
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return out;
    auto cur=f.begin;
    while(cur<f.end&&out.size()<8192){
        const auto o=elf_va_off(elf,cur,d.size());if(!o||*o>=d.size())break;
        ElfDecoded x;x.va=cur;const auto avail=std::min<std::size_t>({ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*o,std::size_t(f.end-cur)});
        if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*o,avail,&x.ins,x.ops.data()))||!x.ins.length)break;
        out.push_back(x);cur+=x.ins.length;
    }
    if(cur!=f.end)out.clear();
    return out;
}
std::optional<ElfDecoded> elf_decode_one(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t va) {
    const auto o=elf_va_off(elf,va,d.size());if(!o||*o>=d.size())return{};
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return{};
    ElfDecoded x;x.va=va;const auto avail=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*o);
    if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*o,avail,&x.ins,x.ops.data()))||!x.ins.length)return{};
    return x;
}
std::optional<std::uint64_t> add_signed_u64(std::uint64_t base,std::int64_t delta) {
    if(delta>=0){const auto u=static_cast<std::uint64_t>(delta);if(base>std::numeric_limits<std::uint64_t>::max()-u)return{};return base+u;}
    const auto mag=static_cast<std::uint64_t>(-(delta+1))+1;if(base<mag)return{};return base-mag;
}
bool add_signed_i64(std::int64_t&base,std::int64_t delta) {
    if(delta>0&&base>std::numeric_limits<std::int64_t>::max()-delta)return false;
    if(delta<0&&base<std::numeric_limits<std::int64_t>::min()-delta)return false;
    base+=delta;return true;
}
std::optional<std::uint64_t> elf_rel_target(const ElfDecoded&x) {
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];if(o.type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||!o.imm.is_relative)continue;
        if(x.va>std::numeric_limits<std::uint64_t>::max()-x.ins.length)return{};
        return add_signed_u64(x.va+x.ins.length,o.imm.value.s);
    }
    return{};
}
std::optional<std::uint64_t> elf_rip_mem_va(const ElfDecoded&x,const ZydisDecodedOperand&o) {
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||pe_large(o.mem.base)!=ZYDIS_REGISTER_RIP)return{};
    if(x.va>std::numeric_limits<std::uint64_t>::max()-x.ins.length)return{};
    const auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;
    return add_signed_u64(x.va+x.ins.length,disp);
}
bool elf_exception_api(std::string_view n) {
    return n=="sigaction"||n=="signal"||n=="raise"||n=="kill"||n=="tgkill"||n=="getpid"||n=="gettid";
}
bool elf_has_signal_registration_import(const ElfInfo&elf) {
    if(elf.dynamic.state!="RESOLVED")return false;
    for(const auto&s:elf.dynamic.symbols)if(s.imported&&(s.name=="sigaction"||s.name=="signal"))return true;
    return false;
}
bool elf_has_exec_syscall_candidate(std::span<const std::uint8_t>d,const ElfInfo&elf) {
    constexpr std::uint64_t max_scan=32ull*1024*1024;
    std::uint64_t scanned=0;
    for(const auto&s:elf.segments){
        if(s.type!=1||(s.flags&1u)==0||!s.file_size||s.offset>=d.size())continue;
        const auto n=std::min<std::uint64_t>(s.file_size,d.size()-static_cast<std::size_t>(s.offset));
        if(scanned>=max_scan)return true; // conservative routing only; exact analyzer still decides claims
        const auto take=std::min<std::uint64_t>(n,max_scan-scanned);
        const auto begin=static_cast<std::size_t>(s.offset),end=begin+static_cast<std::size_t>(take);
        for(std::size_t i=begin;i+1<end;++i)if(d[i]==0x0f&&d[i+1]==0x05)return true;
        scanned+=take;
        if(take<n)return true; // do not use the routing cap as negative evidence
    }
    return false;
}
std::map<std::uint64_t,std::string> elf_exception_got(const ElfInfo&elf) {
    std::map<std::uint64_t,std::string>out;if(elf.dynamic.state!="RESOLVED")return out;
    for(const auto&r:elf.dynamic.relocations){if(r.symbol_index>=elf.dynamic.symbols.size())continue;const auto&s=elf.dynamic.symbols[r.symbol_index];if(!s.imported||!elf_exception_api(s.name))continue;out.emplace(r.target_va,s.name);}
    return out;
}
std::optional<std::string> elf_plt_name(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t va,const std::map<std::uint64_t,std::string>&got) {
    // Accept only the canonical PLT stub shape: an optional ENDBR64/NOP then a
    // RIP-relative unconditional jump through a loader relocation slot.
    for(unsigned step=0;step<2;++step){auto x=elf_decode_one(d,elf,va);if(!x)return{};
        if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR&&x->ins.operand_count_visible){auto slot=elf_rip_mem_va(*x,x->ops[0]);if(slot){auto it=got.find(*slot);if(it!=got.end())return it->second;}return{};}
        if(x->ins.mnemonic!=ZYDIS_MNEMONIC_ENDBR64&&x->ins.mnemonic!=ZYDIS_MNEMONIC_NOP)return{};
        va+=x->ins.length;
    }
    return{};
}
std::vector<ElfApiCall> elf_exception_calls(std::span<const std::uint8_t>d,const ElfInfo&elf) {
    std::vector<ElfApiCall>out;if(!elf.valid||!elf.elf64||!elf.little_endian||elf.machine!=62)return out;const auto got=elf_exception_got(elf);if(got.empty())return out;
    std::set<std::uint64_t>seen;
    for(const auto&f:elf.unwind.fdes){if(!f.function_file_backed||!f.function_size)continue;auto ins=elf_decode_range(d,elf,{f.function_start_va,f.function_end_va});if(ins.empty())continue;
        for(const auto&x:ins){if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||!x.ins.operand_count_visible)continue;std::optional<std::string>name;const auto&o=x.ops[0];
            if(auto slot=elf_rip_mem_va(x,o);slot){auto it=got.find(*slot);if(it!=got.end())name=it->second;}
            else if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){if(auto t=elf_rel_target(x))name=elf_plt_name(d,elf,*t,got);}
            if(name&&seen.insert(x.va).second)out.push_back({*name,x.va,f.function_start_va,f.function_end_va,x.ins.length});
        }
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return std::tie(a.func_begin,a.callsite)<std::tie(b.func_begin,b.callsite);});return out;
}
std::optional<std::uint64_t> elf_scalar_arg(std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfApiCall&c,int arg) {
    if(arg<0||arg>5)return{};
    const auto ins=elf_decode_range(d,elf,{c.func_begin,c.func_end});if(ins.empty())return{};
    auto cur=pe_large(std::array<ZydisRegister,6>{ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9}[arg]);std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==c.callsite){at=i;break;}if(at==ins.size())return{};
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_RSI||r==ZYDIS_REGISTER_RDI||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    std::size_t seen=0;for(std::size_t z=at;z-->0&&seen++<128;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&volatile_reg(cur))return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(q.reg.value);continue;}if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)return q.imm.value.u;}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_XOR&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(x.ops[1].reg.value)==cur)return 0;
        return{};
    }return{};
}
std::optional<std::uint64_t> elf_pointer_arg(std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfApiCall&c,int arg) {
    if(arg<0||arg>5)return{};
    const auto ins=elf_decode_range(d,elf,{c.func_begin,c.func_end});if(ins.empty())return{};
    auto cur=pe_large(std::array<ZydisRegister,6>{ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9}[arg]);std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==c.callsite){at=i;break;}if(at==ins.size())return{};
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_RSI||r==ZYDIS_REGISTER_RDI||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    std::int64_t add=0;std::size_t seen=0;for(std::size_t z=at;z-->0&&seen++<128;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&volatile_reg(cur))return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(q.reg.value);continue;}if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)return add_signed_u64(q.imm.value.u,add);return{};}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){const auto&m=x.ops[1].mem;if(m.index!=ZYDIS_REGISTER_NONE)return{};const auto disp=m.disp.has_displacement?m.disp.value:0;
            if(pe_large(m.base)==ZYDIS_REGISTER_RIP){if(x.va>std::numeric_limits<std::uint64_t>::max()-x.ins.length)return{};auto v=add_signed_u64(x.va+x.ins.length,disp);if(!v)return{};return add_signed_u64(*v,add);}
            if(m.base!=ZYDIS_REGISTER_NONE){cur=pe_large(m.base);if(!add_signed_i64(add,disp))return{};continue;}return{};}
        if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative){auto v=x.ops[1].imm.value.s;if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB){if(v==std::numeric_limits<std::int64_t>::min())return{};v=-v;}if(!add_signed_i64(add,v))return{};continue;}return{};
    }return{};
}
std::optional<std::uint64_t> elf_file_pointer_value(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t slot) {
    auto o=elf_va_off(elf,slot,d.size());if(!o||*o+8>d.size())return{};std::uint64_t raw=0;std::memcpy(&raw,d.data()+*o,8);if(elf_exec_va(elf,raw))return raw;
    if((elf.machine==62||elf.machine==183)&&elf.dynamic.state=="RESOLVED")for(const auto&r:elf.dynamic.relocations){const bool relative=(elf.machine==62&&r.type==8)||(elf.machine==183&&r.type==1027);if(r.target_va==slot&&relative&&r.has_addend&&r.addend>=0&&elf_exec_va(elf,static_cast<std::uint64_t>(r.addend)))return static_cast<std::uint64_t>(r.addend);}
    return{};
}
bool elf_glibc_x86_64(const ElfInfo&elf) { return elf.machine==62&&std::find(elf.needed.begin(),elf.needed.end(),"libc.so.6")!=elf.needed.end(); }
std::optional<std::pair<std::uint64_t,std::uint32_t>> elf_static_sigaction(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t act) {
    // G3 common baseline: glibc x86-64 struct sigaction is 152 bytes; the
    // handler union is the first pointer and sa_flags is the dword at +136.
    // Refuse other libc/architecture layouts rather than guessing.
    if(!elf_glibc_x86_64(elf))return{};
    auto ex=elf_va_extent(elf,act);if(!ex||ex->second<152||ex->first>d.size()||152>d.size()-ex->first)return{};
    auto handler=elf_file_pointer_value(d,elf,act);if(!handler)return{};
    std::uint32_t flags=0;std::memcpy(&flags,d.data()+ex->first+136,4);
    return std::pair<std::uint64_t,std::uint32_t>{*handler,flags};
}

// : bounded stack-resident glibc sigaction recovery.  This is
// deliberately layout-specific (glibc x86-64, 152-byte object) and refuses
// aliased/indexed stack objects.  It exists because optimized and hand-written
// programs commonly build sigaction objects on the stack; treating those as
// unknowable makes exact registration depend on storage duration rather than
// evidence quality.
struct ElfStackRef { ZydisRegister base=ZYDIS_REGISTER_NONE; std::int64_t disp=0; };
struct ElfSigactionValue {
    std::uint64_t handler=0;
    std::uint32_t flags=0;
    bool flags_exact=false;
    std::string source;
};

std::optional<std::uint64_t> elf_reg_constant_before(
    const std::vector<ElfDecoded>&ins,std::size_t before,ZydisRegister wanted,std::size_t budget=96) {
    auto cur=pe_large(wanted);std::int64_t add=0;std::size_t seen=0;
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_RSI||r==ZYDIS_REGISTER_RDI||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    for(std::size_t z=before;z-->0&&seen++<budget;){const auto&x=ins[z];
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&volatile_reg(cur))return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];
            if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(q.reg.value);continue;}
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)return add_signed_u64(q.imm.value.u,add);
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){const auto&m=x.ops[1].mem;if(m.index!=ZYDIS_REGISTER_NONE)return{};const auto dd=m.disp.has_displacement?m.disp.value:0;
            if(pe_large(m.base)==ZYDIS_REGISTER_RIP){auto v=add_signed_u64(x.va+x.ins.length,dd);return v?add_signed_u64(*v,add):std::nullopt;}
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_XOR&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(x.ops[1].reg.value)==cur)return add==0?std::optional<std::uint64_t>(0):add_signed_u64(0,add);
        if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative){auto v=x.ops[1].imm.value.s;if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB){if(v==std::numeric_limits<std::int64_t>::min())return{};v=-v;}if(!add_signed_i64(add,v))return{};continue;}
        return{};
    }return{};
}

std::optional<ElfStackRef> elf_stack_pointer_arg(
    std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfApiCall&c,int arg) {
    if(arg<0||arg>5)return{};
    const auto ins=elf_decode_range(d,elf,{c.func_begin,c.func_end});
    if(ins.empty())return{};
    const std::array<ZydisRegister,6> args={
        ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9};
    auto cur=pe_large(args[static_cast<std::size_t>(arg)]);
    std::size_t at=ins.size();
    for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==c.callsite){at=i;break;}
    if(at==ins.size())return{};
    std::int64_t add=0;
    std::size_t seen=0;
    for(std::size_t z=at;z-->0&&seen++<128;){
        const auto&x=ins[z];
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||
           pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&
           x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){
            cur=pe_large(x.ops[1].reg.value);
            if(cur==ZYDIS_REGISTER_RBP||cur==ZYDIS_REGISTER_RSP)return ElfStackRef{cur,add};
            continue;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&
           x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){
            const auto&m=x.ops[1].mem;
            if(m.index!=ZYDIS_REGISTER_NONE)return{};
            const auto base=pe_large(m.base);
            if(base!=ZYDIS_REGISTER_RBP&&base!=ZYDIS_REGISTER_RSP)return{};
            const auto dd=m.disp.has_displacement?m.disp.value:0;
            if(!add_signed_i64(add,dd))return{};
            return ElfStackRef{base,add};
        }
        if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&
           x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&
           !x.ops[1].imm.is_relative){
            auto v=x.ops[1].imm.value.s;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB){
                if(v==std::numeric_limits<std::int64_t>::min())return{};
                v=-v;
            }
            if(!add_signed_i64(add,v))return{};
            continue;
        }
        return{};
    }
    return{};
}

std::optional<ElfSigactionValue> elf_stack_glibc_sigaction(
    std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfApiCall&c,const ElfStackRef&act) {
    if(!elf_glibc_x86_64(elf))return{};
    const auto ins=elf_decode_range(d,elf,{c.func_begin,c.func_end});
    if(ins.empty())return{};
    std::size_t at=ins.size();
    for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==c.callsite){at=i;break;}
    if(at==ins.size())return{};
    std::optional<std::uint64_t> handler;
    std::optional<std::uint32_t> flags;
    std::size_t seen=0;
    for(std::size_t z=at;z-->0&&seen++<192;){
        const auto&x=ins[z];
        if(!x.ins.operand_count_visible)continue;
        const auto&m=x.ops[0];
        if(m.type!=ZYDIS_OPERAND_TYPE_MEMORY||(m.actions&ZYDIS_OPERAND_ACTION_WRITE)==0||
           m.mem.index!=ZYDIS_REGISTER_NONE||pe_large(m.mem.base)!=act.base)continue;
        const auto md=m.mem.disp.has_displacement?m.mem.disp.value:0;
        const auto rel=md-act.disp;
        if(rel==0&&!handler&&m.size>=64&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&
           x.ins.operand_count_visible>=2){
            const auto&q=x.ops[1];
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)handler=q.imm.value.u;
            else if(q.type==ZYDIS_OPERAND_TYPE_REGISTER)
                handler=elf_reg_constant_before(ins,z,pe_large(q.reg.value));
        }
        if(rel==136&&!flags&&m.size==32&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&
           x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&
           !x.ops[1].imm.is_relative)
            flags=static_cast<std::uint32_t>(x.ops[1].imm.value.u);
        if(handler&&flags)break;
    }
    if(!handler||!elf_exec_va(elf,*handler))return{};
    ElfSigactionValue out;
    out.handler=*handler;
    out.flags=flags.value_or(0);
    out.flags_exact=flags.has_value();
    out.source="bounded stack-resident glibc x86-64 struct sigaction";
    return out;
}

std::map<std::uint64_t,std::string> elf_named_got(const ElfInfo&elf,std::initializer_list<std::string_view> names) {
    std::map<std::uint64_t,std::string>out;if(elf.dynamic.state!="RESOLVED")return out;
    for(const auto&r:elf.dynamic.relocations){if(r.symbol_index>=elf.dynamic.symbols.size())continue;const auto&s=elf.dynamic.symbols[r.symbol_index];if(!s.imported)continue;for(auto n:names)if(s.name==n){out.emplace(r.target_va,s.name);break;}}
    return out;
}

struct HandlerOutcomeEvidence { std::string outcome="UNKNOWN"; std::string detail; bool exact=false; bool ambiguous=false; };
HandlerOutcomeEvidence elf_handler_outcome(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t handler) {
    HandlerOutcomeEvidence out;const auto*hf=elf_fde_func(elf,handler);if(!hf||hf->function_start_va!=handler){out.detail="handler lacks an exact FDE boundary for bounded outcome proof";return out;}const auto ins=elf_decode_range(d,elf,{hf->function_start_va,hf->function_end_va});if(ins.empty()){out.detail="bounded handler decode failed";return out;}
    const auto got=elf_named_got(elf,{"_exit","exit","_Exit","abort","siglongjmp","longjmp","_longjmp","__longjmp_chk"});bool saw_ret=false,saw_term=false,saw_jump=false;
    for(const auto&x:ins){if(x.ins.meta.category==ZYDIS_CATEGORY_RET){saw_ret=true;continue;}if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||!x.ins.operand_count_visible)continue;std::optional<std::string>name;const auto&o=x.ops[0];if(auto slot=elf_rip_mem_va(x,o);slot){auto it=got.find(*slot);if(it!=got.end())name=it->second;}else if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){if(auto t=elf_rel_target(x))name=elf_plt_name(d,elf,*t,got);}if(!name)continue;if(*name=="siglongjmp"||*name=="longjmp"||*name=="_longjmp"||*name=="__longjmp_chk")saw_jump=true;else saw_term=true;}
    const unsigned kinds=(saw_ret?1u:0u)+(saw_term?1u:0u)+(saw_jump?1u:0u);if(kinds!=1){out.ambiguous=kinds>1;out.detail=out.ambiguous?"handler contains multiple bounded outcome classes":"no bounded return/termination/nonlocal-resume outcome recovered";return out;}
    out.exact=true;if(saw_term){out.outcome="TERMINATE_PROCESS";out.detail="exact handler contains a direct imported non-returning termination call";}else if(saw_jump){out.outcome="NONLOCAL_RESUME_TARGET_UNRESOLVED";out.detail="exact handler contains a direct longjmp-family nonlocal-resume call; target context is not inferred";}else{out.outcome="RETURN_TO_SIGNAL_FRAME";out.detail="exact handler contains normal RET and no recognized non-returning transfer";}return out;
}

std::string linux_signal_name(int s);
bool sane_linux_signal(std::uint64_t s);

// Sectionless/static binaries may install a handler with the Linux x86-64
// rt_sigaction syscall directly. uses an entry-rooted bounded
// direct-control walk rather than inventing section/function boundaries: at
// most 4096 basic blocks, 32768 instructions total, and 256 per block.
// Indirect transfers stop a block and are never guessed.
struct ElfReachBlock {
    std::uint64_t begin=0;
    std::vector<ElfDecoded> ins;
};
struct ElfReachCode {
    std::vector<ElfReachBlock> blocks;
    std::map<std::uint64_t,std::uint64_t> parent;
    bool limited=false;
};
ElfReachCode elf_entry_reachable_code(std::span<const std::uint8_t>d,const ElfInfo&elf) {
    ElfReachCode out;
    if(!elf_exec_va(elf,elf.entry)||!elf_va_off(elf,elf.entry,d.size()))return out;
    constexpr std::size_t max_blocks=2048,max_total=8192,max_per_block=256;
    std::vector<std::uint64_t> queue{elf.entry};
    std::set<std::uint64_t> queued{elf.entry},decoded_starts;
    out.parent[elf.entry]=elf.entry;
    std::size_t total=0;
    auto enqueue=[&](std::uint64_t va,std::uint64_t parent){
        if(!elf_exec_va(elf,va)||!elf_va_off(elf,va,d.size())||queued.count(va))return;
        if(queue.size()>=max_blocks){out.limited=true;return;}
        queued.insert(va);out.parent[va]=parent;queue.push_back(va);
    };
    for(std::size_t qi=0;qi<queue.size()&&out.blocks.size()<max_blocks&&total<max_total;++qi){
        const auto start=queue[qi];
        if(!decoded_starts.insert(start).second)continue;
        ElfReachBlock b;b.begin=start;auto va=start;
        for(std::size_t bi=0;bi<max_per_block&&total<max_total;++bi){
            if(bi&&queued.count(va))break;
            auto x=elf_decode_one(d,elf,va);if(!x)break;
            b.ins.push_back(*x);++total;
            const auto next=va+x->ins.length;
            const auto cat=x->ins.meta.category;
            if(cat==ZYDIS_CATEGORY_RET)break;
            if(cat==ZYDIS_CATEGORY_UNCOND_BR){if(auto t=elf_rel_target(*x))enqueue(*t,start);break;}
            if(cat==ZYDIS_CATEGORY_COND_BR){if(auto t=elf_rel_target(*x))enqueue(*t,start);enqueue(next,start);break;}
            // Calls are not followed: the registration state on this path stays
            // with the caller. Exact handler code is analyzed from its pointer.
            if(cat==ZYDIS_CATEGORY_CALL){va=next;continue;}
            if(!elf_exec_va(elf,next)||!elf_va_off(elf,next,d.size()))break;
            va=next;
        }
        if(b.ins.size()==max_per_block)out.limited=true;
        if(!b.ins.empty())out.blocks.push_back(std::move(b));
    }
    if(total>=max_total||out.blocks.size()>=max_blocks)out.limited=true;
    return out;
}

std::vector<std::uint64_t> elf_reach_parent_path(const ElfReachCode&reach,std::uint64_t block) {
    std::vector<std::uint64_t> rev;
    std::set<std::uint64_t> seen;
    for(std::size_t n=0;n<4096;++n){
        if(!seen.insert(block).second)return{};
        rev.push_back(block);
        auto it=reach.parent.find(block);if(it==reach.parent.end())return{};
        if(it->second==block)break;
        block=it->second;
    }
    if(rev.empty())return{};
    std::reverse(rev.begin(),rev.end());return rev;
}

std::uint64_t elf_reach_block_size(const ElfReachCode&reach,std::uint64_t begin) {
    for(const auto&b:reach.blocks)if(b.begin==begin&&!b.ins.empty()){
        const auto&last=b.ins.back();
        if(last.va>=begin&&last.va-begin<=std::numeric_limits<std::uint64_t>::max()-last.ins.length)
            return last.va-begin+last.ins.length;
    }
    return 1;
}

std::optional<ElfStackRef> elf_local_stack_pointer_before(const std::vector<ElfDecoded>&ins,std::size_t before,ZydisRegister wanted) {
    auto cur=pe_large(wanted);std::int64_t add=0;std::size_t seen=0;for(std::size_t z=before;z-->0&&seen++<96;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)return{};
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(x.ops[1].reg.value);if(cur==ZYDIS_REGISTER_RSP||cur==ZYDIS_REGISTER_RBP)return ElfStackRef{cur,add};continue;}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){const auto&m=x.ops[1].mem;if(m.index!=ZYDIS_REGISTER_NONE)return{};const auto base=pe_large(m.base);if(base!=ZYDIS_REGISTER_RSP&&base!=ZYDIS_REGISTER_RBP)return{};auto dd=m.disp.has_displacement?m.disp.value:0;if(!add_signed_i64(add,dd))return{};return ElfStackRef{base,add};}
        return{};
    }return{};
}

struct RawSigactionValue {
    std::uint64_t handler=0;
    std::uint64_t flags_value=0,flags_known_mask=0;
    bool restorer_exact=false,mask_exact=false;
};
std::optional<RawSigactionValue> elf_raw_stack_sigaction(
    const ElfInfo&elf,const std::vector<ElfDecoded>&ins,std::size_t syscall_index,const ElfStackRef&act) {
    RawSigactionValue out;
    bool handler=false;
    std::array<std::uint8_t,8> flag_bytes{},flag_known{};
    std::size_t seen=0;
    for(std::size_t z=syscall_index;z-->0&&seen++<128;){
        const auto&x=ins[z];
        // Any stack-pointer rebase after the object writes invalidates an RSP-relative identity.
        if(act.base==ZYDIS_REGISTER_RSP&&x.ins.operand_count_visible&&
           x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(x.ops[0].reg.value)==ZYDIS_REGISTER_RSP&&
           (x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            if(handler)break;
            continue;
        }
        if(!x.ins.operand_count_visible)continue;
        const auto&m=x.ops[0];
        if(m.type!=ZYDIS_OPERAND_TYPE_MEMORY||(m.actions&ZYDIS_OPERAND_ACTION_WRITE)==0||
           m.mem.index!=ZYDIS_REGISTER_NONE||pe_large(m.mem.base)!=act.base)continue;
        const auto md=m.mem.disp.has_displacement?m.mem.disp.value:0;
        const auto rel=md-act.disp;
        if(rel==0&&!handler&&m.size>=64&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&
           x.ins.operand_count_visible>=2){
            const auto&q=x.ops[1];
            std::optional<std::uint64_t> v;
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!q.imm.is_relative)v=q.imm.value.u;
            else if(q.type==ZYDIS_OPERAND_TYPE_REGISTER)v=elf_reg_constant_before(ins,z,pe_large(q.reg.value));
            if(v&&elf_exec_va(elf,*v)){out.handler=*v;handler=true;}
        }
        if(rel>=8&&rel<16&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&
           x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative){
            const auto bytes=std::min<std::uint64_t>(m.size/8,8u);
            if(bytes&&rel+static_cast<std::int64_t>(bytes)<=16){
                const auto v=x.ops[1].imm.value.u;
                for(std::uint64_t i=0;i<bytes;++i){
                    const auto j=static_cast<std::size_t>(rel-8+i);
                    if(!flag_known[j]){
                        flag_bytes[j]=static_cast<std::uint8_t>(v>>(8*i));
                        flag_known[j]=1;
                    }
                }
            }
        }
        // Exact qword stores close restorer and kernel sigset only; partial
        // stores are intentionally not combined into those claims.
        if(rel==16&&m.size==64&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&
           x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&
           !x.ops[1].imm.is_relative)out.restorer_exact=true;
        if(rel==24&&m.size==64&&x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&
           x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&
           !x.ops[1].imm.is_relative)out.mask_exact=true;
    }
    if(!handler)return{};
    for(std::size_t i=0;i<8;++i)if(flag_known[i]){
        out.flags_known_mask|=std::uint64_t(0xff)<<(8*i);
        out.flags_value|=std::uint64_t(flag_bytes[i])<<(8*i);
    }
    return out;
}

struct RawRegistration {
    std::uint64_t site=0,size=0,handler=0,block_begin=0;
    int signal=0;
    std::uint64_t flags_value=0,flags_known_mask=0;
    bool restorer_exact=false,mask_exact=false;
    HandlerOutcomeEvidence outcome;
};

HandlerOutcomeEvidence elf_raw_handler_outcome(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t handler) {
    HandlerOutcomeEvidence out;std::vector<ElfDecoded>ins;auto va=handler;for(std::size_t i=0;i<256;++i){auto x=elf_decode_one(d,elf,va);if(!x)break;ins.push_back(*x);const auto idx=ins.size()-1;
        if(x->ins.mnemonic==ZYDIS_MNEMONIC_SYSCALL){auto nr=elf_reg_constant_before(ins,idx,ZYDIS_REGISTER_RAX,48);if(nr&&(*nr==60||*nr==231)){auto code=elf_reg_constant_before(ins,idx,ZYDIS_REGISTER_RDI,48);out.exact=true;out.outcome="TERMINATE_PROCESS";out.detail=std::string("raw handler reaches exact ")+(*nr==60?"exit":"exit_group")+" syscall"+(code?" with status="+std::to_string(*code):"");return out;}if(nr&&*nr==15){out.exact=true;out.outcome="RETURN_TO_SIGNAL_FRAME";out.detail="raw handler reaches exact rt_sigreturn syscall";return out;}}
        if(x->ins.meta.category==ZYDIS_CATEGORY_RET){out.exact=true;out.outcome="RETURN_TO_SIGNAL_FRAME";out.detail="raw handler reaches normal RET; exact restorer semantics remain registration-dependent";return out;}
        if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR){auto t=elf_rel_target(*x);if(!t||!elf_exec_va(elf,*t)){out.detail="raw handler exits bounded direct-control domain";return out;}va=*t;continue;}
        if(x->ins.meta.category==ZYDIS_CATEGORY_COND_BR){out.ambiguous=true;out.detail="raw handler contains conditional control before a single outcome can be proven";return out;}
        va+=x->ins.length;
    }out.detail="raw handler outcome instruction budget exhausted or decoding stopped";return out;
}

std::vector<RawRegistration> elf_raw_rt_sigactions(std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfReachCode&reach) {
    std::vector<RawRegistration>out;for(const auto&b:reach.blocks)for(std::size_t i=0;i<b.ins.size();++i){const auto&x=b.ins[i];if(x.ins.mnemonic!=ZYDIS_MNEMONIC_SYSCALL)continue;auto nr=elf_reg_constant_before(b.ins,i,ZYDIS_REGISTER_RAX,64);if(!nr||*nr!=13)continue;auto sn=elf_reg_constant_before(b.ins,i,ZYDIS_REGISTER_RDI,64);auto old=elf_reg_constant_before(b.ins,i,ZYDIS_REGISTER_RDX,64);auto ss=elf_reg_constant_before(b.ins,i,ZYDIS_REGISTER_R10,64);if(!sn||!sane_linux_signal(*sn)||!old||*old!=0||!ss||*ss!=8)continue;auto sr=elf_local_stack_pointer_before(b.ins,i,ZYDIS_REGISTER_RSI);if(!sr)continue;auto sa=elf_raw_stack_sigaction(elf,b.ins,i,*sr);if(!sa)continue;RawRegistration r;r.site=x.va;r.size=x.ins.length;r.handler=sa->handler;r.block_begin=b.begin;r.signal=static_cast<int>(*sn);r.flags_value=sa->flags_value;r.flags_known_mask=sa->flags_known_mask;r.restorer_exact=sa->restorer_exact;r.mask_exact=sa->mask_exact;r.outcome=elf_raw_handler_outcome(d,elf,r.handler);out.push_back(std::move(r));if(out.size()>=16)return out;}return out;
}

struct RawFaultTrigger { std::uint64_t va=0,size=0,block_begin=0; int signal=11; std::string kind; };
bool elf_initial_load_maps(const ElfInfo&elf,std::uint64_t va) {for(const auto&s:elf.segments)if(s.type==1&&s.memory_size&&va>=s.address&&va-s.address<s.memory_size)return true;return false;}
std::vector<RawFaultTrigger> elf_exact_constant_faults(const ElfInfo&elf,const ElfReachCode&reach) {
    std::vector<RawFaultTrigger>out;std::set<std::uint64_t>seen;for(const auto&b:reach.blocks)for(std::size_t i=0;i<b.ins.size();++i){const auto&x=b.ins[i];for(std::uint8_t oi=0;oi<x.ins.operand_count_visible;++oi){const auto&m=x.ops[oi];if(m.type!=ZYDIS_OPERAND_TYPE_MEMORY||m.mem.index!=ZYDIS_REGISTER_NONE||m.mem.base==ZYDIS_REGISTER_NONE||pe_large(m.mem.base)==ZYDIS_REGISTER_RIP)continue;const auto access=m.actions&(ZYDIS_OPERAND_ACTION_READ|ZYDIS_OPERAND_ACTION_WRITE);if(!access)continue;auto base=elf_reg_constant_before(b.ins,i,pe_large(m.mem.base),48);if(!base)continue;const auto dd=m.mem.disp.has_displacement?m.mem.disp.value:0;auto addr=add_signed_u64(*base,dd);if(!addr||elf_initial_load_maps(elf,*addr))continue;if(*addr!=0)continue;if(!seen.insert(x.va).second)continue;RawFaultTrigger t;t.va=x.va;t.size=x.ins.length;t.block_begin=b.begin;t.kind=(access&ZYDIS_OPERAND_ACTION_WRITE)?"CONSTANT_NULL_WRITE_SIGSEGV":"CONSTANT_NULL_READ_SIGSEGV";out.push_back(std::move(t));if(out.size()>=16)return out;}}return out;
}

std::optional<std::uint64_t> elf_direct_nonfault_sibling(
    const ElfReachCode&reach,std::uint64_t fault_block,const std::set<std::uint64_t>&fault_blocks) {
    const auto path=elf_reach_parent_path(reach,fault_block);
    if(path.size()<2)return{};
    const auto parent=path[path.size()-2];
    const ElfReachBlock*pb=nullptr;
    for(const auto&b:reach.blocks)if(b.begin==parent){pb=&b;break;}
    if(!pb||pb->ins.empty())return{};
    const auto&last=pb->ins.back();
    if(last.ins.meta.category!=ZYDIS_CATEGORY_COND_BR)return{};
    const auto target=elf_rel_target(last);
    if(!target)return{};
    if(last.va>std::numeric_limits<std::uint64_t>::max()-last.ins.length)return{};
    const auto fall=last.va+last.ins.length;
    std::uint64_t sibling=0;
    if(*target==fault_block)sibling=fall;
    else if(fall==fault_block)sibling=*target;
    else return{};
    if(fault_blocks.count(sibling))return{};
    for(const auto&b:reach.blocks)if(b.begin==sibling&&!b.ins.empty())return sibling;
    return{};
}

void analyze_raw_linux_signal_surface(
    std::span<const std::uint8_t>d,const ElfInfo&elf,const std::string&artifact,ExceptionalExecutionInfo&out) {
    const auto reach=elf_entry_reachable_code(d,elf);if(reach.blocks.empty())return;
    const auto regs=elf_raw_rt_sigactions(d,elf,reach);
    if(regs.empty())return;
    const auto faults=elf_exact_constant_faults(elf,reach);
    std::set<std::uint64_t>fault_blocks;for(const auto&t:faults)fault_blocks.insert(t.block_begin);
    const bool registration_budget_hit=regs.size()>=16;
    std::map<int,std::size_t>reg_count;for(const auto&r:regs)++reg_count[r.signal];
    for(const auto&r:regs){
        ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism="LINUX_RT_SIGACTION_SYSCALL";f.trigger_kind="HANDLER_REGISTRATION";
        f.registration_site=elf_va_ref(r.site,r.size,"raw rt_sigaction syscall",artifact);
        f.handler=elf_va_ref(r.handler,1,"exact raw rt_sigaction handler",artifact);
        f.evidence_state="REGISTRATION_HANDLER_EXACT";f.priority="INFORMATIONAL";
        f.priority_reason="X1 raw syscall registration remains inventory until a compatible exact trigger is related";
        f.handler_outcome=r.outcome.exact?r.outcome.outcome:"UNKNOWN";
        if(reg_count[r.signal]>1)f.ambiguity="multiple exact rt_sigaction registrations for this signal exist in the bounded graph; trigger relations select the active registration on one exact parent path";
        if(registration_budget_hit){if(!f.ambiguity.empty())f.ambiguity+="; ";f.ambiguity+="registration evidence budget reached; no X3/X5 promotion is allowed";}
        f.provenance="entry-rooted bounded direct CFG + exact Linux x86-64 syscall number/arguments + unaliased stack action object";
        std::ostringstream q;q<<"signal="<<linux_signal_name(r.signal)<<", flags_known_mask="<<hx(r.flags_known_mask)
            <<", flags_known_value="<<hx(r.flags_value)<<", restorer_exact="<<(r.restorer_exact?"true":"false")
            <<", mask_exact="<<(r.mask_exact?"true":"false")<<", code_walk_limited="<<(reach.limited?"true":"false")
            <<", handler_outcome_evidence="<<r.outcome.detail;f.detail=q.str();exceptional_add(out,std::move(f));
    }
    for(const auto&t:faults){
        ExceptionalExecutionFact tf;tf.platform="LINUX_ELF";tf.mechanism="LINUX_FAULT_TRIGGER";tf.trigger_kind=t.kind;
        tf.trigger_location=elf_va_ref(t.va,t.size,"exact constant-address memory operation",artifact);
        tf.protected_range=elf_va_ref(t.block_begin,elf_reach_block_size(reach,t.block_begin),"bounded trigger basic block",artifact);
        tf.evidence_state="TRIGGER_PROVEN";tf.priority="INFORMATIONAL";
        tf.priority_reason="X2 exact faulting operation is not exceptional control flow until a compatible registration/dispatch state is related";
        tf.provenance="entry-rooted bounded direct CFG + exact register constant + PT_LOAD initial mapping geometry";
        tf.detail="effective address is exactly 0 and no PT_LOAD initially maps VA 0; runtime remapping is not claimed";
        exceptional_add(out,std::move(tf));
        if(registration_budget_hit)continue;
        const auto path=elf_reach_parent_path(reach,t.block_begin);if(path.empty())continue;
        const RawRegistration*active=nullptr;
        std::size_t replacements_on_path=0;
        for(const auto block:path){
            const RawRegistration*latest=nullptr;
            for(const auto&r:regs){
                if(r.signal!=t.signal||r.block_begin!=block)continue;
                if(block==t.block_begin&&r.site>=t.va)continue;
                if(!latest||r.site>latest->site)latest=&r;
            }
            if(latest){if(active&&active->handler!=latest->handler)++replacements_on_path;active=latest;}
        }
        if(!active)continue; // trigger before registration or wrong signal
        const auto semantic_sibling=elf_direct_nonfault_sibling(reach,t.block_begin,fault_blocks);
        ExceptionalExecutionFact x;x.platform="LINUX_ELF";x.mechanism="LINUX_RT_SIGACTION_SYSCALL";x.trigger_kind=t.kind;
        x.trigger_location=elf_va_ref(t.va,t.size,"exact SIGSEGV-producing memory operation under initial mapping",artifact);
        x.registration_site=elf_va_ref(active->site,active->size,"active raw rt_sigaction on selected parent path",artifact);
        x.handler=elf_va_ref(active->handler,1,"exact active SIGSEGV handler",artifact);
        x.protected_range=elf_va_ref(t.block_begin,elf_reach_block_size(reach,t.block_begin),"trigger block on bounded parent path",artifact);
        x.protected_function="entry-parent-path:"+hx(elf.entry)+"->"+hx(t.block_begin);
        x.handler_outcome=active->outcome.exact?active->outcome.outcome:"UNKNOWN";
        if(reg_count[t.signal]>1)x.ambiguity="other same-signal registrations exist on alternate bounded paths; this fact is scoped to the selected exact parent path";
        if(replacements_on_path){if(!x.ambiguity.empty())x.ambiguity+="; ";x.ambiguity+=std::to_string(replacements_on_path)+" earlier handler replacement(s) occur on the selected path; the last exact registration is active";}
        x.evidence_state="TRIGGER_HANDLER_CORRELATED";x.priority="HIGH";
        x.priority_reason="an exact constant-null SIGSEGV trigger is reachable on a bounded direct parent path whose active same-signal registration resolves this exact handler";
        x.provenance="X1 raw rt_sigaction + X2 constant fault + bounded entry-rooted parent-path registration state";
        x.resume_semantics=active->outcome.exact&&active->outcome.outcome=="TERMINATE_PROCESS"?"handler terminates; there is no signal-frame resume":"post-dispatch resume remains outcome-dependent";
        exceptional_add(out,std::move(x));
        if(active->outcome.exact){
            ExceptionalExecutionFact ho;ho.platform="LINUX_ELF";ho.mechanism="LINUX_RT_SIGACTION_HANDLER_OUTCOME";ho.trigger_kind=t.kind;
            ho.trigger_location=elf_va_ref(t.va,t.size,"fault site with closed dispatch",artifact);
            ho.registration_site=elf_va_ref(active->site,active->size,"active raw rt_sigaction",artifact);
            ho.handler=elf_va_ref(active->handler,1,"exact dispatched handler",artifact);
            ho.protected_range=elf_va_ref(t.block_begin,elf_reach_block_size(reach,t.block_begin),"faulting control block",artifact);
            ho.protected_function="entry-parent-path:"+hx(elf.entry)+"->"+hx(t.block_begin);
            ho.handler_outcome=active->outcome.outcome;ho.evidence_state="HANDLER_OUTCOME_EXACT";ho.priority="HIGH";
            ho.priority_reason="X3 selected-path dispatch reaches a handler with one bounded exact outcome class";
            ho.provenance="X3 bounded parent-path dispatch + bounded raw-handler outcome";
            ho.resume_semantics=active->outcome.outcome=="TERMINATE_PROCESS"?"handler terminates the process; no signal-frame resume occurs":"handler returns to the signal frame; semantic effect is not inferred";
            if(reg_count[t.signal]>1)ho.ambiguity="outcome is scoped to the selected parent path; alternate-path registrations remain separate";
            exceptional_add(out,std::move(ho));
        }
        if(active->outcome.exact&&active->outcome.outcome=="TERMINATE_PROCESS"&&semantic_sibling){
            ExceptionalExecutionFact cl;cl.platform="LINUX_ELF";cl.mechanism="LINUX_RT_SIGACTION_SEMANTIC_CLOSURE";cl.trigger_kind=t.kind;
            cl.trigger_location=elf_va_ref(t.va,t.size,"fault site",artifact);
            cl.registration_site=elf_va_ref(active->site,active->size,"active raw rt_sigaction",artifact);
            cl.handler=elf_va_ref(active->handler,1,"terminating handler",artifact);
            cl.protected_range=elf_va_ref(t.block_begin,elf_reach_block_size(reach,t.block_begin),"faulting control block",artifact);
            cl.protected_function="entry-parent-path:"+hx(elf.entry)+"->"+hx(t.block_begin);
            cl.handler_outcome="TERMINATE_PROCESS";cl.evidence_state="SEMANTIC_EXCEPTION_CLOSURE";cl.priority="HIGH";
            cl.priority_reason="a bounded exact conditional branch selects between a constant-null fault whose active handler terminates and a separately decoded non-fault sibling continuation";
            cl.provenance="X1+X2+X3 static parent-path dispatch + X4 exact terminating handler + direct conditional sibling control relation";
            cl.resume_semantics="fault branch dispatch terminates; the sibling branch continues at "+hx(*semantic_sibling)+"; this closes a fault-as-terminal/reject-like control role without inferring application-level success text";
            cl.detail="non_fault_sibling="+hx(*semantic_sibling);
            if(reg_count[t.signal]>1)cl.ambiguity="semantic closure is scoped to the selected parent path; alternate-path handler state remains separate";
            exceptional_add(out,std::move(cl));
        }
    }
}

struct ElfCfg {std::vector<ElfDecoded>ins;std::map<std::uint64_t,std::size_t>by_va;std::vector<std::vector<std::size_t>>edges;};
ElfCfg elf_cfg(std::span<const std::uint8_t>d,const ElfInfo&elf,ElfFuncRange f){ElfCfg g;g.ins=elf_decode_range(d,elf,f);g.edges.resize(g.ins.size());for(std::size_t i=0;i<g.ins.size();++i)g.by_va[g.ins[i].va]=i;auto edge=[&](std::size_t a,std::uint64_t v){auto it=g.by_va.find(v);if(it!=g.by_va.end())g.edges[a].push_back(it->second);};
    for(std::size_t i=0;i<g.ins.size();++i){const auto&x=g.ins[i];const auto fall=i+1<g.ins.size()?std::optional<std::uint64_t>(g.ins[i+1].va):std::nullopt;if(x.ins.meta.category==ZYDIS_CATEGORY_RET)continue;if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR){if(auto t=elf_rel_target(x))edge(i,*t);continue;}if(x.ins.meta.category==ZYDIS_CATEGORY_COND_BR){if(auto t=elf_rel_target(x))edge(i,*t);if(fall)edge(i,*fall);continue;}if(fall)edge(i,*fall);}
    return g;
}
bool elf_reachable(const ElfCfg&g,std::size_t start,std::size_t goal,std::optional<std::size_t>blocked={}){if(start>=g.ins.size()||goal>=g.ins.size()||blocked==start)return false;std::vector<std::uint8_t>seen(g.ins.size());std::vector<std::size_t>q{start};seen[start]=1;for(std::size_t p=0;p<q.size();++p){const auto u=q[p];if(u==goal)return true;for(auto v:g.edges[u])if(!seen[v]&&(!blocked||v!=*blocked)){seen[v]=1;q.push_back(v);}}return false;}
bool elf_dominates(const ElfCfg&g,std::size_t dom,std::size_t node){if(g.ins.empty()||dom>=g.ins.size()||node>=g.ins.size()||!elf_reachable(g,0,node))return false;if(dom==0)return true;return !elf_reachable(g,0,node,dom);}
bool elf_barrier_between(const ElfCfg&g,std::size_t reg,std::size_t trigger,const std::set<std::uint64_t>&barriers){for(auto v:barriers){auto it=g.by_va.find(v);if(it==g.by_va.end())continue;if(elf_reachable(g,reg,it->second)&&elf_reachable(g,it->second,trigger))return true;}return false;}

std::optional<int> linux_trap_signal(const ElfDecoded&x,std::string&kind){if(x.ins.mnemonic==ZYDIS_MNEMONIC_UD2){kind="UD2_SIGILL";return 4;}if(x.ins.mnemonic==ZYDIS_MNEMONIC_INT3){kind="INT3_SIGTRAP";return 5;}if(x.ins.mnemonic==ZYDIS_MNEMONIC_INT1){kind="INT1_SIGTRAP";return 5;}return{};}
std::string linux_signal_name(int s){switch(s){case 4:return"SIGILL";case 5:return"SIGTRAP";case 8:return"SIGFPE";case 11:return"SIGSEGV";default:return"SIGNAL_"+std::to_string(s);}}
bool sane_linux_signal(std::uint64_t s){return s>=1&&s<=64;}

bool elf_arg_from_producer_return(std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfApiCall&consumer,int arg,std::string_view producer,const std::map<std::uint64_t,const ElfApiCall*>&by_site){
    if(arg<0||arg>5)return false;
    auto ins=elf_decode_range(d,elf,{consumer.func_begin,consumer.func_end});if(ins.empty())return false;
    auto cur=pe_large(std::array<ZydisRegister,6>{ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9}[arg]);std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==consumer.callsite){at=i;break;}if(at==ins.size())return false;
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_RSI||r==ZYDIS_REGISTER_RDI||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};std::size_t seen=0;
    for(std::size_t z=at;z-->0&&seen++<160;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){if(cur==ZYDIS_REGISTER_RAX){auto it=by_site.find(x.va);return it!=by_site.end()&&it->second->name==producer;}if(volatile_reg(cur))return false;continue;}
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||pe_large(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){cur=pe_large(x.ops[1].reg.value);continue;}
        return false;}
    return false;
}

bool eh_uleb_local(std::span<const std::uint8_t>d,std::size_t&p,std::size_t end,std::uint64_t&v){v=0;unsigned shift=0;for(unsigned n=0;n<10&&p<end;++n){const auto b=d[p++];if(shift>=64&&(b&0x7f))return false;if(shift<64)v|=std::uint64_t(b&0x7f)<<shift;if(!(b&0x80))return true;shift+=7;}return false;}
struct LsdaEntry{std::uint64_t start=0,length=0,landing=0,action=0;};
enum class LsdaState{PARSED,UNSUPPORTED,MALFORMED};
struct LsdaParse{LsdaState state=LsdaState::MALFORMED;std::vector<LsdaEntry>entries;std::string reason;};
bool lsda_unsigned_value(std::span<const std::uint8_t>d,std::size_t&p,std::size_t end,std::uint8_t enc,std::uint64_t&v){const auto fmt=enc&0x0f;if((enc&0xf0)!=0)return false;if(fmt==1)return eh_uleb_local(d,p,end,v);std::size_t n=fmt==2?2:fmt==3?4:fmt==4?8:0;if(!n||p>end||n>end-p)return false;v=0;for(std::size_t i=0;i<n;++i)v|=std::uint64_t(d[p+i])<<(8*i);p+=n;return true;}
LsdaParse parse_lsda_common(std::span<const std::uint8_t>d,const ElfInfo&elf,const ElfUnwindFde&fde){LsdaParse out;auto ex=elf_va_extent(elf,fde.lsda_reference_va);if(!ex||ex->first>=d.size()){out.reason="LSDA is not file-backed";return out;}const auto max=std::min<std::uint64_t>(ex->second,1u<<20);std::size_t p=static_cast<std::size_t>(ex->first),end=p+static_cast<std::size_t>(max);if(p>=end){out.reason="empty LSDA";return out;}
    const auto lpenc=d[p++];if(lpenc!=0xff){out.state=LsdaState::UNSUPPORTED;out.reason="explicit LPStart encoding is outside the common bounded baseline";return out;}
    if(p>=end){out.reason="truncated LSDA type-table encoding";return out;}const auto ttenc=d[p++];if(ttenc!=0xff){std::uint64_t off=0;if(!eh_uleb_local(d,p,end,off)||off>std::uint64_t(end-p)){out.reason="invalid LSDA type-table offset";return out;}}
    if(p>=end){out.reason="truncated LSDA call-site encoding";return out;}const auto csenc=d[p++];if((csenc&0xf0)!=0||!((csenc&0x0f)==1||(csenc&0x0f)==2||(csenc&0x0f)==3||(csenc&0x0f)==4)){out.state=LsdaState::UNSUPPORTED;out.reason="call-site encoding is outside uleb/udata common baseline";return out;}
    std::uint64_t table_len=0;if(!eh_uleb_local(d,p,end,table_len)||table_len>std::uint64_t(end-p)||table_len>(1u<<20)){out.reason="invalid LSDA call-site table length";return out;}const auto table_end=p+static_cast<std::size_t>(table_len);
    while(p<table_end){LsdaEntry e;if(!lsda_unsigned_value(d,p,table_end,csenc,e.start)||!lsda_unsigned_value(d,p,table_end,csenc,e.length)||!lsda_unsigned_value(d,p,table_end,csenc,e.landing)||!eh_uleb_local(d,p,table_end,e.action)){out.reason="malformed LSDA call-site row";return out;}if(e.start>fde.function_size||e.length>fde.function_size-e.start){out.reason="LSDA protected range exceeds FDE function";return out;}if(e.landing&&e.landing>=fde.function_size){out.reason="LSDA landing pad exceeds FDE function";return out;}if(e.action&&e.action-1>=std::uint64_t(end-table_end)){out.reason="LSDA action offset exceeds bounded file extent";return out;}out.entries.push_back(e);if(out.entries.size()>65536){out.reason="LSDA call-site row budget exceeded";return out;}}
    if(p!=table_end){out.reason="LSDA call-site table geometry mismatch";return out;}out.state=LsdaState::PARSED;return out;
}


bool cfi_sleb(std::span<const std::uint8_t>d,std::size_t&p,std::size_t end,std::int64_t&v){
    v=0;unsigned shift=0;std::uint8_t b=0;for(unsigned n=0;n<10&&p<end;++n){b=d[p++];if(shift<64)v|=std::int64_t(std::uint64_t(b&0x7f)<<shift);shift+=7;if(!(b&0x80)){if(shift<64&&(b&0x40))v|=static_cast<std::int64_t>(~std::uint64_t(0)<<shift);return true;}}return false;
}
struct CfiExpressionSummary {
    bool parsed=false;
    std::uint32_t expression_ops=0,return_address_expression_ops=0,def_cfa_expression_ops=0;
    std::uint64_t expression_payload_bytes=0;
    std::string error;
};
CfiExpressionSummary scan_fde_cfi_expressions(std::span<const std::uint8_t>d,const ElfUnwindFde&fde,const ElfUnwindCie&cie){
    CfiExpressionSummary out;
    if(!fde.cfi_size){out.parsed=true;return out;}
    if(fde.cfi_file_offset>d.size()||fde.cfi_size>d.size()-fde.cfi_file_offset||fde.cfi_size>(1u<<20)){out.error="FDE CFI byte range is outside the bounded file-backed program";return out;}
    std::size_t p=static_cast<std::size_t>(fde.cfi_file_offset),end=p+static_cast<std::size_t>(fde.cfi_size);std::uint64_t ops=0;
    auto uleb=[&](std::uint64_t&v){return eh_uleb_local(d,p,end,v);};
    auto sleb=[&](std::int64_t&v){return cfi_sleb(d,p,end,v);};
    auto bytes=[&](std::size_t n){if(n>end-p)return false;p+=n;return true;};
    auto block=[&](bool expression,std::optional<std::uint64_t>reg){std::uint64_t n=0;if(!uleb(n)||n>end-p||n>(1u<<20))return false;if(expression){++out.expression_ops;out.expression_payload_bytes+=n;if(reg&&*reg==cie.return_address_register)++out.return_address_expression_ops;}p+=static_cast<std::size_t>(n);return true;};
    while(p<end&&ops++<65536){const auto op=d[p++];const auto primary=op&0xc0u;if(primary==0x40u||primary==0xc0u)continue;if(primary==0x80u){std::uint64_t v=0;if(!uleb(v)){out.error="truncated primary DW_CFA_offset operand";return out;}continue;}
        std::uint64_t a=0,b=0;std::int64_t sa=0;
        switch(op){
        case 0x00: break; // nop
        case 0x01: if(!bytes(cie.address_size?cie.address_size:8)){out.error="truncated DW_CFA_set_loc";return out;}break;
        case 0x02: if(!bytes(1)){out.error="truncated DW_CFA_advance_loc1";return out;}break;
        case 0x03: if(!bytes(2)){out.error="truncated DW_CFA_advance_loc2";return out;}break;
        case 0x04: if(!bytes(4)){out.error="truncated DW_CFA_advance_loc4";return out;}break;
        case 0x05: if(!uleb(a)||!uleb(b)){out.error="truncated DW_CFA_offset_extended";return out;}break;
        case 0x06: case 0x07: case 0x08: case 0x0d: case 0x0e: case 0x2e: if(!uleb(a)){out.error="truncated one-ULEB DW_CFA operand";return out;}break;
        case 0x09: case 0x0c: case 0x14: if(!uleb(a)||!uleb(b)){out.error="truncated two-ULEB DW_CFA operands";return out;}break;
        case 0x0a: case 0x0b: case 0x2d: break;
        case 0x0f: ++out.def_cfa_expression_ops;if(!block(false,{})){out.error="truncated DW_CFA_def_cfa_expression block";return out;}break;
        case 0x10: if(!uleb(a)||!block(true,a)){out.error="truncated DW_CFA_expression";return out;}break;
        case 0x11: case 0x12: case 0x15: if(!uleb(a)||!sleb(sa)){out.error="truncated signed DW_CFA operands";return out;}break;
        case 0x13: if(!sleb(sa)){out.error="truncated DW_CFA_def_cfa_offset_sf";return out;}break;
        case 0x16: if(!uleb(a)||!block(true,a)){out.error="truncated DW_CFA_val_expression";return out;}break;
        case 0x1d: if(!bytes(8)){out.error="truncated DW_CFA_MIPS_advance_loc8";return out;}break;
        case 0x2f: if(!uleb(a)||!uleb(b)){out.error="truncated DW_CFA_GNU_negative_offset_extended";return out;}break;
        default: out.error="unsupported DW_CFA opcode "+hx(op)+"; expression claim refused";return out;
        }
    }
    if(p!=end){out.error="FDE CFI opcode budget exhausted";return out;}out.parsed=true;return out;
}

std::uint16_t elf_u16le(std::span<const std::uint8_t>d,std::size_t o){return o+2<=d.size()?std::uint16_t(d[o])|(std::uint16_t(d[o+1])<<8):0;}
std::uint32_t elf_u32le(std::span<const std::uint8_t>d,std::size_t o){return o+4<=d.size()?std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24):0;}
std::uint64_t elf_u64le(std::span<const std::uint8_t>d,std::size_t o){if(o+8>d.size())return 0;std::uint64_t v=0;for(int i=7;i>=0;--i)v=(v<<8)|d[o+i];return v;}
bool elf_has_undefined_dynsym(std::span<const std::uint8_t>d,const ElfInfo&elf,std::string_view wanted){
    if(!elf.valid||!elf.elf64||!elf.little_endian||d.size()<64)return false;
    const std::uint64_t shoff=elf_u64le(d,40);const std::uint16_t shents=elf_u16le(d,58),shnum=elf_u16le(d,60);if(!shoff||shents<64||!shnum||shoff>d.size()||std::uint64_t(shents)*shnum>d.size()-shoff)return false;
    struct Sh{std::uint32_t type=0,link=0;std::uint64_t off=0,size=0,ents=0;};std::vector<Sh>secs(shnum);
    for(std::uint16_t i=0;i<shnum;++i){const auto o=static_cast<std::size_t>(shoff)+std::size_t(i)*shents;if(o+64>d.size())return false;secs[i]={elf_u32le(d,o+4),elf_u32le(d,o+40),elf_u64le(d,o+24),elf_u64le(d,o+32),elf_u64le(d,o+56)};if(secs[i].off>d.size()||secs[i].size>d.size()-secs[i].off)return false;}
    for(const auto&symtab:secs){if(symtab.type!=11||symtab.link>=secs.size()||symtab.ents<24||symtab.ents>4096||symtab.size%symtab.ents)continue;const auto&str=secs[symtab.link];if(str.type!=3||!str.size)continue;
        const auto count=symtab.size/symtab.ents;if(count>1000000)return false;for(std::uint64_t i=0;i<count;++i){const auto o=static_cast<std::size_t>(symtab.off+i*symtab.ents);if(o+24>d.size())return false;const auto no=elf_u32le(d,o);const auto shndx=elf_u16le(d,o+6);if(shndx!=0||!no||no>=str.size)continue;const auto p=static_cast<std::size_t>(str.off+no),max=static_cast<std::size_t>(str.size-no);std::size_t n=0;while(n<max&&p+n<d.size()&&d[p+n])++n;if(n==max||p+n>=d.size())continue;if(n==wanted.size()&&std::equal(wanted.begin(),wanted.end(),reinterpret_cast<const char*>(d.data()+p)))return true;}
    }return false;
}
bool elf_unwind_transition_import(std::span<const std::uint8_t>d,const ElfInfo&elf,std::string&which){
    static constexpr std::array<std::string_view,3> names{"_Unwind_RaiseException","__cxa_throw","_Unwind_ForcedUnwind"};
    if(elf.dynamic.state=="RESOLVED")for(const auto&s:elf.dynamic.symbols)if(s.imported)for(auto n:names)if(s.name==n){which=s.name;return true;}
    for(auto n:names)if(elf_has_undefined_dynsym(d,elf,n)){which=std::string(n);return true;}
    return false;
}
bool pe_exec_allocation_protection(std::uint64_t p){return p==0x10||p==0x20||p==0x40||p==0x80;}
std::map<std::uint32_t,std::pair<std::string,std::string>> pe_named_iat(const PeInfo&pe,std::string_view wanted){
    std::map<std::uint32_t,std::pair<std::string,std::string>>out;
    for(const auto&m:pe.imports)for(std::size_t i=0;i<m.functions.size();++i){const auto&fn=m.functions[i];if(!fn.by_ordinal&&fn.name==wanted)out[m.iat_rva+static_cast<std::uint32_t>(i)*8]={m.name,fn.name};}
    return out;
}
std::optional<std::uint32_t> pe_targeted_import_thunk_slot(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,const std::map<std::uint32_t,std::pair<std::string,std::string>>&iat){
    // Bounded direct-thunk resolution only: optional ENDBR64/NOP followed by a
    // RIP-relative unconditional jump through the exact requested IAT slot.
    for(unsigned step=0;step<2;++step){auto x=pe_decode_one(d,pe,rva);if(!x)return{};
        if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR&&x->ins.operand_count_visible){auto slot=pe_rip_mem_rva(*x,x->ops[0]);if(slot&&iat.count(*slot))return slot;return{};}
        if(x->ins.mnemonic!=ZYDIS_MNEMONIC_ENDBR64&&x->ins.mnemonic!=ZYDIS_MNEMONIC_NOP)return{};
        if(rva>0xffffffffu-x->ins.length)return{};
        rva+=x->ins.length;
    }
    return{};
}
std::vector<PeApiCall> pe_targeted_calls_in_function(std::span<const std::uint8_t>d,const PeInfo&pe,PeFuncRange f,std::string_view wanted){
    std::vector<PeApiCall>out;const auto iat=pe_named_iat(pe,wanted);if(iat.empty())return out;
    const auto ins=pe_decode_range(d,pe,f);if(ins.empty())return out;
    std::map<ZydisRegister,std::uint32_t>aliases;std::set<std::uint32_t>seen;
    auto volatile_reg=[](ZydisRegister r){r=pe_large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;};
    for(const auto&x:ins){
        bool emitted_call=false;
        if((x.ins.meta.category==ZYDIS_CATEGORY_CALL||x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR)&&x.ins.operand_count_visible){
            const auto&q=x.ops[0];std::uint32_t slot=0;std::string transfer;
            if(auto r=pe_rip_mem_rva(x,q);r&&iat.count(*r)){slot=*r;transfer=x.ins.meta.category==ZYDIS_CATEGORY_CALL?"call_iat":"tail_jmp_iat";}
            else if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&q.imm.is_relative){if(auto t=pe_rel_target(x);t){auto z=pe_targeted_import_thunk_slot(d,pe,*t,iat);if(z){slot=*z;transfer=x.ins.meta.category==ZYDIS_CATEGORY_CALL?"call_thunk":"tail_jmp_thunk";}}}
            else if(x.ins.meta.category==ZYDIS_CATEGORY_CALL&&q.type==ZYDIS_OPERAND_TYPE_REGISTER){auto z=aliases.find(pe_large(q.reg.value));if(z!=aliases.end()){slot=z->second;transfer="call_iat_register";}}
            if(slot&&seen.insert(x.rva).second){const auto&nm=iat.at(slot);out.push_back({nm.first,nm.second,transfer,x.rva,f.begin,f.end,slot,x.ins.length,x.ins.meta.category==ZYDIS_CATEGORY_CALL});emitted_call=x.ins.meta.category==ZYDIS_CATEGORY_CALL;}
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=pe_large(x.ops[0].reg.value);std::optional<std::uint32_t>v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&q=x.ops[1];if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){auto z=aliases.find(pe_large(q.reg.value));if(z!=aliases.end())v=z->second;}else if(auto r=pe_rip_mem_rva(x,q);r&&iat.count(*r))v=*r;}
            if(v)aliases[dst]=*v;else aliases.erase(dst);
        }
        if(emitted_call){for(auto it=aliases.begin();it!=aliases.end();){if(volatile_reg(it->first))it=aliases.erase(it);else ++it;}}
    }
    return out;
}
bool pe_tls_contains_exec_allocation(std::span<const std::uint8_t>d,const PeInfo&pe,const PeTlsCallback&cb,PeApiCall&hit,std::uint64_t&protection){
    if(!cb.target_va||cb.target_va<pe.image_base||cb.target_va-pe.image_base>0xffffffffull)return false;
    const auto rva=static_cast<std::uint32_t>(cb.target_va-pe.image_base);const auto rf=pe_runtime_func(pe,rva);
    if(!rf.end||rf.begin!=rva)return false;
    const auto calls=pe_targeted_calls_in_function(d,pe,rf,"VirtualAlloc");
    for(const auto&c:calls){auto p=pe_scalar_arg(d,pe,c,3);if(p&&pe_exec_allocation_protection(*p)){hit=c;protection=*p;return true;}}
    return false;
}

struct ContextResumeEvidence {
    bool capability=false;
    bool pc_write=false;
    bool resume_proven=false;
    bool constant_target_observed=false;
    bool target_ambiguous=false;
    std::uint32_t pc_write_count=0;
    std::uint64_t write_site=0;
    std::uint64_t constant_target=0;
    std::optional<std::int64_t> relative_pc_delta;
    std::optional<std::uint64_t> exact_target;
    std::string detail;
};

bool ins_writes_reg(const ZydisDecodedInstruction&ins,const std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT>&ops,ZydisRegister r) {
    r=pe_large(r);
    for(std::uint8_t i=0;i<ins.operand_count_visible;++i){
        const auto&o=ops[i];
        if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE)&&pe_large(o.reg.value)==r)return true;
    }
    return false;
}

bool pe_same_basic_block(const PeCfg&g,std::size_t first,std::size_t last) {
    if(first>=last||last>=g.ins.size())return false;
    std::set<std::uint32_t>targets;
    for(std::size_t i=0;i<g.ins.size();++i){
        const auto&x=g.ins[i];
        if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||x.ins.meta.category==ZYDIS_CATEGORY_COND_BR){
            if(auto t=pe_rel_target(x))targets.insert(*t);
        }
    }
    for(std::size_t i=first+1;i<=last;++i)if(targets.count(g.ins[i].rva))return false;
    for(std::size_t i=first;i<last;++i){
        const auto c=g.ins[i].ins.meta.category;
        if(c==ZYDIS_CATEGORY_CALL||c==ZYDIS_CATEGORY_UNCOND_BR||c==ZYDIS_CATEGORY_COND_BR||c==ZYDIS_CATEGORY_RET)return false;
    }
    return true;
}

bool pe_continue_execution_returns(const PeCfg&g) {
    if(g.ins.empty())return false;
    bool saw_ret=false;
    for(std::size_t ri=0;ri<g.ins.size();++ri){
        if(g.ins[ri].ins.meta.category!=ZYDIS_CATEGORY_RET)continue;
        if(!pe_reachable(g,0,ri))continue;
        saw_ret=true;
        bool proved=false;
        for(std::size_t wi=ri;wi-->0;){
            const auto&x=g.ins[wi];
            if(!ins_writes_reg(x.ins,x.ops,ZYDIS_REGISTER_RAX))continue;
            if(!pe_same_basic_block(g,wi,ri))break;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&
               x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(x.ops[0].reg.value)==ZYDIS_REGISTER_RAX&&
               x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative&&
               static_cast<std::uint32_t>(x.ops[1].imm.value.u)==0xffffffffu)proved=true;
            break;
        }
        if(!proved)return false;
    }
    return saw_ret;
}

ContextResumeEvidence pe_handler_context_evidence(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t handler) {
    ContextResumeEvidence ev;ev.capability=true;
    const auto hf=pe_runtime_func(pe,handler);
    if(!hf.end||hf.begin!=handler){ev.detail="registered callback receives EXCEPTION_POINTERS, but handler lacks an exact RUNTIME_FUNCTION boundary";return ev;}
    const auto g=pe_cfg(d,pe,hf);if(g.ins.empty()){ev.detail="registered callback receives EXCEPTION_POINTERS, but bounded handler decoding failed";return ev;}
    for(std::size_t wi=0;wi<g.ins.size();++wi){
        const auto&x=g.ins[wi];
        for(std::uint8_t oi=0;oi<x.ins.operand_count_visible;++oi){
            const auto&o=x.ops[oi];
            if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||(o.actions&ZYDIS_OPERAND_ACTION_WRITE)==0||o.mem.index!=ZYDIS_REGISTER_NONE||!o.mem.disp.has_displacement||o.mem.disp.value!=0xf8)continue;
            const auto base=pe_large(o.mem.base);if(base==ZYDIS_REGISTER_NONE||base==ZYDIS_REGISTER_RIP)continue;
            bool context_record_exact=false;
            for(std::size_t di=wi;di-->0;){
                const auto&def=g.ins[di];
                if(!ins_writes_reg(def.ins,def.ops,base))continue;
                if(!pe_same_basic_block(g,di,wi))break;
                if(def.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&def.ins.operand_count_visible>=2&&
                   def.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(def.ops[0].reg.value)==base){
                    const auto&s=def.ops[1];
                    context_record_exact=s.type==ZYDIS_OPERAND_TYPE_MEMORY&&s.mem.index==ZYDIS_REGISTER_NONE&&
                        pe_large(s.mem.base)==ZYDIS_REGISTER_RCX&&s.mem.disp.has_displacement&&s.mem.disp.value==8;
                }
                break;
            }
            if(!context_record_exact)continue;
            ev.pc_write=true;ev.write_site=x.rva;
            std::ostringstream q;q<<"exact write to CONTEXT.Rip via EXCEPTION_POINTERS.ContextRecord at RVA 0x"<<std::hex<<x.rva;
            ev.detail=q.str();
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&s=x.ops[1];
                if(s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!s.imm.is_relative){const auto va=s.imm.value.u;if(va>=pe.image_base&&va-pe.image_base<=0xffffffffull&&pe_executable_rva(pe,static_cast<std::uint32_t>(va-pe.image_base)))ev.exact_target=va-pe.image_base;}
            }
            break;
        }
        if(ev.pc_write)break;
    }
    ev.resume_proven=ev.pc_write&&pe_continue_execution_returns(g);
    if(ev.pc_write&&!ev.resume_proven)ev.detail+="; EXCEPTION_CONTINUE_EXECUTION return is not proven on every reachable handler return";
    if(ev.resume_proven)ev.detail+="; every reachable RET has same-basic-block EAX/RAX=-1 (EXCEPTION_CONTINUE_EXECUTION)";
    return ev;
}

bool elf_same_basic_block(const ElfCfg&g,std::size_t first,std::size_t last) {
    if(first>=last||last>=g.ins.size())return false;
    std::set<std::uint64_t>targets;
    for(const auto&x:g.ins){
        if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||x.ins.meta.category==ZYDIS_CATEGORY_COND_BR){
            if(auto t=elf_rel_target(x))targets.insert(*t);
        }
    }
    for(std::size_t i=first+1;i<=last;++i)if(targets.count(g.ins[i].va))return false;
    for(std::size_t i=first;i<last;++i){
        const auto c=g.ins[i].ins.meta.category;
        if(c==ZYDIS_CATEGORY_CALL||c==ZYDIS_CATEGORY_UNCOND_BR||c==ZYDIS_CATEGORY_COND_BR||c==ZYDIS_CATEGORY_RET)return false;
    }
    return true;
}

ContextResumeEvidence elf_siginfo_context_evidence(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t handler) {
    ContextResumeEvidence ev;ev.capability=true;
    const auto*hf=elf_fde_func(elf,handler);
    if(!hf||hf->function_start_va!=handler){ev.detail="SA_SIGINFO callback receives ucontext, but handler lacks an exact FDE boundary";return ev;}
    const auto g=elf_cfg(d,elf,{hf->function_start_va,hf->function_end_va});if(g.ins.empty()){ev.detail="SA_SIGINFO callback receives ucontext, but bounded handler decoding failed";return ev;}
    std::vector<std::size_t>writes;
    for(std::size_t wi=0;wi<g.ins.size();++wi){
        const auto&x=g.ins[wi];
        for(std::uint8_t oi=0;oi<x.ins.operand_count_visible;++oi){
            const auto&o=x.ops[oi];
            if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||(o.actions&ZYDIS_OPERAND_ACTION_WRITE)==0||o.mem.index!=ZYDIS_REGISTER_NONE||!o.mem.disp.has_displacement||o.mem.disp.value!=168)continue;
            auto base=pe_large(o.mem.base);bool exact=base==ZYDIS_REGISTER_RDX;
            if(!exact&&base!=ZYDIS_REGISTER_NONE&&base!=ZYDIS_REGISTER_RIP){
                for(std::size_t di=wi;di-->0;){
                    const auto&def=g.ins[di];if(!ins_writes_reg(def.ins,def.ops,base))continue;if(!elf_same_basic_block(g,di,wi))break;
                    exact=def.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&def.ins.operand_count_visible>=2&&def.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&pe_large(def.ops[1].reg.value)==ZYDIS_REGISTER_RDX;break;
                }
            }
            if(!exact)continue;
            writes.push_back(wi);ev.pc_write=true;ev.write_site=x.va;++ev.pc_write_count;
            std::ostringstream q;q<<"exact write to glibc x86-64 ucontext REG_RIP (+168) at VA 0x"<<std::hex<<x.va;ev.detail=q.str();
            if(x.ins.operand_count_visible>=2){
                const auto&s=x.ops[1];
                if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!s.imm.is_relative){
                    ev.constant_target_observed=true;ev.constant_target=s.imm.value.u;
                    if(elf_exec_va(elf,s.imm.value.u)&&elf_va_off(elf,s.imm.value.u,d.size()))ev.exact_target=s.imm.value.u;
                    else ev.detail+="; constant target "+hx(s.imm.value.u)+" is not executable file-backed artifact code";
                } else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!s.imm.is_relative){
                    auto delta=s.imm.value.s;
                    if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB&&delta==std::numeric_limits<std::int64_t>::min())
                        ev.detail+="; REG_RIP delta overflow is not promoted";
                    else {
                        if(x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)delta=-delta;
                        ev.relative_pc_delta=delta;ev.detail+="; bounded REG_RIP delta="+std::to_string(delta);
                    }
                }
            }
            break;
        }
    }
    if(!ev.pc_write){ev.detail="exact SA_SIGINFO handler has writable ucontext capability, but no exact REG_RIP write was recovered";return ev;}
    bool saw_ret=false,all_rets=false;
    for(const auto wi:writes){
        bool this_all=true,has=false;
        for(std::size_t ri=0;ri<g.ins.size();++ri){if(g.ins[ri].ins.meta.category!=ZYDIS_CATEGORY_RET||!elf_reachable(g,0,ri))continue;has=true;saw_ret=true;if(!elf_dominates(g,wi,ri))this_all=false;}
        if(has&&this_all){all_rets=true;break;}
    }
    ev.resume_proven=saw_ret&&all_rets;
    ev.target_ambiguous=writes.size()>1;
    if(ev.target_ambiguous)ev.detail+="; multiple REG_RIP write sites are reachable, so a single resume target is not claimed";
    if(ev.resume_proven)ev.detail+="; a REG_RIP write dominates every reachable RET, so normal signal return restores a modified context";
    else ev.detail+="; normal return after the REG_RIP write is not proven on every reachable path";
    return ev;
}

// : tiny AArch64 grammar.  This is intentionally not a general
// disassembler/SSA engine: fixed-width decode plus a bounded provenance set.
struct A64Insn { std::uint64_t va=0; std::uint32_t raw=0; };
struct A64Value { std::uint64_t value=0; std::string provenance; };
bool a64_add_i64(std::int64_t& a,std::int64_t b){if((b>0&&a>std::numeric_limits<std::int64_t>::max()-b)||(b<0&&a<std::numeric_limits<std::int64_t>::min()-b))return false;a+=b;return true;}
std::int64_t a64_sext(std::uint64_t v,unsigned bits){const auto m=std::uint64_t(1)<<(bits-1);return static_cast<std::int64_t>((v^m)-m);}
std::optional<A64Insn> a64_one(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t va){auto o=elf_va_off(elf,va,d.size());if(!o||*o+4>d.size()||(va&3))return{};std::uint32_t w=std::uint32_t(d[*o])|(std::uint32_t(d[*o+1])<<8)|(std::uint32_t(d[*o+2])<<16)|(std::uint32_t(d[*o+3])<<24);return A64Insn{va,w};}
std::vector<A64Insn> a64_range(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t begin,std::uint64_t end,std::size_t cap=4096){std::vector<A64Insn>v;if(end<=begin||end-begin>cap*4ull)return v;for(auto va=begin;va+4<=end&&v.size()<cap;va+=4){auto x=a64_one(d,elf,va);if(!x)return{};v.push_back(*x);}return v;}
bool a64_bl(const A64Insn&x){return (x.raw&0xfc000000u)==0x94000000u;}
bool a64_b(const A64Insn&x){return (x.raw&0xfc000000u)==0x14000000u;}
bool a64_bcond(const A64Insn&x){return (x.raw&0xff000010u)==0x54000000u||((x.raw&0x7e000000u)==0x34000000u);}
bool a64_ret(const A64Insn&x){return (x.raw&0xfffffc1fu)==0xd65f0000u;}
bool a64_br(const A64Insn&x){return (x.raw&0xfffffc1fu)==0xd61f0000u;}
bool a64_svc(const A64Insn&x){return (x.raw&0xffe0001fu)==0xd4000001u;}
std::optional<std::uint64_t> a64_branch_target(const A64Insn&x){if(a64_bl(x)||a64_b(x)){auto delta=a64_sext(x.raw&0x03ffffffu,26)*4;return add_signed_u64(x.va,delta);}if((x.raw&0xff000010u)==0x54000000u||((x.raw&0x7e000000u)==0x34000000u)){auto delta=a64_sext((x.raw>>5)&0x7ffffu,19)*4;return add_signed_u64(x.va,delta);}return{};}
bool a64_movz(const A64Insn&x,unsigned&rd,std::uint64_t&value){if((x.raw&0x7f800000u)!=0x52800000u)return false;rd=x.raw&31u;const auto imm=(x.raw>>5)&0xffffu,hw=(x.raw>>21)&3u;value=std::uint64_t(imm)<<(16*hw);if(!(x.raw>>31))value&=0xffffffffu;return true;}
bool a64_mov_reg(const A64Insn&x,unsigned&rd,unsigned&rs){const auto base=x.raw&0x7fe0ffe0u;if(base!=0x2a0003e0u)return false;rd=x.raw&31u;rs=(x.raw>>16)&31u;return true;}
bool a64_adr(const A64Insn&x,unsigned&rd,std::uint64_t&value){const auto tag=x.raw&0x9f000000u;if(tag!=0x10000000u&&tag!=0x90000000u)return false;rd=x.raw&31u;const auto immlo=(x.raw>>29)&3u,immhi=(x.raw>>5)&0x7ffffu;const auto imm=a64_sext((std::uint64_t(immhi)<<2)|immlo,21);if(tag==0x10000000u){auto v=add_signed_u64(x.va,imm);if(!v)return false;value=*v;}else{auto v=add_signed_u64(x.va&~std::uint64_t(0xfff),imm*4096);if(!v)return false;value=*v;}return true;}
bool a64_add_imm(const A64Insn&x,unsigned&rd,unsigned&rn,std::uint64_t&imm,bool&sub){const auto tag=x.raw&0x7f000000u;if(tag!=0x11000000u&&tag!=0x51000000u)return false;rd=x.raw&31u;rn=(x.raw>>5)&31u;imm=(x.raw>>10)&0xfffu;if(x.raw&(1u<<22))imm<<=12;sub=tag==0x51000000u;return true;}
bool a64_ldr_literal(const A64Insn&x,unsigned&rt,std::uint64_t&target){if((x.raw&0xff000000u)!=0x58000000u)return false;rt=x.raw&31u;auto t=add_signed_u64(x.va,a64_sext((x.raw>>5)&0x7ffffu,19)*4);if(!t)return false;target=*t;return true;}
struct A64Mem { bool load=false,store=false; unsigned rt=0,rn=0; std::uint64_t offset=0; unsigned bytes=0; };
std::optional<A64Mem> a64_mem_unsigned(const A64Insn&x){const auto top=x.raw&0xffc00000u;A64Mem m;m.rt=x.raw&31u;m.rn=(x.raw>>5)&31u;const auto imm=(x.raw>>10)&0xfffu;if(top==0xf9400000u){m.load=true;m.bytes=8;m.offset=std::uint64_t(imm)*8;}else if(top==0xf9000000u){m.store=true;m.bytes=8;m.offset=std::uint64_t(imm)*8;}else if(top==0xb9400000u){m.load=true;m.bytes=4;m.offset=std::uint64_t(imm)*4;}else if(top==0xb9000000u){m.store=true;m.bytes=4;m.offset=std::uint64_t(imm)*4;}else return{};return m;}
bool a64_control_or_store(const A64Insn&x){if(a64_bl(x)||a64_b(x)||a64_bcond(x)||a64_ret(x)||a64_br(x)||a64_svc(x))return true;auto m=a64_mem_unsigned(x);return m&&m->store;}
bool a64_maybe_writes(const A64Insn&x,unsigned reg){if(reg==31||a64_control_or_store(x))return false;return (x.raw&31u)==reg;}
bool a64_call_clobbers(unsigned r){return r<=18;}
std::optional<std::uint64_t> a64_file_pointer_any(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t slot){
    auto o=elf_va_off(elf,slot,d.size());if(!o||*o+8>d.size())return{};std::uint64_t raw=0;std::memcpy(&raw,d.data()+*o,8);if(elf_va_extent(elf,raw))return raw;
    if(elf.dynamic.state=="RESOLVED")for(const auto&r:elf.dynamic.relocations){const bool relative=(elf.machine==183&&r.type==1027)||(elf.machine==62&&r.type==8);if(r.target_va==slot&&relative&&r.has_addend&&r.addend>=0&&elf_va_extent(elf,static_cast<std::uint64_t>(r.addend)))return static_cast<std::uint64_t>(r.addend);}
    return{};
}
std::optional<A64Value> a64_value_before(std::span<const std::uint8_t>d,const ElfInfo&elf,const std::vector<A64Insn>&ins,std::size_t before,unsigned wanted,std::size_t budget=128){unsigned cur=wanted;std::int64_t add=0;unsigned copies=0,spills=0;std::size_t seen=0;for(std::size_t z=before;z-->0&&seen++<budget;){const auto&x=ins[z];if(a64_bl(x)&&a64_call_clobbers(cur))return{};unsigned rd=0,rs=0;std::uint64_t v=0,imm=0;bool sub=false;
        if(a64_movz(x,rd,v)&&rd==cur){auto q=add_signed_u64(v,add);return q?std::optional<A64Value>(A64Value{*q,"constant/MOVZ"}):std::nullopt;}
        if(a64_mov_reg(x,rd,rs)&&rd==cur){if(++copies>1)return{};if(rs==31){auto q=add_signed_u64(0,add);return q?std::optional<A64Value>(A64Value{*q,"constant/XZR"}):std::nullopt;}cur=rs;continue;}
        if(a64_add_imm(x,rd,rs,imm,sub)&&rd==cur){if(sub){if(imm>std::uint64_t(std::numeric_limits<std::int64_t>::max()))return{};if(!a64_add_i64(add,-static_cast<std::int64_t>(imm)))return{};}else{if(imm>std::uint64_t(std::numeric_limits<std::int64_t>::max())||!a64_add_i64(add,static_cast<std::int64_t>(imm)))return{};}cur=rs;continue;}
        if(a64_adr(x,rd,v)&&rd==cur){auto q=add_signed_u64(v,add);return q?std::optional<A64Value>(A64Value{*q,"ADR/ADRP+ADD"}):std::nullopt;}
        std::uint64_t lit=0;if(a64_ldr_literal(x,rd,lit)&&rd==cur){auto fv=elf_file_pointer_value(d,elf,lit);if(!fv){auto o=elf_va_off(elf,lit,d.size());if(o&&*o+8<=d.size()){std::uint64_t raw=0;std::memcpy(&raw,d.data()+*o,8);fv=raw;}}if(!fv)return{};auto q=add_signed_u64(*fv,add);return q?std::optional<A64Value>(A64Value{*q,"literal load"}):std::nullopt;}
        auto mem=a64_mem_unsigned(x);if(mem&&mem->load&&mem->rt==cur&&mem->bytes==8){if(mem->rn==31&&spills<1){const auto slot=mem->offset;bool found=false;for(std::size_t y=z;y-->0;){auto sm=a64_mem_unsigned(ins[y]);if(sm&&sm->store&&sm->rn==31&&sm->offset==slot&&sm->bytes==8){cur=sm->rt;++spills;found=true;break;}if(z-y>64)break;}if(found)continue;}
            auto base=a64_value_before(d,elf,ins,z,mem->rn,48);if(base){auto addr=add_signed_u64(base->value,static_cast<std::int64_t>(mem->offset));if(addr){auto fv=a64_file_pointer_any(d,elf,*addr);if(fv){auto q=add_signed_u64(*fv,add);return q?std::optional<A64Value>(A64Value{*q,"bounded table lookup"}):std::nullopt;}}}return{};}
        if(a64_maybe_writes(x,cur))return{};
    }return{};}

struct A64Cfg {std::vector<A64Insn> ins;std::map<std::uint64_t,std::size_t>by;std::vector<std::vector<std::size_t>>edges;};
A64Cfg a64_cfg(std::vector<A64Insn>ins){A64Cfg g;g.ins=std::move(ins);g.edges.resize(g.ins.size());for(std::size_t i=0;i<g.ins.size();++i)g.by[g.ins[i].va]=i;auto edge=[&](std::size_t a,std::uint64_t va){auto it=g.by.find(va);if(it!=g.by.end())g.edges[a].push_back(it->second);};for(std::size_t i=0;i<g.ins.size();++i){const auto&x=g.ins[i];if(a64_ret(x)||a64_br(x))continue;if(a64_b(x)){if(auto t=a64_branch_target(x))edge(i,*t);continue;}if(a64_bcond(x)){if(auto t=a64_branch_target(x))edge(i,*t);if(i+1<g.ins.size())g.edges[i].push_back(i+1);continue;}if(i+1<g.ins.size())g.edges[i].push_back(i+1);}return g;}
bool a64_reachable(const A64Cfg&g,std::size_t a,std::size_t b,std::optional<std::size_t>blocked={}){if(a>=g.ins.size()||b>=g.ins.size()||blocked==a)return false;std::vector<std::uint8_t>seen(g.ins.size());std::vector<std::size_t>q{a};seen[a]=1;for(std::size_t p=0;p<q.size();++p){auto u=q[p];if(u==b)return true;for(auto v:g.edges[u])if(!seen[v]&&(!blocked||v!=*blocked)){seen[v]=1;q.push_back(v);}}return false;}
bool a64_dominates(const A64Cfg&g,std::size_t dom,std::size_t node){if(g.ins.empty()||dom>=g.ins.size()||node>=g.ins.size()||!a64_reachable(g,0,node))return false;if(dom==0)return true;return !a64_reachable(g,0,node,dom);}

std::map<std::uint64_t,std::string> a64_named_got(const ElfInfo&elf,std::initializer_list<std::string_view>names){
    std::map<std::uint64_t,std::string>out;
    if(elf.dynamic.state=="RESOLVED")for(const auto&r:elf.dynamic.relocations){if(r.symbol_index>=elf.dynamic.symbols.size())continue;const auto&s=elf.dynamic.symbols[r.symbol_index];if(!s.imported)continue;for(auto n:names)if(s.name==n){out[r.target_va]=s.name;break;}}
    // The loader plane deliberately survives strict dynsym failure.  Join a
    // raw loader symbol fact to its DT_JMPREL loader-pointer fact only by the
    // exact relocation symbol index; do not guess PLT order from section names.
    if(elf.implicit_exec.state=="RESOLVED"||elf.implicit_exec.state=="PARTIAL"){
        std::map<std::uint64_t,std::string> raw_names;
        for(const auto&f:elf.implicit_exec.facts)if(f.relation=="raw_loader_symbol_record")for(auto n:names)if(f.target_name==n)raw_names[f.source_index]=f.target_name;
        for(const auto&f:elf.implicit_exec.facts)if(f.relation=="loader_pointer_state"&&f.source_kind=="DT_JMPREL_RECORD")if(auto it=raw_names.find(f.source_index);it!=raw_names.end())out[f.target_va]=it->second;
    }
    return out;
}
std::optional<std::string> a64_plt_name(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t va,const std::map<std::uint64_t,std::string>&got){auto a=a64_one(d,elf,va),b=a64_one(d,elf,va+4);if(!a||!b)return{};unsigned rd=0;std::uint64_t page=0;if(!a64_adr(*a,rd,page)||rd!=16||(a->raw&0x9f000000u)!=0x90000000u)return{};auto m=a64_mem_unsigned(*b);if(!m||!m->load||m->rt!=17||m->rn!=16||m->bytes!=8)return{};auto slot=add_signed_u64(page,static_cast<std::int64_t>(m->offset));if(!slot)return{};auto it=got.find(*slot);return it==got.end()?std::optional<std::string>{}:std::optional<std::string>{it->second};}
struct A64ApiCall {std::string name;std::uint64_t site=0,func_begin=0,func_end=0;};
std::vector<A64ApiCall> a64_calls(std::span<const std::uint8_t>d,const ElfInfo&elf){std::vector<A64ApiCall>out;if(!elf.valid||!elf.elf64||!elf.little_endian||elf.machine!=183)return out;const auto got=a64_named_got(elf,{"sigaction","signal","mprotect"});if(got.empty())return out;std::set<std::uint64_t>seen;for(const auto&fde:elf.unwind.fdes){if(!fde.function_file_backed||!fde.function_size||fde.function_size>16384)continue;auto ins=a64_range(d,elf,fde.function_start_va,fde.function_end_va);for(const auto&x:ins){if(!a64_bl(x))continue;auto t=a64_branch_target(x);if(!t)continue;auto n=a64_plt_name(d,elf,*t,got);if(n&&seen.insert(x.va).second)out.push_back({*n,x.va,fde.function_start_va,fde.function_end_va});}}return out;}
std::optional<A64Value> a64_call_arg(std::span<const std::uint8_t>d,const ElfInfo&elf,const A64ApiCall&c,unsigned arg){if(arg>7)return{};auto ins=a64_range(d,elf,c.func_begin,c.func_end);std::size_t at=ins.size();for(std::size_t i=0;i<ins.size();++i)if(ins[i].va==c.site){at=i;break;}if(at==ins.size())return{};return a64_value_before(d,elf,ins,at,arg);}
std::optional<ElfSigactionValue> a64_glibc_sigaction(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t act){if(elf.machine!=183||std::find(elf.needed.begin(),elf.needed.end(),"libc.so.6")==elf.needed.end())return{};auto ex=elf_va_extent(elf,act);if(!ex||ex->second<144||ex->first>d.size()||144>d.size()-ex->first)return{};auto h=elf_file_pointer_value(d,elf,act);if(!h)return{};std::uint32_t flags=0;std::memcpy(&flags,d.data()+ex->first+136,4);ElfSigactionValue v;v.handler=*h;v.flags=flags;v.flags_exact=true;v.source="file-backed glibc AArch64 struct sigaction";return v;}

struct A64ContextEvidence {bool pc_write=false,resume=false,ambiguous=false,invalid_constant=false;std::optional<std::uint64_t>target;std::optional<std::int64_t>delta;std::uint64_t site=0;std::string detail;};
bool a64_base_is_context(const std::vector<A64Insn>&ins,std::size_t at,unsigned r){if(r==2)return true;unsigned rd=0,rs=0;for(std::size_t z=at;z-->0&&at-z<=32;){if(a64_mov_reg(ins[z],rd,rs)&&rd==r)return rs==2;if(a64_maybe_writes(ins[z],r))return false;}return false;}
std::optional<std::int64_t> a64_context_delta(const std::vector<A64Insn>&ins,std::size_t at,unsigned src){for(std::size_t z=at;z-->0&&at-z<=24;){unsigned rd=0,rn=0;std::uint64_t imm=0;bool sub=false;if(a64_add_imm(ins[z],rd,rn,imm,sub)&&rd==src&&rn==src){for(std::size_t y=z;y-->0&&z-y<=12;){auto m=a64_mem_unsigned(ins[y]);if(m&&m->load&&m->rt==src&&m->offset==440&&a64_base_is_context(ins,y,m->rn)){if(imm>std::uint64_t(std::numeric_limits<std::int64_t>::max()))return{};return sub?-static_cast<std::int64_t>(imm):static_cast<std::int64_t>(imm);}if(a64_maybe_writes(ins[y],src))break;}return{};}if(a64_maybe_writes(ins[z],src))break;}return{};}
A64ContextEvidence a64_context_evidence(std::span<const std::uint8_t>d,const ElfInfo&elf,std::uint64_t handler,std::optional<std::uint64_t>fault={}){A64ContextEvidence ev;const auto*hf=elf_fde_func(elf,handler);std::vector<A64Insn>ins;if(hf&&hf->function_start_va==handler)ins=a64_range(d,elf,hf->function_start_va,hf->function_end_va);else{for(std::size_t i=0;i<128;++i){auto x=a64_one(d,elf,handler+i*4);if(!x)break;ins.push_back(*x);}}if(ins.empty()){ev.detail="handler decode unavailable";return ev;}auto g=a64_cfg(ins);std::vector<std::size_t>writes;std::set<std::uint64_t>targets;for(std::size_t i=0;i<ins.size();++i){if(!a64_reachable(g,0,i))continue;auto m=a64_mem_unsigned(ins[i]);if(!m||!m->store||m->bytes!=8||m->offset!=440||!a64_base_is_context(ins,i,m->rn))continue;ev.pc_write=true;ev.site=ins[i].va;writes.push_back(i);auto v=a64_value_before(d,elf,ins,i,m->rt);if(v){if(elf_exec_va(elf,v->value)&&elf_va_off(elf,v->value,d.size()))targets.insert(v->value);else ev.invalid_constant=true;}else if(auto delta=a64_context_delta(ins,i,m->rt)){ev.delta=*delta;if(fault){auto t=add_signed_u64(*fault,*delta);if(t&&elf_exec_va(elf,*t)&&elf_va_off(elf,*t,d.size()))targets.insert(*t);else ev.invalid_constant=true;}}}
    ev.ambiguous=writes.size()>1||targets.size()>1;bool all_rets=false;for(auto wi:writes){bool any=false,all=true;for(std::size_t r=0;r<ins.size();++r)if(a64_ret(ins[r])&&a64_reachable(g,0,r)){any=true;if(!a64_dominates(g,wi,r))all=false;}if(any&&all){all_rets=true;break;}}ev.resume=ev.pc_write&&all_rets;if(!ev.ambiguous&&targets.size()==1)ev.target=*targets.begin();std::ostringstream q;q<<"AArch64 glibc ucontext uc_mcontext.pc (+440) write_sites="<<writes.size()<<", normal_return="<<(ev.resume?"true":"false");if(ev.target)q<<", exact_target="<<hx(*ev.target);if(ev.delta)q<<", pc_delta="<<*ev.delta;if(ev.invalid_constant)q<<", invalid_or_unresolved_target=true";ev.detail=q.str();return ev;}

struct A64Fault {std::uint64_t va=0;std::string kind;};
std::vector<A64Fault> a64_null_faults(std::span<const std::uint8_t>d,const ElfInfo&elf,const std::vector<A64Insn>&ins){std::vector<A64Fault>out;for(std::size_t i=0;i<ins.size()&&out.size()<32;++i){auto m=a64_mem_unsigned(ins[i]);if(!m||!m->store||m->offset!=0||m->rn==31)continue;auto base=a64_value_before(d,elf,ins,i,m->rn);if(!base||base->value!=0||elf_initial_load_maps(elf,0))continue;out.push_back({ins[i].va,"CONSTANT_NULL_WRITE_SIGSEGV"});}return out;}
bool a64_has_svc_candidate(std::span<const std::uint8_t>d,const ElfInfo&elf){std::uint64_t scanned=0;constexpr std::uint64_t cap=32ull*1024*1024;for(const auto&s:elf.segments){if(s.type!=1||(s.flags&1u)==0||s.offset>=d.size())continue;auto n=std::min<std::uint64_t>(s.file_size,d.size()-s.offset);auto take=std::min<std::uint64_t>(n,cap-scanned);for(std::uint64_t p=0;p+4<=take;p+=4){const auto o=static_cast<std::size_t>(s.offset+p);const std::uint32_t w=std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);if((w&0xffe0001fu)==0xd4000001u)return true;}scanned+=take;if(scanned>=cap)break;}return false;}

void analyze_a64_wrapper_signals(std::span<const std::uint8_t>d,const ElfInfo&elf,const std::string&artifact,ExceptionalExecutionInfo&out){auto calls=a64_calls(d,elf);for(const auto&c:calls){if(c.name!="sigaction")continue;auto sn=a64_call_arg(d,elf,c,0),act=a64_call_arg(d,elf,c,1);ExceptionalExecutionFact x;x.platform="LINUX_ELF_AARCH64";x.mechanism="POSIX_SIGACTION_AARCH64";x.trigger_kind="HANDLER_REGISTRATION";x.registration_site=elf_va_ref(c.site,4,"AArch64 sigaction call",artifact);x.provenance="AArch64 BL->PLT relocation + bounded x0/x1 provenance";if(!sn||!sane_linux_signal(sn->value)||!act){x.evidence_state="REFUSED";x.priority="INFORMATIONAL";x.refusal_reason="signal/action arguments exceed bounded AArch64 provenance";exceptional_add(out,std::move(x));continue;}auto sa=a64_glibc_sigaction(d,elf,act->value);if(!sa||!elf_exec_va(elf,sa->handler)){x.evidence_state="REFUSED";x.priority="INFORMATIONAL";x.refusal_reason="glibc AArch64 sigaction object does not resolve one executable handler";exceptional_add(out,std::move(x));continue;}x.handler=elf_va_ref(sa->handler,1,"exact AArch64 sigaction handler",artifact);x.evidence_state="REGISTRATION_HANDLER_EXACT";x.priority="INFORMATIONAL";x.priority_reason="X1 registration is not trigger/dispatch evidence";x.detail="signal="+linux_signal_name(static_cast<int>(sn->value))+", flags="+hx(sa->flags)+", SA_SIGINFO="+((sa->flags&4u)?std::string("true"):std::string("false"))+", handler_provenance="+sa->source;exceptional_add(out,std::move(x));
        auto ins=a64_range(d,elf,c.func_begin,c.func_end);if(ins.empty())continue;auto g=a64_cfg(ins);auto ci=g.by.find(c.site);if(ci==g.by.end())continue;auto faults=a64_null_faults(d,elf,ins);for(const auto&f:faults){ExceptionalExecutionFact t;t.platform="LINUX_ELF_AARCH64";t.mechanism="AARCH64_FAULT_TRIGGER";t.trigger_kind=f.kind;t.trigger_location=elf_va_ref(f.va,4,"exact AArch64 constant-null store",artifact);t.evidence_state="TRIGGER_PROVEN";t.priority="INFORMATIONAL";t.priority_reason="X2 trigger is separate from registration/dispatch";t.provenance="bounded AArch64 register provenance + PT_LOAD geometry";exceptional_add(out,std::move(t));auto fi=g.by.find(f.va);if(fi==g.by.end()||static_cast<int>(sn->value)!=11||!a64_dominates(g,ci->second,fi->second))continue;ExceptionalExecutionFact d3;d3.platform="LINUX_ELF_AARCH64";d3.mechanism="POSIX_SIGACTION_AARCH64";d3.trigger_kind=f.kind;d3.trigger_location=elf_va_ref(f.va,4,"exact compatible SIGSEGV trigger",artifact);d3.registration_site=elf_va_ref(c.site,4,"dominating sigaction registration",artifact);d3.handler=elf_va_ref(sa->handler,1,"exact registered handler",artifact);d3.protected_range=elf_va_ref(c.func_begin,c.func_end-c.func_begin,"bounded AArch64 caller CFG",artifact);d3.evidence_state="TRIGGER_HANDLER_CORRELATED";d3.priority="HIGH";d3.priority_reason="X3 exact compatible trigger is dominated by the exact same-signal registration";d3.provenance="AArch64 ABI + bounded direct CFG dominance";exceptional_add(out,std::move(d3));if(!(sa->flags&4u))continue;auto ce=a64_context_evidence(d,elf,sa->handler,f.va);ExceptionalExecutionFact cr;cr.platform="LINUX_ELF_AARCH64";cr.mechanism="POSIX_SIGACTION_AARCH64_CONTEXT_RESUME";cr.trigger_kind=f.kind;cr.trigger_location=elf_va_ref(f.va,4,"closed SIGSEGV trigger",artifact);cr.registration_site=elf_va_ref(c.site,4,"SA_SIGINFO registration",artifact);cr.handler=elf_va_ref(sa->handler,1,"SA_SIGINFO handler",artifact);cr.context_mutation_evidence=ce.detail;cr.provenance="glibc AArch64 ucontext_t ABI: uc_mcontext@+176, mcontext.pc@+264 => PC@+440 + bounded handler provenance";if(ce.pc_write&&ce.resume&&!ce.ambiguous&&ce.target){cr.evidence_state="CONTEXT_PC_REWRITE_CONFIRMED";cr.evidence_level="X4";cr.priority="HIGH";cr.priority_reason="X3 dispatch plus one exact executable/file-backed AArch64 ucontext PC target and normal signal return";cr.landing_pad=elf_va_ref(*ce.target,1,"exact AArch64 ucontext PC resume target",artifact);cr.resume_semantics="normal signal return restores the modified AArch64 PC";}else{cr.evidence_state="CONTEXT_CONTROL_CAPABILITY";cr.evidence_level=ce.pc_write?"X4":"X1";cr.priority="INFORMATIONAL";cr.priority_reason=ce.ambiguous?"multiple AArch64 ucontext PC writes/targets are not collapsed":ce.invalid_constant?"ucontext PC target is not executable/file-backed":"SA_SIGINFO capability does not itself prove a PC redirect";if(ce.ambiguous)cr.ambiguity="multiple context targets";if(ce.invalid_constant)cr.refusal_reason="resume target fails executable/file-backed validation";}exceptional_add(out,std::move(cr));}}
}

struct A64RawReg {std::size_t index=0;std::uint64_t site=0,handler=0;int signal=0;std::uint64_t flags=0;};
std::vector<A64Insn> a64_entry_linear(std::span<const std::uint8_t>d,const ElfInfo&elf,bool&limited){std::vector<A64Insn>v;auto va=elf.entry;std::set<std::uint64_t>seen;for(std::size_t i=0;i<8192;++i){if(!seen.insert(va).second)break;auto x=a64_one(d,elf,va);if(!x)break;v.push_back(*x);if(a64_ret(*x)||a64_br(*x))break;if(a64_b(*x)){auto t=a64_branch_target(*x);if(!t)break;va=*t;continue;}if(a64_bcond(*x)){limited=true;break;}if(a64_svc(*x)){auto nr=a64_value_before(d,elf,v,v.size()-1,8,64);if(nr&&(nr->value==93||nr->value==94))break;}va+=4;}if(v.size()>=8192)limited=true;return v;}
std::optional<A64RawReg> a64_raw_registration(std::span<const std::uint8_t>d,const ElfInfo&elf,const std::vector<A64Insn>&ins,std::size_t i){if(i>=ins.size()||!a64_svc(ins[i]))return{};auto nr=a64_value_before(d,elf,ins,i,8,64);if(!nr||nr->value!=134)return{};auto sn=a64_value_before(d,elf,ins,i,0,64),act=a64_value_before(d,elf,ins,i,1,64),old=a64_value_before(d,elf,ins,i,2,64),ss=a64_value_before(d,elf,ins,i,3,64);if(!sn||!sane_linux_signal(sn->value)||!act||!old||old->value||!ss||ss->value!=8)return{};auto ex=elf_va_extent(elf,act->value);if(!ex||ex->second<32||ex->first+32>d.size())return{};auto h=elf_file_pointer_value(d,elf,act->value);if(!h||!elf_exec_va(elf,*h))return{};std::uint64_t flags=0;std::memcpy(&flags,d.data()+ex->first+8,8);return A64RawReg{i,ins[i].va,*h,static_cast<int>(sn->value),flags};}
void analyze_a64_raw_signals(std::span<const std::uint8_t>d,const ElfInfo&elf,const std::string&artifact,ExceptionalExecutionInfo&out){bool limited=false;auto ins=a64_entry_linear(d,elf,limited);if(ins.empty())return;std::vector<A64RawReg>regs;for(std::size_t i=0;i<ins.size();++i)if(auto r=a64_raw_registration(d,elf,ins,i))regs.push_back(*r);for(const auto&r:regs){ExceptionalExecutionFact x;x.platform="LINUX_ELF_AARCH64";x.mechanism="LINUX_RT_SIGACTION_AARCH64_SYSCALL";x.trigger_kind="HANDLER_REGISTRATION";x.registration_site=elf_va_ref(r.site,4,"raw AArch64 rt_sigaction svc",artifact);x.handler=elf_va_ref(r.handler,1,"raw rt_sigaction handler",artifact);x.evidence_state="REGISTRATION_HANDLER_EXACT";x.priority="INFORMATIONAL";x.priority_reason="X1 raw registration remains inventory";x.provenance="entry-rooted bounded AArch64 SVC + x8=134, x0..x3 exact + kernel sigaction layout";x.detail="signal="+linux_signal_name(r.signal)+", flags="+hx(r.flags)+", code_walk_limited="+(limited?std::string("true"):std::string("false"));exceptional_add(out,std::move(x));}
    auto faults=a64_null_faults(d,elf,ins);for(const auto&f:faults){ExceptionalExecutionFact t;t.platform="LINUX_ELF_AARCH64";t.mechanism="AARCH64_FAULT_TRIGGER";t.trigger_kind=f.kind;t.trigger_location=elf_va_ref(f.va,4,"exact AArch64 constant-null store",artifact);t.evidence_state="TRIGGER_PROVEN";t.priority="INFORMATIONAL";t.priority_reason="X2 exact fault is not dispatch";t.provenance="entry-rooted bounded AArch64 provenance";exceptional_add(out,std::move(t));std::size_t fi=0;for(;fi<ins.size();++fi)if(ins[fi].va==f.va)break;const A64RawReg*active=nullptr;for(const auto&r:regs)if(r.index<fi&&r.signal==11)active=&r;if(!active)continue;ExceptionalExecutionFact x;x.platform="LINUX_ELF_AARCH64";x.mechanism="LINUX_RT_SIGACTION_AARCH64_SYSCALL";x.trigger_kind=f.kind;x.trigger_location=elf_va_ref(f.va,4,"compatible raw SIGSEGV trigger",artifact);x.registration_site=elf_va_ref(active->site,4,"active raw rt_sigaction",artifact);x.handler=elf_va_ref(active->handler,1,"exact raw handler",artifact);x.evidence_state="TRIGGER_HANDLER_CORRELATED";x.priority="HIGH";x.priority_reason="X3 same linear bounded path reaches registration before exact SIGSEGV";x.provenance="raw AArch64 syscall registration + exact fault ordering";exceptional_add(out,std::move(x));if(!(active->flags&4u))continue;auto ce=a64_context_evidence(d,elf,active->handler,f.va);ExceptionalExecutionFact cr;cr.platform="LINUX_ELF_AARCH64";cr.mechanism="LINUX_RT_SIGACTION_AARCH64_CONTEXT_RESUME";cr.trigger_kind=f.kind;cr.trigger_location=elf_va_ref(f.va,4,"raw SIGSEGV trigger",artifact);cr.registration_site=elf_va_ref(active->site,4,"raw SA_SIGINFO registration",artifact);cr.handler=elf_va_ref(active->handler,1,"raw SA_SIGINFO handler",artifact);cr.context_mutation_evidence=ce.detail;cr.provenance="Linux AArch64 raw rt_sigaction + glibc-compatible signal frame ucontext PC@+440 handler grammar";if(ce.pc_write&&ce.resume&&!ce.ambiguous&&ce.target){cr.evidence_state="CONTEXT_PC_REWRITE_CONFIRMED";cr.evidence_level="X4";cr.priority="HIGH";cr.priority_reason="X3 plus exact single executable resume target";cr.landing_pad=elf_va_ref(*ce.target,1,"exact raw AArch64 resume target",artifact);}else{cr.evidence_state="CONTEXT_CONTROL_CAPABILITY";cr.evidence_level=ce.pc_write?"X4":"X1";cr.priority="INFORMATIONAL";cr.priority_reason=ce.ambiguous?"two targets are ambiguous":ce.invalid_constant?"resume target is non-executable":"handler does not prove PC change and normal return";if(ce.ambiguous)cr.ambiguity="multiple context targets";if(ce.invalid_constant)cr.refusal_reason="resume target fails executable/file-backed validation";}exceptional_add(out,std::move(cr));}}

struct A64ProtectSurface {std::uint64_t noaccess=0,writable=0,func_begin=0,func_end=0;};
std::optional<A64ProtectSurface> a64_protected_page_surface(std::span<const std::uint8_t>d,const ElfInfo&elf){auto calls=a64_calls(d,elf);std::map<std::uint64_t,std::vector<const A64ApiCall*>>by;for(const auto&c:calls)if(c.name=="mprotect")by[c.func_begin].push_back(&c);for(const auto&[fb,vc]:by){const A64ApiCall*no=nullptr,*wr=nullptr;for(auto*c:vc){auto p=a64_call_arg(d,elf,*c,2);if(!p)continue;if(p->value==0)no=c;else if(p->value&2u)wr=c;}if(no&&wr)return A64ProtectSurface{no->site,wr->site,fb,no->func_end};}return{};}

}


ExceptionalExecutionInfo analyze_pe_exception_flow(
    std::span<const std::uint8_t> data,
    const PeInfo& pe,
    const std::string& artifact_identity) {
    ExceptionalExecutionInfo out;
    if(!pe.valid)return out;
    if(!(pe.machine==0x8664||pe.machine==0x014c)){out.analysis_limited=true;out.error="PE exceptional-flow analyzer supports x86/x64 metadata and x64 code correlation only";exceptional_finish(out);return out;}

    // x64 pdata/unwind is metadata-only until a concrete exceptional trigger is
    // related to it.  No C++ language semantics or scope table is interpreted.
    if(pe.pe64&&pe.machine==0x8664){
        std::set<std::tuple<std::uint32_t,std::uint32_t,std::uint32_t>>seen;
        for(const auto&rf:pe.exception.runtime_functions){
            std::string error;auto uh=pe_unwind_handler(data,pe,rf.unwind_rva,error);
            if(!error.empty()){out.analysis_limited=true;if(out.error.empty())out.error="one or more x64 UNWIND_INFO records could not be bounded: "+error;continue;}
            if(!uh||!pe_executable_rva(pe,uh->handler_rva))continue;
            if(!seen.insert({rf.begin_rva,rf.end_rva,uh->handler_rva}).second)continue;
            ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism="PE_X64_UNWIND_HANDLER";f.trigger_kind="POTENTIAL_EXCEPTION_IN_PROTECTED_RANGE";
            const auto hf=pe_runtime_func(pe,uh->handler_rva);f.handler=pe_rva_ref(uh->handler_rva,hf.end&&hf.begin==uh->handler_rva?hf.end-hf.begin:1,"UNWIND_INFO language/exception handler",artifact_identity);
            f.protected_range=pe_rva_ref(rf.begin_rva,rf.end_rva-rf.begin_rva,"RUNTIME_FUNCTION protected range",artifact_identity);
            f.protected_function=hx(rf.begin_rva);f.resume_semantics="OS_UNWIND_DISPATCH; concrete landing/resume target not interpreted";f.evidence_state="EXACT_METADATA";f.provenance="PE exception directory -> RUNTIME_FUNCTION -> bounded UNWIND_INFO";f.priority="INFORMATIONAL";f.priority_reason="compiler-generated unwind/exception metadata is ordinary baseline and does not identify a concrete fault site";
            f.detail="UNWIND_INFO flags="+hx(uh->flags)+", unwind_rva="+hx(uh->unwind_rva)+", chain_hops="+std::to_string(uh->chain_hops);exceptional_add(out,std::move(f));
        }
    }

    // SafeSEH is meaningful only for PE32.  SEHandlerTable is a VA to a table
    // of handler RVAs; merely being whitelisted remains informational.
    if(!pe.pe64&&pe.machine==0x014c&&pe.load_config.present&&pe.load_config.seh_table&&pe.load_config.seh_count){
        constexpr std::uint64_t cap=1u<<20;const auto count=pe.load_config.seh_count;
        if(count>cap||pe.load_config.seh_table<pe.image_base||pe.load_config.seh_table-pe.image_base>0xffffffffull){out.analysis_limited=true;if(out.error.empty())out.error="SafeSEH table geometry exceeds bounded PE32 contract";}
        else if(auto off=pe_rva_off(pe,static_cast<std::uint32_t>(pe.load_config.seh_table-pe.image_base),data.size());off&&count<=(data.size()-*off)/4){
            for(std::uint64_t i=0;i<count;++i){std::uint32_t hr=0;std::memcpy(&hr,data.data()+*off+i*4,4);if(!hr||!pe_executable_rva(pe,hr))continue;ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism="SAFESEH";f.trigger_kind="POTENTIAL_X86_SEH_DISPATCH";f.handler=pe_rva_ref(hr,1,"SafeSEH handler whitelist entry",artifact_identity);f.evidence_state="EXACT_METADATA";f.provenance="PE32 LoadConfig SEHandlerTable/SEHandlerCount";f.priority="INFORMATIONAL";f.priority_reason="SafeSEH whitelists handlers but does not prove registration, a fault site, or a dispatch";f.detail="SafeSEH table index="+std::to_string(i);exceptional_add(out,std::move(f));}
        } else {out.analysis_limited=true;if(out.error.empty())out.error="SafeSEH table is not fully file-backed";}
    }

    // Baseline fdea977 exposes GuardFlags but not GuardEHContinuationTable/Count.
    // Refuse to invent exact continuation targets from the flag alone.
    constexpr std::uint32_t guard_eh_cont_table_present=0x00400000u;
    if(pe.load_config.present&&(pe.load_config.guard_flags&guard_eh_cont_table_present)){
        ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism="EH_CONTINUATION_METADATA";f.trigger_kind="METADATA_PRESENT";f.evidence_state="REFUSED";f.provenance="PE LoadConfig GuardFlags";f.priority="INFORMATIONAL";f.priority_reason="EH continuation presence alone is not a recovered exceptional edge";f.refusal_reason="baseline PeLoadConfigInfo does not expose exact GuardEHContinuationTable/Count; targets are not inferred from GuardFlags";exceptional_add(out,std::move(f));
    }

    if(pe.pe64&&pe.machine==0x8664){
        const auto calls=pe_exception_calls(data,pe);
        std::map<std::uint32_t,std::vector<const PeApiCall*>>by_func;
        for(const auto&c:calls)by_func[c.func_begin].push_back(&c);
        struct Registration{const PeApiCall*call=nullptr;std::uint32_t handler=0;std::string mechanism;};
        std::vector<Registration>regs;
        for(const auto&c:calls){
            if(c.name!="AddVectoredExceptionHandler"&&c.name!="SetUnhandledExceptionFilter")continue;
            const int arg=c.name=="AddVectoredExceptionHandler"?1:0;auto handler=pe_pointer_arg(data,pe,c,arg);
            ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism=c.name=="AddVectoredExceptionHandler"?"VEH":"UNHANDLED_EXCEPTION_FILTER";f.trigger_kind="HANDLER_REGISTRATION";f.registration_site=pe_rva_ref(c.callsite,c.instruction_size,c.name+" callsite",artifact_identity);f.provenance="exact imported API call -> bounded x64 argument recovery";
            if(!handler||!pe_executable_rva(pe,*handler)){
                f.evidence_state="REFUSED";f.priority="INFORMATIONAL";f.priority_reason="registration API use without an exact executable callback is not hidden CFG";f.refusal_reason=!handler?"callback argument is not statically exact within the bounded calling convention trace":"exact callback argument does not name executable image code";exceptional_add(out,std::move(f));continue;
            }
            const auto hf=pe_runtime_func(pe,*handler);f.handler=pe_rva_ref(*handler,hf.end&&hf.begin==*handler?hf.end-hf.begin:1,c.name+" exact callback",artifact_identity);f.protected_function=hx(c.func_begin);f.resume_semantics=c.name=="AddVectoredExceptionHandler"?"vectored handler participates before frame-based SEH; handler return controls continue-search/continue-execution":"top-level unhandled filter participates only after exception remains unhandled";f.evidence_state="REGISTRATION_HANDLER_EXACT";f.priority="REVIEW";f.priority_reason="exact registration->executable callback relation is control-relevant, but no concrete trigger in the same proven registration state is yet attached";f.detail="transfer="+c.transfer+", callback_rva="+hx(*handler);exceptional_add(out,std::move(f));regs.push_back({&c,*handler,c.name=="AddVectoredExceptionHandler"?"VEH":"UNHANDLED_EXCEPTION_FILTER"});
        }

        std::map<std::uint32_t,PeCfg>cfgs;
        for(const auto&r:regs){
            const auto*c=r.call;if(!c||!c->call)continue;
            auto gi=cfgs.find(c->func_begin);if(gi==cfgs.end())gi=cfgs.emplace(c->func_begin,pe_cfg(data,pe,{c->func_begin,c->func_end})).first;auto&g=gi->second;if(g.ins.empty())continue;
            auto ri=g.by_rva.find(c->callsite);if(ri==g.by_rva.end())continue;
            std::set<std::uint32_t>barriers;
            for(auto*q:by_func[c->func_begin]){
                if(r.mechanism=="VEH"&&q->name=="RemoveVectoredExceptionHandler")barriers.insert(q->callsite);
                if(r.mechanism=="UNHANDLED_EXCEPTION_FILTER"&&q->name=="SetUnhandledExceptionFilter"&&q->callsite!=c->callsite)barriers.insert(q->callsite);
            }
            struct Trigger{std::uint32_t rva=0;std::uint32_t size=0;std::string kind;};std::vector<Trigger>triggers;
            for(const auto&x:g.ins)if(auto k=pe_trap_kind(x);!k.empty())triggers.push_back({x.rva,x.ins.length,std::move(k)});
            for(auto*q:by_func[c->func_begin])if(q->name=="RaiseException"&&q->call)triggers.push_back({q->callsite,q->instruction_size,"RAISE_EXCEPTION"});
            std::sort(triggers.begin(),triggers.end(),[](const auto&a,const auto&b){return a.rva<b.rva;});
            for(const auto&t:triggers){auto ti=g.by_rva.find(t.rva);if(ti==g.by_rva.end()||ti->second==ri->second)continue;if(!pe_dominates(g,ri->second,ti->second)||!pe_reachable(g,ri->second,ti->second))continue;if(pe_barrier_between(g,ri->second,ti->second,barriers))continue;
                ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism=r.mechanism;f.trigger_kind=t.kind;f.trigger_location=pe_rva_ref(t.rva,t.size,"concrete exception/trap trigger",artifact_identity);f.registration_site=pe_rva_ref(c->callsite,c->instruction_size,c->name+" dominating registration",artifact_identity);const auto hf=pe_runtime_func(pe,r.handler);f.handler=pe_rva_ref(r.handler,hf.end&&hf.begin==r.handler?hf.end-hf.begin:1,"registered exceptional handler",artifact_identity);f.protected_range=pe_rva_ref(c->func_begin,c->func_end-c->func_begin,"bounded caller CFG proving registration dominance",artifact_identity);f.protected_function=hx(c->func_begin);f.evidence_state="TRIGGER_HANDLER_CORRELATED";f.provenance="Zydis instruction boundaries + imported API identity + exact callback argument + bounded CFG dominance";f.resume_semantics=r.mechanism=="VEH"?"OS dispatches registered vectored handler if registration succeeded; handler result determines search/continue semantics":"filter is a candidate only if the exception reaches the unhandled-filter stage";
                if(r.mechanism=="VEH"){f.priority="HIGH";f.priority_reason="concrete trigger is reachable only through the exact VEH registration in the same bounded function and no RemoveVectoredExceptionHandler path reaches the trigger";}else{f.priority="REVIEW";f.priority_reason="registration dominates a concrete trigger, but static analysis cannot prove the exception remains unhandled through frame-based SEH";}
                f.detail="registration_success remains a runtime condition; no exception handler emulation is performed";exceptional_add(out,std::move(f));
            }
        }

        // Context-controlled resume is a separate evidence tier.  A registered
        // callback implies writable-context capability, not a redirect.  Only
        // an exact CONTEXT.Rip write plus EXCEPTION_CONTINUE_EXECUTION closes
        // the resume relation.
        for(const auto&r:regs){
            if(!r.call)continue;
            const auto ev=pe_handler_context_evidence(data,pe,r.handler);
            const ExceptionalExecutionFact*linked=nullptr;
            for(auto it=out.facts.rbegin();it!=out.facts.rend();++it){
                if(it->mechanism!=r.mechanism||it->evidence_state!="TRIGGER_HANDLER_CORRELATED"||!it->handler||it->handler->offset!=r.handler||!it->registration_site||it->registration_site->offset!=r.call->callsite)continue;
                linked=&*it;break;
            }
            bool set_thread_context=false;
            const auto hf=pe_runtime_func(pe,r.handler);
            if(hf.end&&hf.begin==r.handler)for(const auto&c:calls)if(c.name=="SetThreadContext"&&c.func_begin==hf.begin){set_thread_context=true;break;}

            ExceptionalExecutionFact f;f.platform="WINDOWS_PE";f.mechanism=r.mechanism+"_CONTEXT_RESUME";f.trigger_kind=linked?linked->trigger_kind:"REGISTERED_HANDLER_CONTEXT";
            f.registration_site=pe_rva_ref(r.call->callsite,r.call->instruction_size,r.call->name+" context-capable registration",artifact_identity);
            f.handler=pe_rva_ref(r.handler,hf.end&&hf.begin==r.handler?hf.end-hf.begin:1,"registered exception handler",artifact_identity);
            if(linked){f.trigger_location=linked->trigger_location;f.protected_range=linked->protected_range;f.protected_function=linked->protected_function;}
            f.context_mutation_evidence=ev.detail;f.provenance="exact registered callback ABI + bounded handler instruction/dataflow proof";
            if(ev.pc_write&&ev.resume_proven){
                f.evidence_state="CONTEXT_PC_REWRITE_CONFIRMED";
                f.resume_semantics="handler writes CONTEXT.Rip and every reachable return yields EXCEPTION_CONTINUE_EXECUTION; Windows resumes from the modified context if handler dispatch occurs";
                if(ev.exact_target)f.landing_pad=pe_rva_ref(*ev.exact_target,1,"exact CONTEXT.Rip replacement target",artifact_identity);
                if(linked&&r.mechanism=="VEH"){f.priority="HIGH";f.priority_reason="concrete trigger, exact VEH callback, CONTEXT.Rip write, and continue-execution return are all closed within bounded static evidence";}
                else {f.priority="REVIEW";f.priority_reason="context rewrite/resume semantics are exact, but a concrete guaranteed dispatch relation is not fully closed";}
            } else {
                f.evidence_state="CONTEXT_CONTROL_CAPABILITY";f.priority="REVIEW";
                f.resume_semantics="registered callback receives writable exception context; no redirected control-flow target is claimed";
                if(ev.pc_write)f.priority_reason="an exact CONTEXT.Rip write exists, but continue-execution semantics are not proven on every reachable return";
                else f.priority_reason="callback ABI exposes writable context, but no exact PC mutation is proven";
                if(set_thread_context){
                    if(!f.context_mutation_evidence.empty())f.context_mutation_evidence+="; ";
                    f.context_mutation_evidence+="SetThreadContext call exists inside the exact handler";
                    f.refusal_reason="SetThreadContext is not promoted to a redirect because this bounded pass does not prove both target handle == faulting thread and CONTEXT object identity";
                }
            }
            exceptional_add(out,std::move(f));
        }
    }
    exceptional_finish(out);return out;
}

ExceptionalExecutionInfo analyze_elf_exception_flow(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf,
    const std::string& artifact_identity) {
    ExceptionalExecutionInfo out;if(!elf.valid)return out;

    // Existing CIE/FDE facts are consumed but never interpreted as DWARF CFI.
    // Ordinary compiler unwind/personality presence is an informational baseline.
    if(elf.unwind.state=="RESOLVED")for(const auto&fde:elf.unwind.fdes){if(fde.cie_index>=elf.unwind.cies.size())continue;const auto&cie=elf.unwind.cies[fde.cie_index];
        if(cie.personality_reference_va||cie.signal_frame){ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism=cie.signal_frame?"ELF_SIGNAL_FRAME_UNWIND":"ELF_PERSONALITY_UNWIND";f.trigger_kind="POTENTIAL_UNWIND_IN_PROTECTED_RANGE";f.protected_range=elf_va_ref(fde.function_start_va,fde.function_size,"FDE protected function range",artifact_identity);f.protected_function=hx(fde.function_start_va);f.resume_semantics="unwinder/runtime consumes CIE/FDE metadata; CFI instructions are not interpreted";f.evidence_state="EXACT_METADATA";f.provenance="bounded .eh_frame CIE/FDE inventory";f.priority="INFORMATIONAL";f.priority_reason="ordinary signal-frame/personality unwind metadata does not identify a concrete exceptional trigger";f.detail="personality="+cie.personality_symbol+", signal_frame="+(cie.signal_frame?std::string("true"):std::string("false"));exceptional_add(out,std::move(f));}
        if(fde.lsda_reference_va){ExceptionalExecutionFact meta;meta.platform="LINUX_ELF";meta.mechanism="ELF_ITANIUM_LSDA";meta.trigger_kind="LANGUAGE_SPECIFIC_UNWIND_METADATA";meta.protected_range=elf_va_ref(fde.function_start_va,fde.function_size,"FDE range carrying LSDA",artifact_identity);meta.protected_function=hx(fde.function_start_va);meta.evidence_state=fde.lsda_file_backed?"EXACT_METADATA":"REFUSED";meta.provenance="FDE LSDA reference + CIE personality";meta.priority="INFORMATIONAL";meta.priority_reason="compiler-generated C++ exception tables are ordinary baseline";meta.detail="personality="+cie.personality_symbol+", lsda_va="+hx(fde.lsda_reference_va);
            if(!fde.lsda_file_backed){meta.refusal_reason="LSDA reference is not file-backed";exceptional_add(out,std::move(meta));continue;}
            auto ls=parse_lsda_common(data,elf,fde);if(ls.state==LsdaState::UNSUPPORTED){meta.evidence_state="REFUSED";meta.refusal_reason=ls.reason;exceptional_add(out,std::move(meta));continue;}if(ls.state==LsdaState::MALFORMED){meta.evidence_state="REFUSED";meta.refusal_reason=ls.reason;exceptional_add(out,std::move(meta));out.analysis_limited=true;if(out.error.empty())out.error="one or more LSDA records failed the bounded common Itanium parser: "+ls.reason;continue;}exceptional_add(out,std::move(meta));
            for(const auto&e:ls.entries)if(e.landing){ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism="ELF_ITANIUM_LSDA";f.trigger_kind="UNWIND_TRANSFER_FOR_PROTECTED_CALL_SITE";f.protected_range=elf_va_ref(fde.function_start_va+e.start,e.length,"LSDA call-site protected range",artifact_identity);f.landing_pad=elf_va_ref(fde.function_start_va+e.landing,1,"LSDA landing pad",artifact_identity);f.protected_function=hx(fde.function_start_va);f.resume_semantics="personality may transfer to this landing pad for an exception matching the call-site/action metadata; action/type semantics are not interpreted";f.evidence_state="LANDING_PAD_EXACT_METADATA";f.provenance="common GCC/Clang Itanium LSDA call-site table; LPStart omitted; bounded unsigned call-site encoding";f.priority="INFORMATIONAL";f.priority_reason="exact language-level landing-pad metadata is ordinary compiler exception handling until a concrete throw/fault relation is independently proven";f.detail="action_offset="+std::to_string(e.action)+", personality="+cie.personality_symbol;exceptional_add(out,std::move(f));}
        }
    }

    // Signal registration/trigger closure is deliberately x86-64 only. Other
    // ELF architectures retain the metadata plane above without guessed ABI dataflow.
    if(elf.elf64&&elf.little_endian&&elf.machine==62){
        if(elf.dynamic.state=="FAILED"){
            ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism="POSIX_SIGNAL_IMPORT_RECOVERY";f.trigger_kind="ANALYSIS_GATE";f.evidence_state="REFUSED";f.provenance="strict ElfDynamicInfo plane";f.priority="INFORMATIONAL";f.priority_reason="signal API identity is not guessed when the shared dynamic-import plane rejects the ELF";f.refusal_reason="ElfDynamicInfo failed: "+elf.dynamic.error;exceptional_add(out,std::move(f));out.analysis_limited=true;if(out.error.empty())out.error="ELF dynamic import plane unavailable for bounded signal-call recovery";
        }
        const auto calls=elf_exception_calls(data,elf);std::map<std::uint64_t,const ElfApiCall*>by_site;std::map<std::uint64_t,std::vector<const ElfApiCall*>>by_func;for(const auto&c:calls){by_site[c.callsite]=&c;by_func[c.func_begin].push_back(&c);}
        struct Registration{const ElfApiCall*call=nullptr;int signal=0;std::uint64_t handler=0;bool siginfo=false;std::string mechanism;std::string handler_outcome;bool outcome_exact=false;};std::vector<Registration>regs;
        for(const auto&c:calls){if(c.name!="signal"&&c.name!="sigaction")continue;auto sn=elf_scalar_arg(data,elf,c,0);ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism=c.name=="signal"?"POSIX_SIGNAL":"POSIX_SIGACTION";f.trigger_kind="HANDLER_REGISTRATION";f.registration_site=elf_va_ref(c.callsite,c.instruction_size,c.name+" callsite",artifact_identity);f.provenance="exact imported libc call + bounded System V x86-64 argument recovery";
            if(!sn||!sane_linux_signal(*sn)){f.evidence_state="REFUSED";f.priority="INFORMATIONAL";f.priority_reason="registration without an exact signal number is not linked to a trigger";f.refusal_reason="signal-number argument is not a bounded exact scalar";exceptional_add(out,std::move(f));continue;}
            std::optional<std::uint64_t>handler;bool siginfo=false;std::string source;bool flags_exact=true;std::uint32_t flags=0;
            if(c.name=="signal"){handler=elf_pointer_arg(data,elf,c,1);source="direct signal() handler argument";}
            else {
                std::optional<ElfSigactionValue> sav;
                if(auto act=elf_pointer_arg(data,elf,c,1)){if(auto sa=elf_static_sigaction(data,elf,*act)){ElfSigactionValue v;v.handler=sa->first;v.flags=sa->second;v.flags_exact=true;v.source="file-backed glibc x86-64 struct sigaction";sav=v;}}
                if(!sav)if(auto sr=elf_stack_pointer_arg(data,elf,c,1))sav=elf_stack_glibc_sigaction(data,elf,c,*sr);
                if(sav){handler=sav->handler;flags=sav->flags;flags_exact=sav->flags_exact;siginfo=flags_exact&&(flags&4u)!=0;source=sav->source;}
                else {f.evidence_state="REFUSED";f.priority="INFORMATIONAL";f.priority_reason="sigaction call exists but callback layout is not exact";f.refusal_reason="bounded glibc x86-64 sigaction recovery could not prove an exact executable handler from either file-backed or unaliased stack storage";f.detail="signal="+linux_signal_name(static_cast<int>(*sn));exceptional_add(out,std::move(f));continue;}
            }
            if(!handler||!elf_exec_va(elf,*handler)){f.evidence_state="REFUSED";f.priority="INFORMATIONAL";f.priority_reason="registration API use without an exact executable callback is not hidden CFG";f.refusal_reason=!handler?"handler argument is not statically exact":"exact handler value is not executable image code (SIG_DFL/SIG_IGN/data-pointer bait included)";f.detail="signal="+linux_signal_name(static_cast<int>(*sn));exceptional_add(out,std::move(f));continue;}
            const auto ho=elf_handler_outcome(data,elf,*handler);
            const auto*hf=elf_fde_func(elf,*handler);f.handler=elf_va_ref(*handler,hf&&hf->function_start_va==*handler?hf->function_size:1,c.name+" exact signal handler",artifact_identity);f.evidence_state="REGISTRATION_HANDLER_EXACT";f.priority="INFORMATIONAL";f.priority_reason="X1 exact registration is inventory until a compatible concrete trigger/dispatch relation is attached";f.resume_semantics="kernel/libc signal delivery invokes the registered handler only if registration succeeds and a matching signal is actually delivered/unblocked";f.handler_outcome=ho.exact?ho.outcome:"UNKNOWN";f.ambiguity=ho.ambiguous?ho.detail:"";f.detail="signal="+linux_signal_name(static_cast<int>(*sn))+", handler_source="+source+", flags="+(flags_exact?hx(flags):std::string("PARTIAL_OR_UNKNOWN"))+", SA_SIGINFO="+(siginfo?std::string("true"):std::string("false"))+", mask/restorer="+(c.name=="sigaction"?std::string("not promoted unless independently closed"):std::string("n/a"))+", handler_outcome_evidence="+ho.detail;exceptional_add(out,std::move(f));regs.push_back({&c,static_cast<int>(*sn),*handler,siginfo,c.name=="signal"?"POSIX_SIGNAL":"POSIX_SIGACTION",ho.outcome,ho.exact});
        }
        std::map<std::uint64_t,ElfCfg>cfgs;
        for(const auto&r:regs){const auto*c=r.call;if(!c)continue;auto gi=cfgs.find(c->func_begin);if(gi==cfgs.end())gi=cfgs.emplace(c->func_begin,elf_cfg(data,elf,{c->func_begin,c->func_end})).first;auto&g=gi->second;if(g.ins.empty())continue;auto ri=g.by_va.find(c->callsite);if(ri==g.by_va.end())continue;
            std::set<std::uint64_t>barriers;for(auto*q:by_func[c->func_begin])if((q->name=="signal"||q->name=="sigaction")&&q->callsite!=c->callsite){auto s=elf_scalar_arg(data,elf,*q,0);if(s&&*s==static_cast<std::uint64_t>(r.signal))barriers.insert(q->callsite);}
            struct Trigger{std::uint64_t va=0,size=0;int signal=0;std::string kind;};std::vector<Trigger>triggers;
            for(const auto&x:g.ins){std::string kind;if(auto s=linux_trap_signal(x,kind))triggers.push_back({x.va,x.ins.length,*s,std::move(kind)});}
            for(auto*q:by_func[c->func_begin]){if(q->name=="raise"){auto s=elf_scalar_arg(data,elf,*q,0);if(s&&sane_linux_signal(*s))triggers.push_back({q->callsite,q->instruction_size,static_cast<int>(*s),"RAISE_"+linux_signal_name(static_cast<int>(*s))});}
                else if(q->name=="kill"){auto s=elf_scalar_arg(data,elf,*q,1);if(s&&sane_linux_signal(*s)&&elf_arg_from_producer_return(data,elf,*q,0,"getpid",by_site))triggers.push_back({q->callsite,q->instruction_size,static_cast<int>(*s),"KILL_SELF_"+linux_signal_name(static_cast<int>(*s))});}
                else if(q->name=="tgkill"){auto s=elf_scalar_arg(data,elf,*q,2);if(s&&sane_linux_signal(*s)&&elf_arg_from_producer_return(data,elf,*q,0,"getpid",by_site)&&elf_arg_from_producer_return(data,elf,*q,1,"gettid",by_site))triggers.push_back({q->callsite,q->instruction_size,static_cast<int>(*s),"TGKILL_SELF_THREAD_"+linux_signal_name(static_cast<int>(*s))});}}
            std::sort(triggers.begin(),triggers.end(),[](const auto&a,const auto&b){return a.va<b.va;});
            for(const auto&t:triggers){if(t.signal!=r.signal)continue;auto ti=g.by_va.find(t.va);if(ti==g.by_va.end()||!elf_dominates(g,ri->second,ti->second)||!elf_reachable(g,ri->second,ti->second)||elf_barrier_between(g,ri->second,ti->second,barriers))continue;ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism=r.mechanism;f.trigger_kind=t.kind;f.trigger_location=elf_va_ref(t.va,t.size,"concrete compatible signal/fault trigger",artifact_identity);f.registration_site=elf_va_ref(c->callsite,c->instruction_size,c->name+" dominating registration",artifact_identity);const auto*hf=elf_fde_func(elf,r.handler);f.handler=elf_va_ref(r.handler,hf&&hf->function_start_va==r.handler?hf->function_size:1,"registered signal handler",artifact_identity);f.protected_range=elf_va_ref(c->func_begin,c->func_end-c->func_begin,"bounded caller CFG proving registration dominance",artifact_identity);f.protected_function=hx(c->func_begin);f.evidence_state="TRIGGER_HANDLER_CORRELATED";f.provenance="dynamic relocation/import identity + System V x86-64 exact args + Zydis instruction boundaries + bounded CFG dominance";f.resume_semantics="compatible signal delivery dispatches the exact registered handler if registration succeeds and the signal is unblocked; post-handler resume target is not inferred here";f.handler_outcome=r.outcome_exact?r.handler_outcome:"UNKNOWN";f.priority="HIGH";f.priority_reason="exact signal registration dominates a concrete compatible self-signal/trap trigger in the same bounded function with no same-signal replacement barrier";f.detail="signal="+linux_signal_name(r.signal)+", SA_SIGINFO="+(r.siginfo?std::string("true"):std::string("false"));const auto trigger_copy=f.trigger_location;const auto reg_copy=f.registration_site;const auto handler_copy=f.handler;const auto protected_copy=f.protected_range;const auto protected_func=f.protected_function;exceptional_add(out,std::move(f));
                if(r.outcome_exact){ExceptionalExecutionFact ho;ho.platform="LINUX_ELF";ho.mechanism=r.mechanism+"_HANDLER_OUTCOME";ho.trigger_kind=t.kind;ho.trigger_location=trigger_copy;ho.registration_site=reg_copy;ho.handler=handler_copy;ho.protected_range=protected_copy;ho.protected_function=protected_func;ho.handler_outcome=r.handler_outcome;ho.evidence_state="HANDLER_OUTCOME_EXACT";ho.provenance="X3 exact dispatch relation + bounded exact handler outcome";ho.priority="HIGH";ho.priority_reason="the correlated dispatch target has one bounded exact handler outcome class";ho.resume_semantics=r.handler_outcome=="TERMINATE_PROCESS"?"handler terminates the process; no normal signal-frame resume occurs":r.handler_outcome=="RETURN_TO_SIGNAL_FRAME"?"handler returns normally to the kernel signal frame; semantic effect still requires independent context/control evidence":"handler performs a nonlocal resume primitive, but its target context remains unresolved";exceptional_add(out,std::move(ho));}
                // A terminating handler is X4 outcome evidence only.  Without
                // an independently closed semantic branch relation it must not
                // become X5 merely because the process exits.
            }
        }

        // SA_SIGINFO proves a writable ucontext capability through the exact
        // callback ABI.  It becomes a redirect only when REG_RIP is exactly
        // written and that write dominates every normal handler return.
        for(const auto&r:regs){
            if(!r.call||r.mechanism!="POSIX_SIGACTION"||!r.siginfo)continue;
            const auto ev=elf_siginfo_context_evidence(data,elf,r.handler);
            const ExceptionalExecutionFact*linked=nullptr;
            for(auto it=out.facts.rbegin();it!=out.facts.rend();++it){
                if(it->mechanism!=r.mechanism||it->evidence_state!="TRIGGER_HANDLER_CORRELATED"||!it->handler||it->handler->offset!=r.handler||!it->registration_site||it->registration_site->offset!=r.call->callsite)continue;
                linked=&*it;break;
            }
            const auto*hf=elf_fde_func(elf,r.handler);
            ExceptionalExecutionFact f;f.platform="LINUX_ELF";f.mechanism="POSIX_SIGACTION_CONTEXT_RESUME";f.trigger_kind=linked?linked->trigger_kind:"REGISTERED_SA_SIGINFO_CONTEXT";
            f.registration_site=elf_va_ref(r.call->callsite,r.call->instruction_size,"sigaction SA_SIGINFO registration",artifact_identity);
            f.handler=elf_va_ref(r.handler,hf&&hf->function_start_va==r.handler?hf->function_size:1,"SA_SIGINFO handler",artifact_identity);
            if(linked){f.trigger_location=linked->trigger_location;f.protected_range=linked->protected_range;f.protected_function=linked->protected_function;}
            f.context_mutation_evidence=ev.detail;f.provenance="exact file-backed glibc x86-64 sigaction + SA_SIGINFO ABI + bounded handler instruction/dataflow proof";
            std::optional<std::uint64_t>resume_target=ev.exact_target;
            if(!resume_target&&linked&&ev.relative_pc_delta&&linked->trigger_location){
                if(auto t=add_signed_u64(linked->trigger_location->offset,*ev.relative_pc_delta);t&&elf_exec_va(elf,*t)&&elf_va_off(elf,*t,data.size()))resume_target=*t;
            }
            const bool invalid_constant=ev.constant_target_observed&&!ev.exact_target;
            const bool confirmed=ev.pc_write&&ev.resume_proven&&!ev.target_ambiguous&&resume_target.has_value();
            if(confirmed){
                f.evidence_state="CONTEXT_PC_REWRITE_CONFIRMED";f.evidence_level=linked?"X4":"X1";f.resume_semantics="SA_SIGINFO handler writes ucontext REG_RIP, one executable file-backed resume target is exact, and the write dominates every reachable RET";
                f.landing_pad=elf_va_ref(*resume_target,1,"exact executable/file-backed ucontext REG_RIP resume target",artifact_identity);
                if(linked){f.priority="HIGH";f.priority_reason="concrete compatible trigger, exact SA_SIGINFO handler, exact executable resume target, REG_RIP mutation, and normal return are closed within bounded static evidence";}
                else {f.priority="REVIEW";f.priority_reason="context rewrite target/resume semantics are exact, but no concrete compatible trigger is closed in the same registration state";}
            } else {
                f.evidence_state="CONTEXT_CONTROL_CAPABILITY";f.evidence_level=(linked&&ev.pc_write)?"X4":"X1";f.resume_semantics="SA_SIGINFO supplies writable ucontext; no valid single redirected control-flow edge is claimed";
                if(ev.target_ambiguous){f.priority="INFORMATIONAL";f.priority_reason="multiple possible REG_RIP write sites make the resume target ambiguous";f.ambiguity="multiple possible context-resume targets; bounded analysis refuses to choose one";if(invalid_constant)f.refusal_reason="one or more constant context targets also fail executable/file-backed target validation";}
                else if(invalid_constant){f.priority="INFORMATIONAL";f.priority_reason="exact REG_RIP constant is not executable file-backed artifact code";f.refusal_reason="constant context target fails executable/file-backed target validation";}
                else if(ev.pc_write&&ev.resume_proven){f.priority="REVIEW";f.priority_reason="exact REG_RIP mutation/normal return exists, but the resume target is not a bounded exact executable file-backed address";}
                else if(ev.pc_write){f.priority="REVIEW";f.priority_reason="exact REG_RIP mutation exists, but normal return after the write is not proven on every reachable path";}
                else {f.priority="INFORMATIONAL";f.priority_reason="ABI capability without an exact context mutation is X1 inventory, not a REVIEW-worthy exceptional edge";}
            }
            exceptional_add(out,std::move(f));
        }

        // Independent raw-syscall path: no dynamic symbol, section, or FDE is
        // required. Facts remain STATIC_PROVEN and never borrow runtime state.
        analyze_raw_linux_signal_surface(data,elf,artifact_identity,out);
    }
    if(elf.elf64&&elf.little_endian&&elf.machine==183){
        analyze_a64_wrapper_signals(data,elf,artifact_identity,out);
        if(a64_has_svc_candidate(data,elf))analyze_a64_raw_signals(data,elf,artifact_identity,out);
    }
    exceptional_finish(out);return out;
}


std::vector<Finding> compose_exception_execution_surfaces(
    std::span<const std::uint8_t> data,
    const PeInfo& pe,
    const ElfInfo& elf,
    const std::string& artifact_identity) {
    std::vector<Finding> out;

    { auto vendor=compose_dwarf_vendor_surfaces(data,elf,artifact_identity); out.insert(out.end(),std::make_move_iterator(vendor.begin()),std::make_move_iterator(vendor.end())); }

    // ELF: expression-bearing FDEs are not unusual enough by themselves.  The
    // REVIEW gate requires (1) syntactically exact CFI expression semantics that
    // can alter the return-address register, (2) a metadata/program-size
    // contradiction against the tiny protected code range, and (3) an exact
    // language/runtime unwind transition import.  We deliberately do not execute
    // either the CFI program or its DWARF expressions.
    if(elf.valid&&elf.elf64&&elf.little_endian&&elf.unwind.state=="RESOLVED"){
        std::string transition;
        if(elf_unwind_transition_import(data,elf,transition)){
            const ElfUnwindFde*best=nullptr;CfiExpressionSummary best_sum;std::uint64_t best_score=0;
            for(const auto&fde:elf.unwind.fdes){
                if(fde.cie_index>=elf.unwind.cies.size()||!fde.cfi_size)continue;
                const bool metadata_heavy=fde.cfi_size>=64&&(
                    fde.function_size<=16 || (fde.function_size&&fde.cfi_size/fde.function_size>=4));
                if(!metadata_heavy)continue;
                const auto&cie=elf.unwind.cies[fde.cie_index];
                auto sum=scan_fde_cfi_expressions(data,fde,cie);
                if(!sum.parsed||!sum.return_address_expression_ops)continue;
                const auto score=fde.function_size?fde.cfi_size/std::max<std::uint64_t>(1,fde.function_size):fde.cfi_size;
                if(!best||score>best_score){best=&fde;best_sum=sum;best_score=score;}
            }
            if(best){const auto&cie=elf.unwind.cies[best->cie_index];Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";f.variant="ELF expression-bearing unwind composition";f.state="CONFIRMED";f.confidence=0.90;
                f.evidence.push_back("bounded FDE CFI syntax contains "+std::to_string(best_sum.return_address_expression_ops)+" expression operation(s) targeting the CIE return-address register");
                f.evidence.push_back("FDE CFI program is "+std::to_string(best->cfi_size)+" bytes while its protected executable range is "+std::to_string(best->function_size)+" bytes; metadata semantics materially exceed visible protected code");
                f.evidence.push_back("exact imported unwind transition "+transition+" independently proves this image can enter language/runtime unwinding");
                f.negative_evidence.push_back("DWARF CFI/expression semantics are not evaluated; no checker result, landing value, or runtime dispatch is claimed");
                f.ranges.push_back(file_offset_range(best->cfi_file_offset,best->cfi_size,"expression-bearing FDE CFI program",CoordinateBasis::CURRENT_INPUT_FILE,artifact_identity));
                f.ranges.push_back(elf_va_ref(best->function_start_va,best->function_size,"FDE protected executable range",artifact_identity));
                f.fields["surface_state"]="REVIEW_ALTERNATE_SURFACE";f.fields["semantic_state"]="UNRESOLVED_DWARF_EXPRESSION_SEMANTICS";f.fields["static_control_relation"]="BOUNDED_UNWIND_SURFACE";f.fields["runtime_confirmation"]="NOT_OBSERVED";f.fields["unwind_transition"]=transition;f.fields["fde_va"]=hx(best->va);f.fields["protected_start_va"]=hx(best->function_start_va);f.fields["protected_size"]=std::to_string(best->function_size);f.fields["cfi_size"]=std::to_string(best->cfi_size);f.fields["return_address_register"]=std::to_string(cie.return_address_register);f.fields["return_address_expression_ops"]=std::to_string(best_sum.return_address_expression_ops);
                f.suggested_actions.push_back("inspect the expression-bearing FDE and the unwind-triggering path before treating visible main/entry logic as complete");f.suggested_actions.push_back("use an unwind-aware debugger/emulator for concrete expression semantics; static S composition intentionally stops here");out.push_back(std::move(f));}
        }
    }

    // Linux signal/exception composition is stricter than raw plane emission.
    // X1 registration, X2 trigger, X3 dispatch, and X4 handler outcome alone do
    // not make a MAIN-facing alternate surface.  Promote only a fully semantic
    // X5 exceptional closure, or an X4 context-resume relation whose concrete
    // trigger and one executable/file-backed landing target are both exact.
    if(elf.valid&&elf.elf64&&elf.little_endian&&elf.machine==62&&
       (elf_has_signal_registration_import(elf)||elf_has_exec_syscall_candidate(data,elf))){
        const auto ex=analyze_elf_exception_flow(data,elf,artifact_identity);
        const ExceptionalExecutionFact* semantic=nullptr;
        const ExceptionalExecutionFact* resume=nullptr;
        std::size_t semantic_count=0,resume_count=0;
        for(const auto&fact:ex.facts){
            if(fact.proof_plane!="STATIC_PROVEN")continue;
            if(fact.evidence_level=="X5"&&fact.evidence_state=="SEMANTIC_EXCEPTION_CLOSURE"&&
               fact.priority=="HIGH"&&fact.trigger_location&&fact.registration_site&&fact.handler){
                ++semantic_count;
                if(!semantic)semantic=&fact;
                continue;
            }
            if(fact.evidence_level=="X4"&&fact.evidence_state=="CONTEXT_PC_REWRITE_CONFIRMED"&&
               fact.priority=="HIGH"&&fact.trigger_location&&fact.registration_site&&fact.handler&&fact.landing_pad){
                ++resume_count;
                if(!resume)resume=&fact;
            }
        }
        const auto add_ranges=[](Finding&f,const ExceptionalExecutionFact&x){
            if(x.trigger_location)f.ranges.push_back(*x.trigger_location);
            if(x.registration_site)f.ranges.push_back(*x.registration_site);
            if(x.handler)f.ranges.push_back(*x.handler);
            if(x.landing_pad)f.ranges.push_back(*x.landing_pad);
            if(x.protected_range)f.ranges.push_back(*x.protected_range);
        };
        if(semantic){
            Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";
            f.variant="ELF signal semantic exceptional closure";f.state="CONFIRMED";f.confidence=0.98;
            f.evidence.push_back("X5 STATIC_PROVEN closure binds an exact trigger, active registration, exact handler, and handler semantic outcome");
            f.evidence.push_back("trigger="+semantic->trigger_kind+", handler_outcome="+semantic->handler_outcome+", mechanism="+semantic->mechanism);
            if(semantic_count>1)f.evidence.push_back(std::to_string(semantic_count)+" bounded X5 closures share this mechanism class; one representative path is ranged below");
            f.negative_evidence.push_back("runtime dispatch is not claimed; this is a bounded static exceptional-control proof");
            add_ranges(f,*semantic);
            f.fields["surface_state"]="HIGH_ALTERNATE_SURFACE";
            f.fields["semantic_state"]="STATIC_EXCEPTION_SEMANTIC_CLOSURE";
            f.fields["static_control_relation"]="X5_TRIGGER_HANDLER_OUTCOME_CLOSED";
            f.fields["runtime_confirmation"]="NOT_OBSERVED";
            f.fields["evidence_level"]="X5";
            f.fields["exception_mechanism"]=semantic->mechanism;
            f.fields["trigger_kind"]=semantic->trigger_kind;
            f.fields["handler_outcome"]=semantic->handler_outcome;
            f.fields["closure_count"]=std::to_string(semantic_count);
            f.suggested_actions.push_back("treat the exceptional path as first-class control flow; do not reason from normal CFG successors alone");
            if(semantic->handler_outcome=="TERMINATE_PROCESS")f.suggested_actions.push_back("interpret the faulting path as terminal/reject-like unless downstream program semantics independently prove another role");
            out.push_back(std::move(f));
        } else if(resume){
            Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";
            f.variant="ELF signal context-resume edge";f.state="CONFIRMED";f.confidence=0.94;
            f.evidence.push_back("X4 STATIC_PROVEN relation binds an exact compatible trigger to an exact SA_SIGINFO handler and one executable/file-backed resume target");
            f.evidence.push_back("context mutation: "+resume->context_mutation_evidence);
            if(resume_count>1)f.evidence.push_back(std::to_string(resume_count)+" bounded exact context-resume relations were recovered; one representative edge is ranged below");
            f.negative_evidence.push_back("the semantic role of the resume target is not inferred merely from the PC rewrite; no X5 accept/reject claim is made");
            f.negative_evidence.push_back("runtime dispatch is not claimed; this is a bounded static context-resume proof");
            add_ranges(f,*resume);
            f.fields["surface_state"]="REVIEW_ALTERNATE_SURFACE";
            f.fields["semantic_state"]="STATIC_CONTEXT_RESUME_TARGET_CLOSED_SEMANTIC_ROLE_UNRESOLVED";
            f.fields["static_control_relation"]="X4_TRIGGER_CONTEXT_RESUME_CLOSED";
            f.fields["runtime_confirmation"]="NOT_OBSERVED";
            f.fields["evidence_level"]="X4";
            f.fields["exception_mechanism"]=resume->mechanism;
            f.fields["trigger_kind"]=resume->trigger_kind;
            f.fields["resume_target"]=resume->landing_pad?hx(resume->landing_pad->offset):std::string{};
            f.fields["closure_count"]=std::to_string(resume_count);
            f.suggested_actions.push_back("follow the exact exceptional resume edge before treating the normal CFG successor as complete");
            out.push_back(std::move(f));
        }
    }

    // AArch64 product gate: share the X contract, not the
    // x86 instruction grammar. Exact X4 context-resume is REVIEW. Separately,
    // an mprotect(PROT_NONE)/writable partition is REVIEW guidance only and
    // remains below X2 until a concrete fault address is proven.
    if(elf.valid&&elf.elf64&&elf.little_endian&&elf.machine==183){
        if(elf_has_signal_registration_import(elf)||a64_has_svc_candidate(data,elf)){
            const auto ex=analyze_elf_exception_flow(data,elf,artifact_identity);const ExceptionalExecutionFact*resume=nullptr;std::size_t n=0;
            for(const auto&fact:ex.facts)if(fact.proof_plane=="STATIC_PROVEN"&&fact.evidence_level=="X4"&&fact.evidence_state=="CONTEXT_PC_REWRITE_CONFIRMED"&&fact.priority=="HIGH"&&fact.trigger_location&&fact.registration_site&&fact.handler&&fact.landing_pad){++n;if(!resume)resume=&fact;}
            if(resume){Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";f.variant="AArch64 signal context-resume edge";f.state="CONFIRMED";f.confidence=0.94;f.evidence.push_back("AArch64 X4 STATIC_PROVEN relation binds exact registration, compatible SIGSEGV trigger, SA_SIGINFO handler, ucontext PC write, and one executable/file-backed resume target");f.evidence.push_back(resume->context_mutation_evidence);f.negative_evidence.push_back("the resume target's application-level meaning is not inferred; no X5 semantic closure is claimed");if(resume->trigger_location)f.ranges.push_back(*resume->trigger_location);if(resume->registration_site)f.ranges.push_back(*resume->registration_site);if(resume->handler)f.ranges.push_back(*resume->handler);if(resume->landing_pad)f.ranges.push_back(*resume->landing_pad);f.fields["surface_state"]="REVIEW_ALTERNATE_SURFACE";f.fields["semantic_state"]="UNRESOLVED_AARCH64_RESUME_SEMANTIC_ROLE";f.fields["static_control_relation"]="AARCH64_X4_TRIGGER_CONTEXT_RESUME_CLOSED";f.fields["runtime_confirmation"]="NOT_OBSERVED";f.fields["evidence_level"]="X4";f.fields["closure_count"]=std::to_string(n);f.fields["ucontext_pc_offset"]="440";f.suggested_actions.push_back("follow the exact AArch64 exceptional resume edge before relying on the normal successor");out.push_back(std::move(f));}
        }
        if(auto p=a64_protected_page_surface(data,elf)){Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";f.variant="AArch64 protected-page fault surface";f.state="CONFIRMED";f.confidence=0.84;f.evidence.push_back("one bounded AArch64 function makes direct imported mprotect calls with exact PROT_NONE and writable protection values");f.evidence.push_back("this proves deliberate page-permission partitioning in executable logic, a fault-relevant surface");f.negative_evidence.push_back("the runtime effective address of a later access is not closed to one protected page; this remains below X2 TRIGGER_PROVEN");f.negative_evidence.push_back("no signal registration, dispatch, handler, or resume relation is inferred from mprotect alone");f.ranges.push_back(elf_va_ref(p->noaccess,4,"mprotect exact PROT_NONE call",artifact_identity));f.ranges.push_back(elf_va_ref(p->writable,4,"mprotect exact writable call",artifact_identity));f.ranges.push_back(elf_va_ref(p->func_begin,p->func_end-p->func_begin,"bounded permission-partitioning function",artifact_identity));f.fields["surface_state"]="REVIEW_ALTERNATE_SURFACE";f.fields["semantic_state"]="REQUIRES_DYNAMIC_FAULT_ADDRESS_PROVENANCE";f.fields["static_control_relation"]="AARCH64_PROTECTED_PAGE_PERMISSION_PARTITION";f.fields["runtime_confirmation"]="NOT_OBSERVED";f.fields["evidence_level"]="PRE_X2";f.suggested_actions.push_back("trace the computed memory access back to the protected-page partition; promote to X2 only if one faulting effective address is exact");out.push_back(std::move(f));}
    }

    // PE: keep ordinary TLS callbacks and ordinary exception metadata normal.
    // A REVIEW surface appears only when an exact loader pre-entry callback itself
    // performs executable VirtualAlloc and the same image independently installs
    // an exact executable exception callback.  HIGH additionally requires G's
    // exact trigger->handler closure.  This is static composition, not proof the
    // allocation or exception dispatch succeeded at runtime.
    if(pe.valid&&pe.pe64&&pe.machine==0x8664&&!pe.tls.callbacks.empty()){
        bool has_exception_registration_import=false;
        for(const auto&m:pe.imports)for(const auto&fn:m.functions)if(!fn.by_ordinal&&(fn.name=="AddVectoredExceptionHandler"||fn.name=="SetUnhandledExceptionFilter")){has_exception_registration_import=true;break;}
        if(has_exception_registration_import){
            PeApiCall alloc;std::uint64_t protection=0;const PeTlsCallback*alloc_cb=nullptr;
            for(const auto&cb:pe.tls.callbacks)if(cb.target_file_backed&&pe_tls_contains_exec_allocation(data,pe,cb,alloc,protection)){alloc_cb=&cb;break;}
            if(alloc_cb){auto ex=analyze_pe_exception_flow(data,pe,artifact_identity);const ExceptionalExecutionFact*reg=nullptr,*strong=nullptr;
                for(const auto&fact:ex.facts){
                    const bool registered=(fact.mechanism=="VEH"||fact.mechanism=="UNHANDLED_EXCEPTION_FILTER")&&fact.handler&&fact.registration_site;
                    if(registered&&fact.evidence_state=="REGISTRATION_HANDLER_EXACT"&&!reg)reg=&fact;
                    if(registered&&fact.priority=="HIGH"&&fact.trigger_location&&!strong)strong=&fact;
                }
                const auto*chosen=strong?strong:reg;
                if(chosen){const auto cb_rva=alloc_cb->target_va-pe.image_base;Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";f.variant="PE pre-entry materialization + exception registration";f.state="CONFIRMED";f.confidence=strong?0.98:0.90;
                    f.evidence.push_back("exact PE TLS callback executes before the declared entry and contains a bounded VirtualAlloc call with executable protection "+hx(protection));
                    f.evidence.push_back("exact "+chosen->mechanism+" registration resolves an executable exception callback at RVA "+hx(chosen->handler->offset));
                    if(strong)f.evidence.push_back("existing exceptional-flow proof closes a compatible concrete trigger to that exact registered handler: "+strong->trigger_kind);
                    else f.negative_evidence.push_back("no compatible concrete exception trigger is statically closed to the registered handler; recursive/HLT/dynamic-unwind semantics remain unresolved");
                    f.negative_evidence.push_back("static composition does not claim VirtualAlloc success, first execution, or exception dispatch was observed; those are runtime claims");
                    f.ranges.push_back(pe_rva_ref(cb_rva,1,"exact TLS callback target",artifact_identity));f.ranges.push_back(pe_rva_ref(alloc.callsite,alloc.instruction_size,"pre-entry executable VirtualAlloc call",artifact_identity));if(chosen->registration_site)f.ranges.push_back(*chosen->registration_site);if(chosen->handler)f.ranges.push_back(*chosen->handler);if(strong&&strong->trigger_location)f.ranges.push_back(*strong->trigger_location);
                    f.fields["surface_state"]=strong?"HIGH_ALTERNATE_SURFACE":"REVIEW_ALTERNATE_SURFACE";f.fields["semantic_state"]=strong?"STATIC_TRIGGER_HANDLER_CLOSED":"UNRESOLVED_EXCEPTION_TRIGGER_SEMANTICS";f.fields["static_control_relation"]="CONFIRMED_PRE_ENTRY_EXECUTABLE_ALLOCATION_PLUS_HANDLER_REGISTRATION";f.fields["runtime_confirmation"]="NOT_OBSERVED";f.fields["tls_callback_rva"]=hx(cb_rva);f.fields["allocation_call_rva"]=hx(alloc.callsite);f.fields["allocation_protection"]=hx(protection);f.fields["exception_mechanism"]=chosen->mechanism;f.fields["handler_rva"]=hx(chosen->handler->offset);
                    f.suggested_actions.push_back("analyze TLS/pre-entry materialization and the registered exception callback as first-class control surfaces before relying on declared entry/main");if(!strong)f.suggested_actions.push_back("use runtime tracing/debugging to confirm the concrete exception trigger and dynamically materialized unwind/handler state");out.push_back(std::move(f));}
            }
        }
    }
    return out;
}

ExceptionalExecutionExtractResult extract_exceptional_execution(
    const ExceptionalExecutionInfo& info,
    const std::filesystem::path& csv) {
    ExceptionalExecutionExtractResult out;
    if (info.state == "NOT_PRESENT") {
        out.error = "exceptional execution plane is not present";
        return out;
    }
    std::ofstream f(csv, std::ios::binary | std::ios::trunc);
    if (!f) {
        out.error = "cannot create exceptional execution CSV";
        return out;
    }
    f << "fact_index,platform,mechanism,trigger_kind,";
    range_header(f, "trigger"); f << ',';
    range_header(f, "registration"); f << ',';
    range_header(f, "handler"); f << ',';
    range_header(f, "landing_pad"); f << ',';
    range_header(f, "protected_range");
    f << ",protected_function,resume_semantics,context_mutation_evidence,evidence_level,proof_plane,handler_outcome,ambiguity,evidence_state,provenance,priority,priority_reason,refusal_reason,detail\n";
    for (const auto& x : info.facts) {
        f << x.index << ',' << csvq(x.platform) << ',' << csvq(x.mechanism) << ',' << csvq(x.trigger_kind) << ',';
        range_row(f, x.trigger_location); f << ',';
        range_row(f, x.registration_site); f << ',';
        range_row(f, x.handler); f << ',';
        range_row(f, x.landing_pad); f << ',';
        range_row(f, x.protected_range);
        f << ',' << csvq(x.protected_function) << ',' << csvq(x.resume_semantics) << ','
          << csvq(x.context_mutation_evidence) << ',' << csvq(x.evidence_level) << ',' << csvq(x.proof_plane) << ','
          << csvq(x.handler_outcome) << ',' << csvq(x.ambiguity) << ',' << csvq(x.evidence_state) << ','
          << csvq(x.provenance) << ',' << csvq(x.priority) << ',' << csvq(x.priority_reason) << ','
          << csvq(x.refusal_reason) << ',' << csvq(x.detail) << "\n";
    }
    f.close();
    if (!f) {
        out.error = "write exceptional execution CSV failed";
        std::error_code ec;
        std::filesystem::remove(csv, ec);
        return out;
    }
    out.success=true;
    out.csv=csv;
    out.fact_count=info.facts.size();
    return out;
}
} // namespace prts
