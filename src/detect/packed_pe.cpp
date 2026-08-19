#include "prts/packed_pe.hpp"
extern "C" {
#include "Zydis.h"
}
#include <algorithm>
#include <array>
#include <cstring>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>

namespace prts { namespace {
constexpr std::uint32_t SCN_EXEC=0x20000000u, SCN_WRITE=0x80000000u;
std::string lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});return s;}
std::string hx(std::uint64_t v){std::ostringstream o;o<<"0x"<<std::hex<<v;return o.str();}
std::string fixed(double v,int precision){std::ostringstream o;o<<std::fixed<<std::setprecision(precision)<<v;return o.str();}
std::optional<std::size_t> section_index_for_rva(const PeInfo&pe,std::uint32_t rva){
    if(!rva)return std::nullopt;
    for(std::size_t i=0;i<pe.sections.size();++i){const auto&s=pe.sections[i];const auto n=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)-s.rva<n)return i;}
    return std::nullopt;
}
bool imported(const PeInfo&pe,std::string_view name){for(const auto&m:pe.imports)for(const auto&f:m.functions)if(!f.by_ordinal&&f.name==name)return true;return false;}
std::uint32_t import_function_count(const PeInfo&pe){std::uint64_t n=0;for(const auto&m:pe.imports)n+=m.functions.size();return static_cast<std::uint32_t>(std::min<std::uint64_t>(n,0xffffffffull));}
std::vector<std::string> marker_hints(const PeInfo&pe){
    bool mpress1=false,mpress2=false,aspack=false,adata=false;std::set<std::string> h;
    for(const auto&s:pe.sections){auto n=lower(s.name);if(n==".mpress1")mpress1=true;else if(n==".mpress2")mpress2=true;else if(n==".aspack")aspack=true;else if(n==".adata")adata=true;if(n.rfind(".vmp",0)==0)h.insert("VMProtect section-name marker");if(n==".themida"||n==".winlice")h.insert("Themida/WinLicense section-name marker");if(n.find("kkrunchy")!=std::string::npos)h.insert("kkrunchy section-name marker");if(n.find("enigma")!=std::string::npos)h.insert("Enigma section-name marker");}
    if(mpress1||mpress2)h.insert((mpress1&&mpress2)?"MPRESS paired section-name markers":"MPRESS partial section-name marker");
    if(aspack||adata)h.insert((aspack&&adata)?"ASPack paired section-name markers":"ASPack partial section-name marker");
    return {h.begin(),h.end()};
}
Finding structural_family(std::string family,std::string variant,double confidence,std::vector<std::string>e,std::vector<std::string>neg,std::map<std::string,std::string>fields,std::vector<RangeRef>ranges){
    Finding f;f.kind="protector";f.family=std::move(family);f.variant=std::move(variant);f.state="LIKELY";f.confidence=confidence;f.evidence=std::move(e);f.negative_evidence=std::move(neg);f.fields=std::move(fields);f.ranges=std::move(ranges);f.suggested_actions={"unpack:generic-runtime","inspect:entrypoint-and-materialization"};return f;
}

Finding packer_family(std::string family,std::string variant,double confidence,const PackedPeInfo&packed,std::vector<std::string>e,std::vector<std::string>neg,std::map<std::string,std::string>fields,std::vector<RangeRef>ranges){
    Finding f;f.kind="packer";f.family=std::move(family);f.variant=std::move(variant);f.state="LIKELY";f.confidence=confidence;
    e.insert(e.begin(),"generic packed/loader route passed with structural score "+std::to_string(packed.structural_score)+" and "+std::to_string(packed.evidence_categories)+"/3 independent evidence categories");
    fields["structural_score"]=std::to_string(packed.structural_score);fields["evidence_categories"]=std::to_string(packed.evidence_categories)+"/3";
    f.evidence=std::move(e);f.negative_evidence=std::move(neg);f.fields=std::move(fields);f.ranges=std::move(ranges);f.suggested_actions={"unpack:generic-runtime","inspect:entrypoint-and-materialization"};return f;
}

Finding semantic_protector_family(std::string family,std::string variant,double confidence,const PackedPeInfo&packed,std::vector<std::string>e,std::vector<std::string>neg,std::map<std::string,std::string>fields,std::vector<RangeRef>ranges){
    Finding f;f.kind="protector";f.family=std::move(family);f.variant=std::move(variant);f.state="LIKELY";f.confidence=confidence;
    e.insert(e.begin(),"generic packed/loader route passed with structural score "+std::to_string(packed.structural_score)+" and "+std::to_string(packed.evidence_categories)+"/3 independent evidence categories");
    fields["structural_score"]=std::to_string(packed.structural_score);fields["evidence_categories"]=std::to_string(packed.evidence_categories)+"/3";
    f.evidence=std::move(e);f.negative_evidence=std::move(neg);f.fields=std::move(fields);f.ranges=std::move(ranges);f.suggested_actions={"unpack:generic-runtime","inspect:entrypoint-and-materialization"};return f;
}

template<class T> bool raw_read(std::span<const std::uint8_t>d,std::size_t off,T&v){if(off+sizeof(T)>d.size())return false;std::memcpy(&v,d.data()+off,sizeof(T));return true;}
std::optional<std::size_t> rva_offset(const PeInfo&pe,std::uint32_t rva,std::size_t file_size){
    if(rva<pe.headers_size&&rva<file_size)return std::size_t(rva);
    for(const auto&s:pe.sections){const auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)-s.rva<span){const auto delta=std::uint64_t(rva)-s.rva;if(delta>=s.raw_size)return std::nullopt;const auto off=std::uint64_t(s.raw_offset)+delta;if(off<file_size)return static_cast<std::size_t>(off);}}
    return std::nullopt;
}
std::optional<std::uint32_t> pe_size_of_code(std::span<const std::uint8_t>d){std::uint32_t peoff=0,size=0;if(d.size()<0x40||!raw_read(d,0x3c,peoff)||std::uint64_t(peoff)+32>d.size())return std::nullopt;if(std::memcmp(d.data()+peoff,"PE\0\0",4))return std::nullopt;if(!raw_read(d,std::size_t(peoff)+28,size))return std::nullopt;return size;}

struct EntryInsn {
    ZydisMnemonic mnemonic=ZYDIS_MNEMONIC_INVALID;ZydisInstructionCategory category=ZYDIS_CATEGORY_INVALID;
    ZydisRegister dst=ZYDIS_REGISTER_NONE,src=ZYDIS_REGISTER_NONE,src_mem_base=ZYDIS_REGISTER_NONE,dst_mem_base=ZYDIS_REGISTER_NONE;
    std::uint32_t rva=0;std::uint8_t length=0;bool has_imm=false,rel_imm=false,rep=false,fs_mem=false,dst_mem=false;std::int64_t imm=0;
};
struct EntryProfile {bool valid=false;std::uint32_t original_rva=0,start_rva=0,decoded_bytes=0;std::uint32_t trampoline_hops=0;std::vector<EntryInsn> insns;};
ZydisRegister largest_reg(ZydisMachineMode mode,ZydisRegister r){return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(mode,r);}
bool decode_insn(std::span<const std::uint8_t>d,const PeInfo&pe,ZydisDecoder&decoder,ZydisMachineMode mode,std::uint32_t rva,EntryInsn&out){
    auto off=rva_offset(pe,rva,d.size());if(!off||*off>=d.size())return false;ZydisDecodedInstruction zi{};ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,d.data()+*off,d.size()-*off,&zi,ops))||!zi.length)return false;
    out.mnemonic=zi.mnemonic;out.category=zi.meta.category;out.rva=rva;out.length=zi.length;out.rep=(zi.attributes&(ZYDIS_ATTRIB_HAS_REP|ZYDIS_ATTRIB_HAS_REPE|ZYDIS_ATTRIB_HAS_REPNE))!=0;
    for(std::uint8_t i=0;i<zi.operand_count_visible;i++){
        const auto&o=ops[i];if(o.type==ZYDIS_OPERAND_TYPE_REGISTER){auto reg=largest_reg(mode,o.reg.value);if(i==0)out.dst=reg;else if(i==1)out.src=reg;}
        else if(o.type==ZYDIS_OPERAND_TYPE_MEMORY){auto base=largest_reg(mode,o.mem.base);if(i==0){out.dst_mem=true;out.dst_mem_base=base;}else if(i==1)out.src_mem_base=base;if(o.mem.segment==ZYDIS_REGISTER_FS)out.fs_mem=true;}
        else if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!out.has_imm){out.has_imm=true;out.rel_imm=o.imm.is_relative;out.imm=o.imm.is_signed?o.imm.value.s:static_cast<std::int64_t>(o.imm.value.u);}
    }
    return true;
}
std::optional<std::uint32_t> direct_target(const PeInfo&pe,const EntryInsn&i){if(!i.rel_imm)return std::nullopt;const auto base=static_cast<std::int64_t>(pe.image_base)+i.rva+i.length;const auto t=base+i.imm;if(t<static_cast<std::int64_t>(pe.image_base)||std::uint64_t(t-static_cast<std::int64_t>(pe.image_base))>0xffffffffull)return std::nullopt;return static_cast<std::uint32_t>(t-static_cast<std::int64_t>(pe.image_base));}
EntryProfile profile_entry(std::span<const std::uint8_t>d,const PeInfo&pe){
    EntryProfile p;p.original_rva=pe.entry_rva;if(!pe.valid||(pe.machine!=0x14c&&pe.machine!=0x8664))return p;const auto mode=pe.pe64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32;const auto width=pe.pe64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32;ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,mode,width)))return p;
    std::uint32_t cur=pe.entry_rva;for(int guard=0;guard<4;guard++){EntryInsn i;if(!decode_insn(d,pe,dec,mode,cur,i))return p;auto next=cur+i.length;if(i.mnemonic==ZYDIS_MNEMONIC_NOP){cur=next;continue;}if(i.category==ZYDIS_CATEGORY_COND_BR){auto t=direct_target(pe,i);if(t&&*t==next){cur=next;continue;}}if(i.mnemonic==ZYDIS_MNEMONIC_JMP){auto t=direct_target(pe,i);if(t&&rva_offset(pe,*t,d.size())){cur=*t;++p.trampoline_hops;continue;}}break;}
    p.start_rva=cur;for(std::size_t n=0;n<48;n++){EntryInsn i;if(!decode_insn(d,pe,dec,mode,cur,i))break;p.insns.push_back(i);const auto next=cur+i.length;p.decoded_bytes=next-p.start_rva;if(p.decoded_bytes>=0x180)break;if(i.category==ZYDIS_CATEGORY_RET||i.category==ZYDIS_CATEGORY_INTERRUPT||i.category==ZYDIS_CATEGORY_SYSTEM||i.mnemonic==ZYDIS_MNEMONIC_JMP)break;cur=next;}p.valid=!p.insns.empty();return p;
}

EntryProfile trace_small_jump_entry(std::span<const std::uint8_t>d,const PeInfo&pe){
    EntryProfile p;p.original_rva=p.start_rva=pe.entry_rva;if(!pe.valid||(pe.machine!=0x14c&&pe.machine!=0x8664))return p;const auto mode=pe.pe64?ZYDIS_MACHINE_MODE_LONG_64:ZYDIS_MACHINE_MODE_LEGACY_32;const auto width=pe.pe64?ZYDIS_STACK_WIDTH_64:ZYDIS_STACK_WIDTH_32;ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,mode,width)))return p;
    std::set<std::uint32_t>seen;std::uint32_t cur=pe.entry_rva,max_end=cur;for(std::size_t n=0;n<40&&seen.insert(cur).second;n++){EntryInsn i;if(!decode_insn(d,pe,dec,mode,cur,i))break;p.insns.push_back(i);const auto next=cur+i.length;max_end=std::max(max_end,next);if(max_end-p.start_rva>=0x180)break;if(i.mnemonic==ZYDIS_MNEMONIC_JMP&&i.rel_imm&&i.imm>=-8&&i.imm<=8){auto t=direct_target(pe,i);if(t&&rva_offset(pe,*t,d.size())){cur=*t;++p.trampoline_hops;continue;}}if(i.category==ZYDIS_CATEGORY_RET||i.category==ZYDIS_CATEGORY_INTERRUPT||i.category==ZYDIS_CATEGORY_SYSTEM)break;cur=next;}p.decoded_bytes=max_end-p.start_rva;p.valid=!p.insns.empty();return p;
}
std::size_t first_if(const EntryProfile&p,const auto&pred,std::size_t limit=static_cast<std::size_t>(-1),std::size_t from=0){const auto end=std::min(limit,p.insns.size());for(std::size_t i=from;i<end;i++)if(pred(p.insns[i]))return i;return static_cast<std::size_t>(-1);}
bool is_push_all(ZydisMnemonic m){return m==ZYDIS_MNEMONIC_PUSHA||m==ZYDIS_MNEMONIC_PUSHAD;}
bool is_push_flags(ZydisMnemonic m){return m==ZYDIS_MNEMONIC_PUSHF||m==ZYDIS_MNEMONIC_PUSHFD||m==ZYDIS_MNEMONIC_PUSHFQ;}
bool is_lodsd(ZydisMnemonic m){return m==ZYDIS_MNEMONIC_LODSD||m==ZYDIS_MNEMONIC_LODSQ;}
bool is_movsd(ZydisMnemonic m){return m==ZYDIS_MNEMONIC_MOVSD||m==ZYDIS_MNEMONIC_MOVSQ;}
bool is_stosd(ZydisMnemonic m){return m==ZYDIS_MNEMONIC_STOSD||m==ZYDIS_MNEMONIC_STOSQ;}
std::size_t first_mn(const EntryProfile&p,ZydisMnemonic m,std::size_t limit=static_cast<std::size_t>(-1),std::size_t from=0){return first_if(p,[&](const EntryInsn&i){return i.mnemonic==m;},limit,from);}
std::size_t first_push_all(const EntryProfile&p,std::size_t limit){return first_if(p,[](const EntryInsn&i){return is_push_all(i.mnemonic);},limit);}
std::size_t first_push_flags(const EntryProfile&p,std::size_t limit){return first_if(p,[](const EntryInsn&i){return is_push_flags(i.mnemonic);},limit);}
std::size_t count_if(const EntryProfile&p,const auto&pred,std::size_t limit=static_cast<std::size_t>(-1)){std::size_t n=0;for(std::size_t i=0;i<std::min(limit,p.insns.size());i++)if(pred(p.insns[i]))++n;return n;}
std::size_t count_mn(const EntryProfile&p,ZydisMnemonic m,std::size_t limit=static_cast<std::size_t>(-1)){return count_if(p,[&](const EntryInsn&i){return i.mnemonic==m;},limit);}
bool mov_imm_to(const EntryInsn&i,ZydisRegister r){return i.mnemonic==ZYDIS_MNEMONIC_MOV&&i.dst==r&&i.has_imm;}
bool mov_reg_reg(const EntryInsn&i,ZydisRegister d,ZydisRegister s){return i.mnemonic==ZYDIS_MNEMONIC_MOV&&i.dst==d&&i.src==s;}
bool section_named(const PeInfo&pe,std::initializer_list<std::string_view>names){for(const auto&s:pe.sections){auto n=lower(s.name);for(auto want:names)if(n==want||n.rfind(want,0)==0)return true;}return false;}
bool ascii_bounded(std::span<const std::uint8_t>d,std::string_view needle,std::size_t max_bytes){if(needle.empty())return false;auto end=d.begin()+std::min(max_bytes,d.size());return std::search(d.begin(),end,needle.begin(),needle.end())!=end;}
std::map<std::string,std::string> profile_fields(const EntryProfile&p,bool marker){return {{"basis","STRUCTURAL+BOUNDED_EP_SEMANTICS"},{"entry_profile_rva",hx(p.start_rva)},{"entry_profile_bytes",std::to_string(p.decoded_bytes)},{"entry_profile_instructions",std::to_string(p.insns.size())},{"entry_trampoline_hops",std::to_string(p.trampoline_hops)},{"section_name_marker",marker?"present":"absent"}};}
std::vector<RangeRef> profile_range(const EntryProfile&p){return p.decoded_bytes?std::vector<RangeRef>{{p.start_rva,p.decoded_bytes,"bounded normalized entry-loader semantic window RVA"}}:std::vector<RangeRef>{};}

bool push_reg(const EntryInsn&i,ZydisRegister r){return i.mnemonic==ZYDIS_MNEMONIC_PUSH&&i.dst==r;}
bool getpc_pop_ebp(const EntryProfile&p,std::size_t call_index){for(std::size_t i=call_index+1;i<std::min(call_index+4,p.insns.size());++i)if(p.insns[i].mnemonic==ZYDIS_MNEMONIC_POP&&p.insns[i].dst==ZYDIS_REGISTER_EBP)return true;return false;}
std::size_t count_ebp_adjust(const EntryProfile&p,std::size_t limit=16){return count_if(p,[](const EntryInsn&i){return (i.mnemonic==ZYDIS_MNEMONIC_SUB||i.mnemonic==ZYDIS_MNEMONIC_ADD)&&i.dst==ZYDIS_REGISTER_EBP&&i.has_imm;},limit);}
std::size_t count_fs_memory(const EntryProfile&p,std::size_t limit=24){return count_if(p,[](const EntryInsn&i){return i.fs_mem;},limit);}
std::size_t count_small_jumps(const EntryProfile&p,std::size_t limit=32){return count_if(p,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_JMP&&i.rel_imm&&i.imm>=-8&&i.imm<=8;},limit);}

std::optional<Finding> detect_entry_protector_family(std::span<const std::uint8_t>d,const PeInfo&pe,const PackedPeInfo&packed){
    if(!pe.valid||!packed.candidate)return std::nullopt;
    const auto prof=profile_entry(d,pe);if(!prof.valid)return std::nullopt;
    const auto trace=trace_small_jump_entry(d,pe);const bool x86=pe.machine==0x14c,x64=pe.machine==0x8664;
    const bool enigma_marker=section_named(pe,{".enigma","enigma"})||ascii_bounded(d,"ENIGMA",0x800);
    if(x86){
        const auto pa=first_push_all(prof,4),call=first_mn(prof,ZYDIS_MNEMONIC_CALL,7);const bool getpc=call!=static_cast<std::size_t>(-1)&&getpc_pop_ebp(prof,call);
        // ASProtect SKE loaders use a get-PC EBP transfer followed by INC EBP / PUSH EBP / RET;
        // the odd RET-based handoff is kept as an independent discriminator from ASPack.
        const auto inc_ebp=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_INC&&i.dst==ZYDIS_REGISTER_EBP;},12);const auto push_ebp=first_if(prof,[](const EntryInsn&i){return push_reg(i,ZYDIS_REGISTER_EBP);},14);const auto ret=first_if(prof,[](const EntryInsn&i){return i.category==ZYDIS_CATEGORY_RET;},16);
        if(pa!=static_cast<std::size_t>(-1)&&call!=static_cast<std::size_t>(-1)&&getpc&&inc_ebp!=static_cast<std::size_t>(-1)&&push_ebp!=static_cast<std::size_t>(-1)&&ret!=static_cast<std::size_t>(-1)&&inc_ebp<push_ebp&&push_ebp<ret){auto f=profile_fields(prof,false);return semantic_protector_family("ASProtect-like","SKE get-PC/RET loader",.93,packed,{"entry loader saves all GPRs and recovers EBP through an early CALL/POP get-PC sequence","recovered EBP is incremented, pushed, and consumed by an immediate RET-style transfer"},{"classification does not rely on ASPack/ASProtect section-name markers"},std::move(f),profile_range(prof));}
        // Enigma x86 loaders repeatedly relocate the get-PC EBP base. Requiring two immediate
        // EBP adjustments prevents the older single-adjust ASPack profile from claiming them.
        if(pa!=static_cast<std::size_t>(-1)&&call!=static_cast<std::size_t>(-1)&&getpc&&count_ebp_adjust(prof,14)>=2){auto f=profile_fields(prof,enigma_marker);std::vector<std::string>e={"entry loader saves all GPRs and obtains EBP through an early CALL/POP get-PC sequence","bounded loader performs at least two immediate EBP base relocations before transfer"};std::vector<std::string>neg;if(enigma_marker)e.push_back("bounded ENIGMA/section marker is also present (confidence booster only)");else neg.push_back("Enigma marker absent/renamed; classification is semantic");return semantic_protector_family("Enigma Protector-like","x86 repeated-base loader",enigma_marker?.96:.93,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}
        // Armadillo 3.x begins with a PUSHA/get-PC setup and preserves EAX+ECX before entering
        // a dense chain of tiny unconditional branches. The jump chain is traced with a
        // bounded control-flow follower, not counted from arbitrary skipped bytes.
        const bool arm_prefix=trace.insns.size()>=5&&is_push_all(trace.insns[0].mnemonic)&&trace.insns[1].mnemonic==ZYDIS_MNEMONIC_CALL&&trace.insns[2].mnemonic==ZYDIS_MNEMONIC_POP&&trace.insns[2].dst==ZYDIS_REGISTER_EBP&&push_reg(trace.insns[3],ZYDIS_REGISTER_EAX)&&push_reg(trace.insns[4],ZYDIS_REGISTER_ECX);
        const auto arm_jumps=count_small_jumps(trace,32);if(arm_prefix&&arm_jumps>=3){auto f=profile_fields(trace,false);f["small_jump_chain"]=std::to_string(arm_jumps);return semantic_protector_family("Armadillo-like","3.x get-PC/jump-obfuscation loader",.93,packed,{"entry begins PUSHA/CALL/POP-EBP followed by preservation of EAX and ECX","bounded executed-flow trace follows at least three tiny relative JMP obfuscation transfers"},{"classification does not rely on Armadillo product strings"},std::move(f),profile_range(trace));}
        // Obsidium 1.2-1.4 uses small-jump junk chains around an early CALL and then exposes
        // either the caller's stack argument through EDX or clears EAX. Require the entry itself
        // to begin with a tiny JMP so Armadillo's post-get-PC branch maze cannot collide.
        const auto obs_jumps=count_small_jumps(trace,32),obs_call=first_mn(trace,ZYDIS_MNEMONIC_CALL,24);const bool obs_tail=first_if(trace,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_MOV&&i.dst==ZYDIS_REGISTER_EDX&&i.src_mem_base==ZYDIS_REGISTER_ESP;},32)!=static_cast<std::size_t>(-1)||first_if(trace,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_XOR&&i.dst==ZYDIS_REGISTER_EAX;},32)!=static_cast<std::size_t>(-1);
        if(!trace.insns.empty()&&trace.insns.front().mnemonic==ZYDIS_MNEMONIC_JMP&&trace.insns.front().rel_imm&&obs_jumps>=4&&obs_call!=static_cast<std::size_t>(-1)&&obs_tail){auto f=profile_fields(trace,false);f["small_jump_chain"]=std::to_string(obs_jumps);return semantic_protector_family("Obsidium-like","1.2-1.4 short-jump loader",.92,packed,{"entry begins with a tiny relative JMP and bounded executed-flow contains at least four tiny branch transfers","same branch chain contains an early CALL and reaches stack-argument EDX load or EAX-clear loader semantics"},{"classification does not rely on Obsidium product strings"},std::move(f),profile_range(trace));}
        // Yoda's Protector 1.x has an ordinary frame prologue but then two CALLs followed by
        // XOR EAX and an FS-segment exception-chain rewrite. The FS pair is the key independent
        // semantic discriminator.
        const bool frame=prof.insns.size()>=2&&push_reg(prof.insns[0],ZYDIS_REGISTER_EBP)&&mov_reg_reg(prof.insns[1],ZYDIS_REGISTER_EBP,ZYDIS_REGISTER_ESP);const auto y_calls=count_mn(prof,ZYDIS_MNEMONIC_CALL,12),y_fs=count_fs_memory(prof,16);const auto y_xor=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_XOR&&i.dst==ZYDIS_REGISTER_EAX;},14);
        if(frame&&y_calls>=2&&y_xor!=static_cast<std::size_t>(-1)&&y_fs>=2){auto f=profile_fields(prof,false);f["fs_memory_operations"]=std::to_string(y_fs);return semantic_protector_family("Yoda's Protector-like","1.01-1.03 SEH loader",.94,packed,{"entry starts with a conventional EBP frame and performs at least two early CALL transfers","loader clears EAX and performs at least two FS-segment memory operations consistent with SEH-chain manipulation"},{"classification does not rely on Yoda product or section strings"},std::move(f),profile_range(prof));}
    }
    if(x64){
        // Enigma x64 saves an unusually broad register set, saves flags, reserves stack space,
        // emits FXSAVE at RSP and then performs get-PC CALL/POP-RBP. This combination is highly
        // distinctive even when all section/product names are stripped.
        const auto pushes=count_mn(prof,ZYDIS_MNEMONIC_PUSH,24),pf=first_push_flags(prof,24),sub_rsp=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_SUB&&i.dst==ZYDIS_REGISTER_RSP;},28),fx=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_FXSAVE||i.mnemonic==ZYDIS_MNEMONIC_FXSAVE64;},30),call=first_mn(prof,ZYDIS_MNEMONIC_CALL,34);const bool getpc=call!=static_cast<std::size_t>(-1)&&first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_POP&&i.dst==ZYDIS_REGISTER_RBP;},38,call+1)!=static_cast<std::size_t>(-1);
        if(pushes>=15&&pf!=static_cast<std::size_t>(-1)&&sub_rsp!=static_cast<std::size_t>(-1)&&fx!=static_cast<std::size_t>(-1)&&getpc){auto f=profile_fields(prof,enigma_marker);f["saved_register_pushes"]=std::to_string(pushes);std::vector<std::string>e={"x64 loader saves at least fifteen GPRs plus flags before reserving stack space","bounded entry performs FXSAVE at the stack and then CALL/POP-RBP get-PC setup"};std::vector<std::string>neg;if(enigma_marker)e.push_back("bounded ENIGMA/section marker is also present (confidence booster only)");else neg.push_back("Enigma marker absent/renamed; classification is semantic");return semantic_protector_family("Enigma Protector-like","x64 full-state loader",enigma_marker?.97:.95,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}
    }
    return std::nullopt;
}

std::optional<Finding> detect_entry_packer_family(std::span<const std::uint8_t>d,const PeInfo&pe,const PackedPeInfo&packed){
    if(!pe.valid||!packed.candidate)return std::nullopt;
    const auto prof=profile_entry(d,pe);const bool x86=pe.machine==0x14c;
    const bool aspack_marker=section_named(pe,{".aspack",".adata"}),mpress_marker=section_named(pe,{".mpress1",".mpress2"}),nspack_marker=section_named(pe,{".nsp","nsp"}),kkr_marker=section_named(pe,{"kkrunchy"});

    // nSPack 2.x/3.x exposes an unusually constrained resolver import surface and zero
    // SizeOfCode. This survives entry-stub mutation and is stronger than a section label.
    bool nspack_imports=false;static constexpr std::array<std::string_view,6> nspack_names={"LoadLibraryA","GetProcAddress","VirtualProtect","VirtualAlloc","VirtualFree","ExitProcess"};
    const auto soc=pe_size_of_code(d);std::uint32_t total=0;for(const auto&m:pe.imports)total+=static_cast<std::uint32_t>(m.functions.size());
    if(soc&&*soc==0&&total==nspack_names.size())for(const auto&m:pe.imports)if(m.functions.size()==nspack_names.size()){bool ok=true;for(std::size_t i=0;i<nspack_names.size();++i)ok=ok&&!m.functions[i].by_ordinal&&m.functions[i].name==nspack_names[i];if(ok){nspack_imports=true;break;}}
    if(nspack_imports){std::string variant="2.x/3.x resolver geometry";if(!pe.sections.empty()){const auto&s=pe.sections.front();if(s.raw_size&&s.raw_offset<0x200)variant="2.x-like resolver geometry";else if(!s.raw_size&&s.raw_offset>=0x200)variant="3.x-like resolver geometry";}std::vector<std::string>e={"SizeOfCode is zero while the complete import surface is exactly the six-function nSPack loader resolver sequence"};std::vector<std::string>neg;if(nspack_marker)e.push_back("nSPack-like section-name marker is also present (confidence booster only)");else neg.push_back("nSPack section-name marker absent/renamed; classification uses import/header geometry");std::map<std::string,std::string>f{{"basis","STRUCTURAL_IMPORT_GEOMETRY"},{"size_of_code","0"},{"resolver_import_sequence","LoadLibraryA,GetProcAddress,VirtualProtect,VirtualAlloc,VirtualFree,ExitProcess"},{"section_name_marker",nspack_marker?"present":"absent"}};return packer_family("nSPack-like",std::move(variant),nspack_marker?.97:.95,packed,std::move(e),std::move(neg),std::move(f),{});}
    if(!prof.valid)return std::nullopt;

    // MPRESS loaders retain a decompressor shape across x86/x64: saved register state,
    // get-PC setup, then both word and dword/qword LODS operations in the early decoder.
    const auto lodsw=first_mn(prof,ZYDIS_MNEMONIC_LODSW,40),lodsd=first_if(prof,[](const EntryInsn&i){return is_lodsd(i.mnemonic);},40);const auto call=first_mn(prof,ZYDIS_MNEMONIC_CALL,10);const auto lea=first_mn(prof,ZYDIS_MNEMONIC_LEA,10);const auto pushes=count_mn(prof,ZYDIS_MNEMONIC_PUSH,10);const bool mpress_stack=(x86&&first_push_all(prof,3)!=static_cast<std::size_t>(-1))||(!x86&&pushes>=5);if(mpress_stack&&(call!=static_cast<std::size_t>(-1)||(!x86&&lea!=static_cast<std::size_t>(-1)))&&lodsw!=static_cast<std::size_t>(-1)&&lodsd!=static_cast<std::size_t>(-1)){auto f=profile_fields(prof,mpress_marker);std::vector<std::string>e={"entry loader saves broad register state and establishes position-independent decoder state","early decoder contains both LODSW and LODSD/LODSQ string-load semantics"};std::vector<std::string>neg;if(mpress_marker)e.push_back("MPRESS section-name marker is also present (confidence booster only)");else neg.push_back("standard .MPRESS1/.MPRESS2 names absent/renamed; classification is semantic");return packer_family("MPRESS-like",x86?"x86 LZ-style loader":"x64 LZ-style loader",mpress_marker?.95:.92,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}

    if(x86){
        // kkrunchy 0.2x establishes EBP-backed loader state, clears EAX, then uses REP STOSD.
        const bool kkr_start=mov_imm_to(prof.insns.front(),ZYDIS_REGISTER_EBP);const auto ebp_writes=count_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_MOV&&i.dst_mem&&i.dst_mem_base==ZYDIS_REGISTER_EBP;},12);const auto lea_edi=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_LEA&&i.dst==ZYDIS_REGISTER_EDI;},16);const auto xor_eax=first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_XOR&&i.dst==ZYDIS_REGISTER_EAX;},18);const auto rep_stos=first_if(prof,[](const EntryInsn&i){return is_stosd(i.mnemonic)&&i.rep;},24);
        if(kkr_start&&ebp_writes>=2&&lea_edi!=static_cast<std::size_t>(-1)&&xor_eax!=static_cast<std::size_t>(-1)&&rep_stos!=static_cast<std::size_t>(-1)){auto f=profile_fields(prof,kkr_marker);std::vector<std::string>e={"entry loader initializes EBP-backed state with multiple memory writes","loader prepares EDI/EAX and executes REP STOSD in the bounded entry window"};std::vector<std::string>neg;if(kkr_marker)e.push_back("kkrunchy section-name marker is also present (confidence booster only)");else neg.push_back("kkrunchy section-name marker absent/renamed; classification is semantic");return packer_family("kkrunchy-like","0.2x loader",kkr_marker?.95:.92,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}

        // WinUpack 0.2x: ESI source setup, LODSD, explicit EDI<-EAX, XCHG and MOVSD.
        const bool esi_start=mov_imm_to(prof.insns.front(),ZYDIS_REGISTER_ESI);const auto first_lodsd=first_if(prof,[](const EntryInsn&i){return is_lodsd(i.mnemonic);},5);const auto mov_edi_eax=first_if(prof,[](const EntryInsn&i){return mov_reg_reg(i,ZYDIS_REGISTER_EDI,ZYDIS_REGISTER_EAX);},7);const auto xchg=first_mn(prof,ZYDIS_MNEMONIC_XCHG,10);const auto movsd=first_if(prof,[](const EntryInsn&i){return is_movsd(i.mnemonic);},14);
        if(esi_start&&first_lodsd!=static_cast<std::size_t>(-1)&&mov_edi_eax!=static_cast<std::size_t>(-1)&&xchg!=static_cast<std::size_t>(-1)&&movsd!=static_cast<std::size_t>(-1)){auto f=profile_fields(prof,false);return packer_family("WinUpack-like","0.2x copy/decompress loader",.91,packed,{"entry loader initializes ESI, performs LODSD, explicitly transfers EAX to EDI, then uses XCHG + MOVSD semantics"},{"classification does not depend on a WinUpack marker"},std::move(f),profile_range(prof));}

        // FSG 1.3x uses a dense LODSD/XCHG decoder followed by MOVSB; older 1.0/1.1
        // loaders set EBX/EDI/ESI immediates before a push/call decoder handoff.
        const auto lodsd_count=count_if(prof,[](const EntryInsn&i){return is_lodsd(i.mnemonic);},14),xchg_count=count_mn(prof,ZYDIS_MNEMONIC_XCHG,14),movsb=first_mn(prof,ZYDIS_MNEMONIC_MOVSB,18);const bool fsg13=prof.trampoline_hops==0&&esi_start&&lodsd_count>=3&&xchg_count>=2&&movsb!=static_cast<std::size_t>(-1);
        std::set<ZydisRegister> imm_regs;for(std::size_t i=0;i<std::min<std::size_t>(4,prof.insns.size());++i)if(prof.insns[i].mnemonic==ZYDIS_MNEMONIC_MOV&&prof.insns[i].has_imm&&prof.insns[i].dst!=ZYDIS_REGISTER_NONE)imm_regs.insert(prof.insns[i].dst);const bool fsg_old=prof.trampoline_hops==0&&imm_regs.count(ZYDIS_REGISTER_EBX)&&imm_regs.count(ZYDIS_REGISTER_EDI)&&imm_regs.count(ZYDIS_REGISTER_ESI)&&first_mn(prof,ZYDIS_MNEMONIC_PUSH,7)!=static_cast<std::size_t>(-1)&&(first_mn(prof,ZYDIS_MNEMONIC_CALL,12)!=static_cast<std::size_t>(-1)||first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_MOV&&i.dst==ZYDIS_REGISTER_EDX&&i.has_imm;},12)!=static_cast<std::size_t>(-1));
        if(fsg13||fsg_old){auto f=profile_fields(prof,false);std::vector<std::string>e;if(fsg13)e={"entry decoder begins from an immediate ESI source and contains three-or-more LODSD plus repeated XCHG operations","the same bounded decoder transitions to MOVSB copy semantics"};else e={"entry loader initializes the EBX/EDI/ESI state triple from immediates before a push/call-or-decoder handoff"};return packer_family("FSG-like",fsg13?"1.3x decompressor":"1.0/1.1 loader",.90,packed,std::move(e),{"classification does not depend on an FSG marker"},std::move(f),profile_range(prof));}

        // MEW SE loaders commonly jump from the PE entry to an ESI-based LODSD decoder.
        if(prof.trampoline_hops>=1&&esi_start&&lodsd_count>=3&&first_mn(prof,ZYDIS_MNEMONIC_PUSH,14)!=static_cast<std::size_t>(-1)){auto f=profile_fields(prof,false);return packer_family("MEW-like","SE 1.x trampoline/decompressor",.90,packed,{"PE entry resolves through a direct trampoline into an immediate-ESI decoder","trampoline target performs three-or-more LODSD operations with an early stack transfer"},{"classification does not depend on a MEW marker"},std::move(f),profile_range(prof));}

        // ASPack versions consistently save all GPRs, use call/get-PC into EBP, then adjust
        // that base. Immediates and exact register-allocation details are ignored.
        const auto pa=first_push_all(prof,3),ca=first_mn(prof,ZYDIS_MNEMONIC_CALL,6);bool getpc_ebp=false,adjust_ebp=false;std::size_t ebp_adjusts=0;if(ca!=static_cast<std::size_t>(-1)){for(std::size_t i=ca+1;i<std::min(ca+5,prof.insns.size());++i){const auto&x=prof.insns[i];if((x.mnemonic==ZYDIS_MNEMONIC_POP&&x.dst==ZYDIS_REGISTER_EBP)||(x.mnemonic==ZYDIS_MNEMONIC_MOV&&x.dst==ZYDIS_REGISTER_EBP&&x.src_mem_base==ZYDIS_REGISTER_ESP))getpc_ebp=true;}for(std::size_t i=ca+1;i<std::min(ca+11,prof.insns.size());++i){const auto&x=prof.insns[i];if((x.mnemonic==ZYDIS_MNEMONIC_SUB||x.mnemonic==ZYDIS_MNEMONIC_ADD)&&x.dst==ZYDIS_REGISTER_EBP){adjust_ebp=true;++ebp_adjusts;}}}
        if(pa!=static_cast<std::size_t>(-1)&&ca!=static_cast<std::size_t>(-1)&&getpc_ebp&&adjust_ebp&&ebp_adjusts==1&&first_push_flags(prof,pa+1)==static_cast<std::size_t>(-1)){auto f=profile_fields(prof,aspack_marker);std::vector<std::string>e={"entry loader saves all general registers before a relative call/get-PC transfer into EBP","loader subsequently adjusts the recovered EBP image base; immediate values are ignored"};std::vector<std::string>neg;if(aspack_marker)e.push_back("ASPack/.adata section-name marker is also present (confidence booster only)");else neg.push_back("standard ASPack section names absent/renamed; classification is semantic");return packer_family("ASPack-like","1.x/2.x get-PC loader",aspack_marker?.95:.92,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}

        // PECompact has two durable loader shapes in the reference rules: early generations
        // trampoline into PUSHF/PUSHAD/CALL; later loaders build an FS:[0] SEH chain.
        const auto pf=first_push_flags(prof,5),pall=first_push_all(prof,6),early_call=first_mn(prof,ZYDIS_MNEMONIC_CALL,8);const auto fs_count=count_if(prof,[](const EntryInsn&i){return i.fs_mem;},10);const bool pec_legacy=prof.trampoline_hops>=1&&pf!=static_cast<std::size_t>(-1)&&pall==pf+1&&early_call!=static_cast<std::size_t>(-1);const bool pec_seh=mov_imm_to(prof.insns.front(),ZYDIS_REGISTER_EAX)&&fs_count>=2&&first_mn(prof,ZYDIS_MNEMONIC_PUSH,5)!=static_cast<std::size_t>(-1)&&first_if(prof,[](const EntryInsn&i){return i.mnemonic==ZYDIS_MNEMONIC_XOR&&i.dst==ZYDIS_REGISTER_EAX;},10)!=static_cast<std::size_t>(-1);
        if(pec_legacy||pec_seh){const bool marker=ascii_bounded(d,"PEC2",0x600);auto f=profile_fields(prof,marker);std::vector<std::string>e=pec_legacy?std::vector<std::string>{"direct entry trampoline resolves to adjacent PUSHF/PUSHAD state save followed by an early CALL"}:std::vector<std::string>{"entry loader starts from immediate EAX setup and performs multiple FS-segment memory operations","early FS accesses form an SEH-style loader chain and EAX is subsequently cleared"};std::vector<std::string>neg;if(marker)e.push_back("bounded PEC2 header marker is also present (confidence booster only)");else neg.push_back("PEC2 header marker absent; classification is based on loader semantics");return packer_family("PECompact-like",pec_legacy?"1.x trampoline loader":"2.x/3.x SEH loader",marker?.94:.91,packed,std::move(e),std::move(neg),std::move(f),profile_range(prof));}

        // Petite 1.x/2.x retains PUSHF/PUSHAD state save but, unlike PECompact's legacy
        // loader, performs local LEA/push setup without an early relative CALL.
        const auto ordinary_push=first_mn(prof,ZYDIS_MNEMONIC_PUSH,8),early_lea=first_mn(prof,ZYDIS_MNEMONIC_LEA,10);const bool petite=pf!=static_cast<std::size_t>(-1)&&pall==pf+1&&early_call==static_cast<std::size_t>(-1)&&ordinary_push!=static_cast<std::size_t>(-1)&&early_lea!=static_cast<std::size_t>(-1)&&fs_count<2;
        if(petite){auto f=profile_fields(prof,false);return packer_family("Petite-like","1.x/2.x local-state loader",.89,packed,{"entry loader uses adjacent PUSHF/PUSHAD state save followed by local PUSH/LEA setup","no early CALL or multi-FS SEH chain is present, separating this profile from PECompact-like loaders"},{"classification does not depend on a Petite section marker"},std::move(f),profile_range(prof));}
    }
    return std::nullopt;
}
} // namespace

PackedPeInfo detect_packed_pe(const PeInfo&pe,std::uint64_t file_size){
    PackedPeInfo i;if(!pe.valid||pe.sections.empty())return i;
    auto epi=section_index_for_rva(pe,pe.entry_rva);if(epi)i.ep_section_index=static_cast<std::uint32_t>(*epi);
    const PeSection* ep=epi?&pe.sections[*epi]:nullptr;
    i.import_modules=static_cast<std::uint32_t>(pe.imports.size());i.import_functions=import_function_count(pe);
    static constexpr std::string_view resolver_names[]={"LoadLibraryA","LoadLibraryW","GetProcAddress","VirtualProtect","VirtualProtectEx","VirtualAlloc","VirtualAllocEx","NtProtectVirtualMemory","NtAllocateVirtualMemory"};
    for(auto n:resolver_names)if(imported(pe,n))++i.resolver_api_count;
    i.sparse_imports=i.import_functions<=24&&i.import_modules<=4;
    i.resolver_imports=i.resolver_api_count>=2&&i.import_functions<=64;
    if(ep){
        i.ep_high_entropy_exec=(ep->characteristics&SCN_EXEC)&&ep->raw_size>=0x1000&&ep->entropy>=7.25;
        i.ep_writable_exec=(ep->characteristics&SCN_EXEC)&&(ep->characteristics&SCN_WRITE);
        if(i.ep_high_entropy_exec){std::ostringstream e;e<<"entry point is in executable section "<<ep->name<<" with entropy "<<std::fixed<<std::setprecision(3)<<ep->entropy;i.evidence.push_back(e.str());i.structural_score+=3;}
        if(i.ep_writable_exec){i.evidence.push_back("entry-point section is writable+executable (characteristics "+hx(ep->characteristics)+")");i.structural_score+=2;}
    }else i.negative_evidence.push_back("entry point does not map to a parsed section");
    for(const auto&s:pe.sections){
        const bool exec=(s.characteristics&SCN_EXEC)!=0;
        if(exec&&s.raw_size==0&&s.vsize>=0x4000)++i.raw_empty_exec_count;
        if(exec&&s.vsize>=std::uint64_t(s.raw_size)+0x2000&&s.vsize>=std::uint64_t(std::max<std::uint32_t>(s.raw_size,1))*2)++i.exec_virtual_gap_count;
        if(s.raw_size>=0x4000&&s.entropy>=7.5)++i.high_entropy_section_count;
    }
    i.raw_empty_exec=i.raw_empty_exec_count!=0;i.exec_virtual_gap=i.exec_virtual_gap_count!=0;i.high_entropy_payload=i.high_entropy_section_count!=0;
    if(i.raw_empty_exec){i.evidence.push_back(std::to_string(i.raw_empty_exec_count)+" executable section(s) reserve >=16 KiB virtual memory with no file payload");i.structural_score+=3;}
    if(i.exec_virtual_gap){i.evidence.push_back(std::to_string(i.exec_virtual_gap_count)+" executable section(s) have a >=8 KiB and >=2x virtual/raw materialization gap");i.structural_score+=2;}
    if(i.high_entropy_payload){i.evidence.push_back(std::to_string(i.high_entropy_section_count)+" file-backed section(s) >=16 KiB have entropy >=7.5");i.structural_score+=1;}
    if(i.sparse_imports){i.evidence.push_back("sparse import surface: "+std::to_string(i.import_modules)+" module(s), "+std::to_string(i.import_functions)+" function(s)");i.structural_score+=1;}
    if(i.resolver_imports){i.evidence.push_back(std::to_string(i.resolver_api_count)+" loader/materialization API(s) are present in a compact import surface");i.structural_score+=2;}
    i.overlay_size=pe.overlay_size;i.overlay_ratio=file_size?double(i.overlay_size)/double(file_size):0.0;i.large_overlay=i.overlay_size>=0x4000&&i.overlay_ratio>=0.15;
    if(i.large_overlay){std::ostringstream e;e<<"large overlay is "<<i.overlay_size<<" bytes ("<<std::fixed<<std::setprecision(1)<<(i.overlay_ratio*100.0)<<"% of file)";i.evidence.push_back(e.str());i.structural_score+=1;}
    i.tls_pre_entry=pe.tls.present&&!pe.tls.callback_vas.empty();if(i.tls_pre_entry){i.evidence.push_back("TLS callback(s) execute before the PE entry point");i.structural_score+=1;}
    const bool content=i.ep_high_entropy_exec||i.high_entropy_payload,material=i.raw_empty_exec||i.exec_virtual_gap||i.ep_writable_exec,loader=i.resolver_imports||i.sparse_imports;
    i.evidence_categories=static_cast<int>(content)+static_cast<int>(material)+static_cast<int>(loader);
    i.candidate=i.structural_score>=7&&i.evidence_categories>=2;
    i.family_marker_hints=marker_hints(pe);
    if(!i.family_marker_hints.empty()){for(const auto&h:i.family_marker_hints)i.evidence.push_back(h+" present; used only as a family label hint after structural routing");}
    if(!i.candidate&&i.structural_score)i.negative_evidence.push_back("multi-signal packed/loader threshold not met (requires score >=7 and >=2 independent evidence categories)");
    return i;
}

Finding packed_pe_finding(const PackedPeInfo&i,const PeInfo&pe){
    Finding f;f.kind="packer";f.family="Packed/loader-like PE";f.variant="multi-signal structural";f.state=(i.structural_score>=10&&i.evidence_categories==3)?"LIKELY":"SUSPECTED";f.confidence=f.state=="LIKELY"?std::optional<double>(.94):std::optional<double>(.78);f.evidence=i.evidence;f.negative_evidence=i.negative_evidence;
    f.fields["evidence_strength"]="STRUCTURAL_MULTI_SIGNAL";f.fields["structural_score"]=std::to_string(i.structural_score);f.fields["evidence_categories"]=std::to_string(i.evidence_categories)+"/3";f.fields["import_modules"]=std::to_string(i.import_modules);f.fields["import_functions"]=std::to_string(i.import_functions);f.fields["resolver_api_count"]=std::to_string(i.resolver_api_count);f.fields["raw_empty_exec_count"]=std::to_string(i.raw_empty_exec_count);f.fields["exec_virtual_gap_count"]=std::to_string(i.exec_virtual_gap_count);f.fields["high_entropy_section_count"]=std::to_string(i.high_entropy_section_count);f.fields["overlay_size"]=std::to_string(i.overlay_size);f.fields["tls_callbacks"]=std::to_string(pe.tls.callback_vas.size());
    if(i.ep_section_index<pe.sections.size()){const auto&s=pe.sections[i.ep_section_index];f.fields["entry_section_index"]=std::to_string(i.ep_section_index);f.fields["entry_section"]=s.name;f.fields["entry_section_entropy"]=fixed(s.entropy,4);f.fields["entry_section_characteristics"]=hx(s.characteristics);f.ranges.push_back({s.rva,s.vsize,"entry-point section RVA range"});}
    if(!i.family_marker_hints.empty()){std::string h;for(std::size_t n=0;n<i.family_marker_hints.size();++n){if(n)h+="; ";h+=i.family_marker_hints[n];}f.fields["family_marker_hints"]=std::move(h);}
    f.suggested_actions={"unpack:generic-runtime","inspect:entrypoint-and-materialization"};return f;
}

std::vector<Finding> detect_pe_protector_structures(std::span<const std::uint8_t>data,const PeInfo&pe,const PackedPeInfo*packed_info){
    std::vector<Finding> out;if(!pe.valid||pe.sections.empty())return out;const auto local_packed=packed_info?PackedPeInfo{}:detect_packed_pe(pe,data.size());const auto&packed=packed_info?*packed_info:local_packed;if(auto protector=detect_entry_protector_family(data,pe,packed))out.push_back(std::move(*protector));else if(auto family=detect_entry_packer_family(data,pe,packed))out.push_back(std::move(*family));
    const auto epi=section_index_for_rva(pe,pe.entry_rva);const auto ri=pe.resources.present?section_index_for_rva(pe,pe.resources.rva):std::nullopt;const auto reli=pe.relocations.present?section_index_for_rva(pe,pe.relocations.rva):std::nullopt;
    // VMProtect has a stable loader geometry in multiple generations: a high-entropy W+X
    // entry section surrounded by several virtual-only tail sections. Names are optional labels.
    if(pe.sections.size()>7&&epi){
        std::size_t tail_count=5,n=pe.sections.size();if(ri&&*ri>=n-tail_count)++tail_count;if(reli&&*reli>=n-std::min(n,tail_count))++tail_count;tail_count=std::min(n,tail_count);const std::size_t start=n-tail_count;
        std::uint32_t empty=0;std::optional<std::size_t> last_file;
        for(std::size_t x=start;x<n;++x){if((ri&&x==*ri)||(reli&&x==*reli))continue;const auto&s=pe.sections[x];if(s.raw_size==0&&s.vsize>=0x1000)++empty;else if(s.raw_size)last_file=x;}
        if(empty>=3&&last_file&&*last_file==*epi){const auto&s=pe.sections[*epi];const bool strong=(s.characteristics&SCN_EXEC)&&(s.characteristics&SCN_WRITE)&&s.raw_size>=0x1000&&s.entropy>7.55;if(strong){bool named=false;for(const auto&x:pe.sections)if(lower(x.name).rfind(".vmp",0)==0)named=true;std::vector<std::string>e={"tail loader geometry contains "+std::to_string(empty)+" virtual-only section(s)","entry point is in the last file-backed tail section", "entry section is writable+executable with entropy "+fixed(s.entropy,3)};std::vector<std::string>neg;if(named)e.push_back("standard .vmp* section-name marker also present (label booster only)");else neg.push_back("standard .vmp* section names absent/renamed; classification is structural");std::map<std::string,std::string>fields{{"basis","STRUCTURAL_LAYOUT"},{"tail_virtual_only_sections",std::to_string(empty)},{"entry_section_index",std::to_string(*epi)},{"entry_section_characteristics",hx(s.characteristics)},{"section_name_marker",named?"present":"absent"}};out.push_back(structural_family("VMProtect-like","virtualized-loader geometry",named?.94:.89,std::move(e),std::move(neg),std::move(fields),{{s.rva,s.vsize,"VMProtect-like entry/loader section RVA"}}));}}
    }
    // Historical Themida/WinLicense layouts place resources/imports in fixed early sections,
    // start execution exactly at a later section boundary, and keep a high-entropy first payload.
    if(pe.sections.size()>=4&&epi&&ri&&*ri==1&&!pe.imports.empty()){
        auto ii=section_index_for_rva(pe,pe.imports.front().descriptor_rva);if(ii&&*ii==2&&*epi>=3&&pe.entry_rva==pe.sections[*epi].rva){const auto&payload=pe.sections[0],&ep=pe.sections[*epi];if(payload.raw_size>=0x1000&&payload.entropy>=7.5){bool named=false;for(const auto&s:pe.sections){auto n=lower(s.name);if(n==".themida"||n==".winlice")named=true;}std::vector<std::string>e={"resource directory maps to section index 1 and import descriptors to section index 2","entry point is exactly the start of section index "+std::to_string(*epi),"first file-backed payload section entropy is "+fixed(payload.entropy,3)};std::vector<std::string>neg;if(named)e.push_back("standard Themida/WinLicense section-name marker also present (label booster only)");else neg.push_back("standard .themida/.winlice section names absent/renamed; classification is structural");std::map<std::string,std::string>fields{{"basis","STRUCTURAL_LAYOUT"},{"resource_section_index","1"},{"import_section_index","2"},{"entry_section_index",std::to_string(*epi)},{"section_name_marker",named?"present":"absent"}};out.push_back(structural_family("Themida/WinLicense-like",*epi==3?"historical 1.x-like layout":"historical 2.x-like layout",named?.94:.88,std::move(e),std::move(neg),std::move(fields),{{payload.rva,payload.vsize,"high-entropy protected payload section RVA"},{ep.rva,ep.vsize,"protector entry section RVA"}}));}}
    }
    return out;
}
} // namespace prts
