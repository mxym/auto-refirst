#include "prts/nuitka.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts { namespace {

constexpr std::uint64_t kMaxExecScanBytes = 64ull * 1024ull * 1024ull;
constexpr std::uint32_t kMaxTupleInstructions = 192;
constexpr std::uint64_t kMaxTupleSpanBytes = 2048;

struct XInsn {
    std::uint64_t va=0;
    ZydisDecodedInstruction ins{};
    std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT> ops{};
};

ZydisRegister reg64(ZydisRegister r) {
    return r==ZYDIS_REGISTER_NONE ? r : ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);
}

std::optional<std::uint64_t> add_unsigned(std::uint64_t base,std::uint64_t delta) {
    if(base>std::numeric_limits<std::uint64_t>::max()-delta)return{};
    return base+delta;
}
std::optional<std::uint64_t> add_signed(std::uint64_t base,std::int64_t delta) {
    if(delta>=0)return add_unsigned(base,static_cast<std::uint64_t>(delta));
    auto mag=static_cast<std::uint64_t>(-(delta+1))+1;if(base<mag)return{};return base-mag;
}

std::optional<std::pair<std::size_t,std::size_t>> va_extent(const ElfInfo&e,std::uint64_t va,std::size_t n) {
    for(const auto&s:e.segments){
        if(s.type!=1||va<s.address)continue;
        const auto delta=va-s.address;
        if(delta>=s.file_size||s.offset>n||delta>n-s.offset)continue;
        const auto off=s.offset+delta;if(off>=n)return{};
        const auto avail=std::min<std::uint64_t>(s.file_size-delta,n-off);
        return std::pair<std::size_t,std::size_t>{static_cast<std::size_t>(off),static_cast<std::size_t>(avail)};
    }
    return{};
}

std::optional<XInsn> decode_one(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,std::uint64_t va) {
    auto ex=va_extent(e,va,d.size());if(!ex)return{};
    XInsn x;x.va=va;const auto n=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,ex->second);
    if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+ex->first,n,&x.ins,x.ops.data()))||!x.ins.length)return{};
    return x;
}

std::optional<std::uint64_t> rel_target(const XInsn&x) {
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){auto next=add_unsigned(x.va,x.ins.length);return next?add_signed(*next,o.imm.value.s):std::optional<std::uint64_t>{};}
    }
    return{};
}

std::optional<std::uint64_t> rip_target(const XInsn&x,const ZydisDecodedOperand&o) {
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||reg64(o.mem.base)!=ZYDIS_REGISTER_RIP)return{};
    auto next=add_unsigned(x.va,x.ins.length);return next?add_signed(*next,o.mem.disp.has_displacement?o.mem.disp.value:0):std::optional<std::uint64_t>{};
}

bool writes_reg(const XInsn&x,ZydisRegister wanted) {
    wanted=reg64(wanted);
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){const auto&o=x.ops[i];if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(o.reg.value)==wanted&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE))return true;}
    return false;
}

struct CallResolver {
    std::map<std::uint64_t,std::string> direct_symbols;
    std::map<std::string,std::uint64_t> direct_name_vas;
    std::set<std::string> ambiguous_direct_names;
    std::map<std::uint64_t,std::string> got_imports;
};

CallResolver make_call_resolver(const ElfInfo&e) {
    CallResolver out;
    for(const auto&s:e.dynamic.symbols){
        if(s.name.empty()||!s.value||!s.value_file_backed)continue;
        auto [it,inserted]=out.direct_symbols.emplace(s.value,s.name);
        if(!inserted&&it->second!=s.name)it->second.clear();
        auto [ni,ninserted]=out.direct_name_vas.emplace(s.name,s.value);
        if(!ninserted&&ni->second!=s.value)out.ambiguous_direct_names.insert(s.name);
    }
    for(const auto&r:e.dynamic.relocations){
        if(r.symbol_index>=e.dynamic.symbols.size())continue;
        const auto&s=e.dynamic.symbols[r.symbol_index];
        if(!s.imported||s.name.empty()||!r.target_va)continue;
        auto [it,inserted]=out.got_imports.emplace(r.target_va,s.name);
        if(!inserted&&it->second!=s.name)it->second.clear();
    }
    return out;
}

std::optional<std::string> target_symbol_name(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,const CallResolver&r,std::uint64_t va) {
    if(auto it=r.direct_symbols.find(va);it!=r.direct_symbols.end()&&!it->second.empty()&&!r.ambiguous_direct_names.count(it->second)){
        return it->second;
    }
    auto ip=va;
    for(int i=0;i<3;++i){auto x=decode_one(d,e,dec,ip);if(!x)return{};
        if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR&&x->ins.operand_count_visible){auto slot=rip_target(*x,x->ops[0]);if(!slot)return{};auto it=r.got_imports.find(*slot);return it==r.got_imports.end()||it->second.empty()?std::optional<std::string>{}:std::optional<std::string>{it->second};}
        if(x->ins.mnemonic!=ZYDIS_MNEMONIC_ENDBR64&&x->ins.mnemonic!=ZYDIS_MNEMONIC_NOP)return{};
        auto next=add_unsigned(ip,x->ins.length);if(!next)return{};ip=*next;
    }
    return{};
}

std::optional<std::string> call_symbol_name(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,const CallResolver&r,const XInsn&x) {
    if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||!x.ins.operand_count_visible)return{};
    const auto&o=x.ops[0];
    if(auto slot=rip_target(x,o)){auto it=r.got_imports.find(*slot);if(it!=r.got_imports.end()&&!it->second.empty())return it->second;}
    if(auto target=rel_target(x))return target_symbol_name(d,e,dec,r,*target);
    return{};
}

bool read_u64_va(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va,std::uint64_t&out) {
    auto ex=va_extent(e,va,d.size());if(!ex||ex->second<8)return false;out=0;for(int i=7;i>=0;--i)out=(out<<8)|d[ex->first+static_cast<std::size_t>(i)];return true;
}

bool read_u32_va(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va,std::uint32_t&out) {
    auto ex=va_extent(e,va,d.size());if(!ex||ex->second<4)return false;out=std::uint32_t(d[ex->first])|(std::uint32_t(d[ex->first+1])<<8)|(std::uint32_t(d[ex->first+2])<<16)|(std::uint32_t(d[ex->first+3])<<24);return true;
}

std::optional<std::string> cstr_va(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va,std::size_t cap=512) {
    auto ex=va_extent(e,va,d.size());if(!ex)return{};const auto n=std::min(cap,ex->second);std::size_t len=0;while(len<n&&d[ex->first+len])++len;if(len==n)return{};
    return std::string(reinterpret_cast<const char*>(d.data()+ex->first),len);
}

struct DescriptorInfo {std::uint64_t va=0;std::uint32_t fields=0;};
std::optional<DescriptorInfo> validate_descriptor(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va) {
    std::uint64_t name=0,doc=0,fields=0;std::uint32_t count=0;
    auto va8=add_unsigned(va,8),va16=add_unsigned(va,16),va24=add_unsigned(va,24);if(!va8||!va16||!va24)return{};
    if(!read_u64_va(d,e,va,name)||!read_u64_va(d,e,*va8,doc)||!read_u64_va(d,e,*va16,fields)||!read_u32_va(d,e,*va24,count))return{};
    if(count<4||count>64)return{};
    auto n=cstr_va(d,e,name,128),ds=cstr_va(d,e,doc,256);if(!n||*n!="__nuitka_version__"||!ds)return{};
    if(ds->rfind("__compiled__",0)!=0||ds->find("Version information as a named tuple.")==std::string::npos)return{};
    static const std::array<std::string_view,4> expected={"major","minor","micro","releaselevel"};
    for(std::size_t i=0;i<expected.size();++i){std::uint64_t fp=0;auto field_va=add_unsigned(fields,i*16);if(!field_va||!read_u64_va(d,e,*field_va,fp))return{};auto f=cstr_va(d,e,fp,64);if(!f||*f!=expected[i])return{};}
    return DescriptorInfo{va,count};
}

std::optional<std::uint64_t> raw_direct_call(std::span<const std::uint8_t>d,const ElfSegment&s,std::size_t off) {
    if(s.offset>d.size()||s.file_size>d.size()-s.offset||s.file_size<5||off<s.offset||off-s.offset>s.file_size-5||off>d.size()-5||d[off]!=0xe8)return{};
    std::int32_t disp=0;std::memcpy(&disp,d.data()+off+1,4);const auto delta=off-s.offset;if(delta>std::numeric_limits<std::uint64_t>::max()-s.address)return{};auto va=add_unsigned(s.address,delta);if(!va)return{};auto next=add_unsigned(*va,5);return next?add_signed(*next,disp):std::optional<std::uint64_t>{};
}

std::optional<DescriptorInfo> descriptor_before_call(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,std::uint64_t call_va,std::size_t call_off) {
    const auto begin=call_off>160?call_off-160:0;
    for(std::size_t off=begin;off<call_off;++off){
        std::uint64_t va=0;bool mapped=false;for(const auto&s:e.segments)if(s.type==1&&(s.flags&1)&&s.offset<=off&&s.offset<=d.size()&&s.file_size<=d.size()-s.offset&&off-s.offset<s.file_size){auto mapped_va=add_unsigned(s.address,off-s.offset);if(!mapped_va)continue;va=*mapped_va;mapped=true;break;}if(!mapped)continue;
        auto x=decode_one(d,e,dec,va);if(!x||x->ins.mnemonic!=ZYDIS_MNEMONIC_LEA||x->ins.operand_count_visible<2||x->ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||reg64(x->ops[0].reg.value)!=ZYDIS_REGISTER_RSI)continue;
        auto target=rip_target(*x,x->ops[1]);if(!target)continue;auto desc=validate_descriptor(d,e,*target);if(!desc)continue;
        auto next=add_unsigned(x->va,x->ins.length);if(!next)continue;auto ip=*next;bool ok=true;std::uint32_t steps=0;
        while(ip<call_va&&steps++<32){auto y=decode_one(d,e,dec,ip);if(!y){ok=false;break;}auto ynext=add_unsigned(ip,y->ins.length);if(!ynext||*ynext>call_va){ok=false;break;}if(writes_reg(*y,ZYDIS_REGISTER_RSI)){ok=false;break;}if(y->ins.meta.category==ZYDIS_CATEGORY_CALL||y->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||y->ins.meta.category==ZYDIS_CATEGORY_RET){ok=false;break;}ip=*ynext;}
        if(ok&&ip==call_va)return desc;
    }
    return{};
}

std::optional<XInsn> find_next_named_call(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,const CallResolver&r,std::uint64_t ip,std::string_view name) {
    for(std::uint32_t steps=0;steps<16;++steps){auto x=decode_one(d,e,dec,ip);if(!x)return{};if(x->ins.meta.category==ZYDIS_CATEGORY_CALL){auto n=call_symbol_name(d,e,dec,r,*x);if(n&&*n==name)return x;return{};}if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||x->ins.meta.category==ZYDIS_CATEGORY_RET)return{};auto next=add_unsigned(ip,x->ins.length);if(!next)return{};ip=*next;}
    return{};
}

bool named_call_within(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,const CallResolver&r,std::uint64_t begin,std::string_view name,std::size_t span) {
    const auto ex=va_extent(e,begin,d.size());if(!ex)return false;auto end=add_unsigned(begin,std::min<std::uint64_t>(span,ex->second));if(!end)return false;auto ip=begin;
    for(std::uint32_t steps=0;ip<*end&&steps<128;++steps){auto x=decode_one(d,e,dec,ip);if(!x)return false;if(x->ins.meta.category==ZYDIS_CATEGORY_CALL){auto n=call_symbol_name(d,e,dec,r,*x);if(n&&*n==name)return true;}if(x->ins.meta.category==ZYDIS_CATEGORY_RET)return false;auto next=add_unsigned(ip,x->ins.length);if(!next)return false;ip=*next;}
    return false;
}

enum class ProvKind {Unknown,Tuple,CallResult};
struct Prov {ProvKind kind=ProvKind::Unknown;std::size_t call=0;};
struct CallRecord {std::uint64_t target=0,arg=0;bool arg_known=false;std::string target_name,pointed_string;};

void clobber_callers(std::map<ZydisRegister,Prov>&regs) {
    for(auto r:{ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_RSI,ZYDIS_REGISTER_RDI,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11})regs[reg64(r)]={};
}

std::optional<NuitkaCompiledVersionInfo> recover_tuple(std::span<const std::uint8_t>d,const ElfInfo&e,const ZydisDecoder&dec,const CallResolver&resolver,const DescriptorInfo&desc,const XInsn&new_call) {
    std::map<ZydisRegister,Prov>regs;std::set<std::uint64_t>tuple_globals;std::vector<CallRecord>calls;
    regs[ZYDIS_REGISTER_RAX]={ProvKind::Tuple,0};bool rdi_known=false;std::uint64_t rdi_value=0;std::optional<std::int64_t>first_slot;std::array<std::uint32_t,3>version{};std::size_t version_count=0;std::uint64_t constructor=0;std::string release;
    auto ip0=add_unsigned(new_call.va,new_call.ins.length);if(!ip0)return{};auto end=add_unsigned(*ip0,kMaxTupleSpanBytes);if(!end)return{};auto ip=*ip0;
    for(std::uint32_t steps=0;steps<kMaxTupleInstructions&&ip<*end;++steps){
        auto x=decode_one(d,e,dec,ip);if(!x)return{};
        if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||x->ins.meta.category==ZYDIS_CATEGORY_RET)return{};
        if(x->ins.meta.category==ZYDIS_CATEGORY_CALL){
            auto target=rel_target(*x);if(!target)return{};CallRecord c;c.target=*target;c.arg_known=rdi_known;c.arg=rdi_value;if(auto n=call_symbol_name(d,e,dec,resolver,*x))c.target_name=*n;
            if(c.arg_known&&c.target_name=="PyUnicode_FromString"){auto s=cstr_va(d,e,c.arg,64);if(s)c.pointed_string=*s;}
            calls.push_back(std::move(c));const auto id=calls.size()-1;clobber_callers(regs);regs[ZYDIS_REGISTER_RAX]={ProvKind::CallResult,id};rdi_known=false;auto next=add_unsigned(ip,x->ins.length);if(!next)return{};ip=*next;continue;
        }

        bool recognized_dest=false;
        if(x->ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x->ins.operand_count_visible>=2){const auto&dst=x->ops[0];const auto&src=x->ops[1];
            if(dst.type==ZYDIS_OPERAND_TYPE_REGISTER){const auto dr=reg64(dst.reg.value);Prov p{};
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(reg64(src.reg.value));if(it!=regs.end())p=it->second;}
                else if(src.type==ZYDIS_OPERAND_TYPE_MEMORY){if(auto m=rip_target(*x,src);m&&tuple_globals.count(*m))p={ProvKind::Tuple,0};}
                regs[dr]=p;recognized_dest=true;
                if(dr==ZYDIS_REGISTER_RDI){if(src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!src.imm.is_relative){rdi_known=true;rdi_value=src.imm.value.u;}else rdi_known=false;}
            }else if(dst.type==ZYDIS_OPERAND_TYPE_MEMORY&&src.type==ZYDIS_OPERAND_TYPE_REGISTER){
                Prov sv{};auto it=regs.find(reg64(src.reg.value));if(it!=regs.end())sv=it->second;
                if(auto m=rip_target(*x,dst)){if(sv.kind==ProvKind::Tuple)tuple_globals.insert(*m);}
                const auto br=reg64(dst.mem.base);auto bi=regs.find(br);if(dst.mem.index==ZYDIS_REGISTER_NONE&&bi!=regs.end()&&bi->second.kind==ProvKind::Tuple&&sv.kind==ProvKind::CallResult&&sv.call<calls.size()){
                    const auto disp=dst.mem.disp.has_displacement?dst.mem.disp.value:0;const auto&c=calls[sv.call];
                    if(version_count<3){
                        if(!first_slot)first_slot=disp;
                        if(disp!=*first_slot+static_cast<std::int64_t>(version_count*8)||!c.arg_known||c.arg>1000000)return{};
                        if(!constructor){if(!c.target)return{};constructor=c.target;}else if(constructor!=c.target)return{};
                        version[version_count++]=static_cast<std::uint32_t>(c.arg);
                    }else if(release.empty()&&disp==*first_slot+24){
                        if(c.target_name!="PyUnicode_FromString"||c.pointed_string.empty())return{};
                        // Nuitka code generation maps is_final to exactly
                        // "release" or "candidate" and discards rc_number.
                        // The PyStructSequence field documentation mentions
                        // alpha/beta for sys.version_info similarity, but
                        // those strings are not emitted by the generations
                        // covered by this structural profile.
                        if(c.pointed_string!="candidate"&&c.pointed_string!="release")return{};
                        release=c.pointed_string;
                    }
                }
            }
        }else if(x->ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x->ins.operand_count_visible>=2&&x->ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER){
            const auto dr=reg64(x->ops[0].reg.value);regs[dr]={};recognized_dest=true;if(dr==ZYDIS_REGISTER_RDI){auto t=rip_target(*x,x->ops[1]);rdi_known=t.has_value();if(t)rdi_value=*t;}
        }else if(x->ins.mnemonic==ZYDIS_MNEMONIC_XOR&&x->ins.operand_count_visible>=2&&x->ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&x->ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&reg64(x->ops[0].reg.value)==reg64(x->ops[1].reg.value)){
            const auto dr=reg64(x->ops[0].reg.value);regs[dr]={};recognized_dest=true;if(dr==ZYDIS_REGISTER_RDI){rdi_known=true;rdi_value=0;}
        }
        if(!recognized_dest){
            for(auto&[r,p]:regs)if(p.kind!=ProvKind::Unknown&&writes_reg(*x,r))p={};
            if(writes_reg(*x,ZYDIS_REGISTER_RDI)){rdi_known=false;}
        }
        if(version_count==3&&!release.empty())break;
        auto next=add_unsigned(ip,x->ins.length);if(!next)return{};ip=*next;
    }
    if(version_count!=3||release.empty()||(!version[0]&&!version[1]&&!version[2]))return{};
    auto constructor_name=target_symbol_name(d,e,dec,resolver,constructor);
    bool constructor_ok=constructor_name&&*constructor_name=="PyLong_FromLong";
    std::string profile;
    if(constructor_ok){auto it=resolver.direct_symbols.find(constructor);profile=it!=resolver.direct_symbols.end()&&it->second=="PyLong_FromLong"?"ELF64_X86_64_PYSTRUCTSEQUENCE_PYLONG_DIRECT":"ELF64_X86_64_PYSTRUCTSEQUENCE_PYLONG_PLT_IMPORT";}
    else{profile="ELF64_X86_64_PYSTRUCTSEQUENCE_NUITKA_INT_WRAPPER";constructor_ok=named_call_within(d,e,dec,resolver,constructor,"_PyLong_New",256);}
    if(!constructor_ok)return{};
    NuitkaCompiledVersionInfo out;out.valid=true;out.major=version[0];out.minor=version[1];out.micro=version[2];out.releaselevel=release;out.profile=std::move(profile);out.descriptor_va=desc.va;out.descriptor_field_count=desc.fields;out.int_constructor_va=constructor;return out;
}

} // namespace

NuitkaCompiledVersionInfo detect_nuitka_compiled_version(std::span<const std::uint8_t>d,const ElfInfo&e) {
    NuitkaCompiledVersionInfo empty;
    if(!e.valid||!e.elf64||!e.little_endian||e.machine!=62||e.dynamic.state!="RESOLVED")return empty;
    const auto resolver=make_call_resolver(e);
    std::uint64_t exec_bytes=0;for(const auto&s:e.segments)if(s.type==1&&(s.flags&1)){if(s.file_size>kMaxExecScanBytes-exec_bytes){empty.error="Nuitka compiled-version executable scan exceeds bounded 64 MiB profile";return empty;}exec_bytes+=s.file_size;}
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64))){empty.error="Zydis decoder initialization failed";return empty;}
    std::optional<NuitkaCompiledVersionInfo> found;
    for(const auto&s:e.segments){if(s.type!=1||!(s.flags&1)||s.offset>=d.size())continue;const auto n=std::min<std::uint64_t>(s.file_size,d.size()-s.offset);
        for(std::size_t rel=0;rel+5<=n;++rel){const auto off=static_cast<std::size_t>(s.offset)+rel;if(d[off]!=0xe8)continue;auto raw=raw_direct_call(d,s,off);if(!raw)continue;auto call_va=add_unsigned(s.address,rel);if(!call_va)continue;auto ci=decode_one(d,e,dec,*call_va);if(!ci||ci->ins.meta.category!=ZYDIS_CATEGORY_CALL||ci->ins.length!=5)continue;auto init_name=call_symbol_name(d,e,dec,resolver,*ci);if(!init_name||*init_name!="PyStructSequence_InitType")continue;
            auto desc=descriptor_before_call(d,e,dec,*call_va,off);if(!desc)continue;auto next=add_unsigned(*call_va,ci->ins.length);if(!next)continue;auto nc=find_next_named_call(d,e,dec,resolver,*next,"PyStructSequence_New");if(!nc)continue;
            auto v=recover_tuple(d,e,dec,resolver,*desc,*nc);if(!v)continue;v->init_call_va=*call_va;
            if(found){empty.error="multiple independently validated Nuitka __compiled__ version initializers found; exact tuple withheld";return empty;}found=std::move(v);
        }
    }
    return found.value_or(empty);
}

} // namespace prts
