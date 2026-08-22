#include "prts/cpython_cython.hpp"
extern "C" {
#include "Zydis.h"
#ifndef MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES 1
#endif
#include "miniz.h"
}
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <vector>

namespace prts { namespace {
constexpr std::size_t kMaxName=512;
constexpr std::size_t kMaxDoc=8192;
constexpr std::size_t kMaxFunctionInstructions=8192;
constexpr std::size_t kMaxBackwardInstructions=192;
constexpr std::size_t kMaxTypeMethods=512;
constexpr std::size_t kMaxDirectHelpers=64;
constexpr std::size_t kMaxCapiReachableBodies=128;
constexpr std::size_t kMaxCapiExports=64;
constexpr std::size_t kMaxCapiCompressedInput=4096;
constexpr std::size_t kMaxCapiDecompressed=65536;
constexpr std::size_t kMaxCapiZlibStreams=128;

struct Decoded {
    std::uint32_t rva=0;
    ZydisDecodedInstruction ins{};
    std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT> ops{};
};

std::optional<std::size_t> rva_off(const PeInfo&pe,std::uint32_t rva,std::size_t file_size){
    if(rva<pe.headers_size&&rva<file_size)return std::size_t(rva);
    for(const auto&s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva<s.rva||std::uint64_t(rva)>=std::uint64_t(s.rva)+span)continue;
        const auto delta=std::uint64_t(rva)-s.rva;
        if(delta>=s.raw_size)return std::nullopt;
        const auto off=std::uint64_t(s.raw_offset)+delta;
        if(off<file_size)return std::size_t(off);
    }
    return std::nullopt;
}

bool exec_rva(const PeInfo&pe,std::uint32_t rva){
    for(const auto&s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span)
            return (s.characteristics&0x20000000u)!=0;
    }
    return false;
}

bool exec_file_rva(const PeInfo&pe,std::uint32_t rva,std::size_t file_size){
    return exec_rva(pe,rva)&&rva_off(pe,rva,file_size).has_value();
}

template<class T> bool read_rva(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,T&out){
    auto off=rva_off(pe,rva,d.size());
    if(!off||*off+sizeof(T)>d.size())return false;
    std::memcpy(&out,d.data()+*off,sizeof(T));
    return true;
}

std::optional<std::uint32_t> va_rva(const PeInfo&pe,std::uint64_t va,bool require_file,std::size_t file_size){
    if(va<pe.image_base)return std::nullopt;
    const auto x=va-pe.image_base;
    if(x>0xffffffffull)return std::nullopt;
    const auto rva=static_cast<std::uint32_t>(x);
    bool mapped=false;
    if(rva<pe.headers_size)mapped=true;
    for(const auto&s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span){mapped=true;break;}
    }
    if(!mapped)return std::nullopt;
    if(require_file&&!rva_off(pe,rva,file_size))return std::nullopt;
    return rva;
}

std::optional<std::string> cstr(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,
                                std::size_t limit,bool doc){
    auto off=rva_off(pe,rva,d.size());if(!off)return std::nullopt;
    std::string out;
    for(std::size_t i=0;i<limit&&*off+i<d.size();++i){
        const auto c=d[*off+i];
        if(!c)return out;
        if(c<0x20u){if(doc&&(c=='\t'||c=='\r'||c=='\n'))out.push_back(static_cast<char>(c));else return std::nullopt;}
        else out.push_back(static_cast<char>(c));
    }
    return std::nullopt;
}

bool nonexec_file(const PeInfo&pe,std::uint32_t rva,std::size_t n){return rva_off(pe,rva,n).has_value()&&!exec_rva(pe,rva);}

ZydisRegister large(ZydisRegister r){
    return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);
}

bool writes_reg(const Decoded&x,ZydisRegister want){
    want=large(want);
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&large(o.reg.value)==want&&(o.actions&ZYDIS_OPERAND_ACTION_WRITE))return true;
    }
    return false;
}

std::optional<std::uint32_t> rip_mem_rva(const Decoded&x,const ZydisDecodedOperand&o){
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.base!=ZYDIS_REGISTER_RIP||o.mem.index!=ZYDIS_REGISTER_NONE)return std::nullopt;
    const auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;
    const auto t=std::int64_t(x.rva+x.ins.length)+disp;
    if(t<0||t>0xffffffffll)return std::nullopt;
    return static_cast<std::uint32_t>(t);
}

std::optional<std::uint32_t> direct_target(const Decoded&x){
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){
            const auto t=std::int64_t(x.rva+x.ins.length)+o.imm.value.s;
            if(t>=0&&t<=0xffffffffll)return static_cast<std::uint32_t>(t);
        }
    }
    return std::nullopt;
}

std::optional<std::uint32_t> indirect_slot(const Decoded&x){
    if(x.ins.operand_count_visible!=1)return std::nullopt;
    return rip_mem_rva(x,x.ops[0]);
}

std::map<std::uint32_t,std::string> iat_names(const PeInfo&pe){
    std::map<std::uint32_t,std::string> out;
    for(const auto&m:pe.imports){
        if(!m.iat_rva)continue;
        for(std::size_t i=0;i<m.functions.size();++i){
            const auto&f=m.functions[i];if(f.by_ordinal||f.name.empty())continue;
            const auto r=std::uint64_t(m.iat_rva)+i*8ull;
            if(r<=0xffffffffull)out[static_cast<std::uint32_t>(r)]=f.name;
        }
    }
    return out;
}

std::optional<Decoded> decode_one(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva){
    auto off=rva_off(pe,rva,d.size());if(!off)return std::nullopt;
    ZydisDecoder dec;
    if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return std::nullopt;
    Decoded x;x.rva=rva;const auto avail=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*off);
    if(!avail||!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,avail,&x.ins,x.ops.data()))||!x.ins.length)return std::nullopt;
    return x;
}

std::optional<std::string> import_at(std::span<const std::uint8_t>d,const PeInfo&pe,const Decoded&x,
                                     const std::map<std::uint32_t,std::string>&iat){
    if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL&&x.ins.meta.category!=ZYDIS_CATEGORY_UNCOND_BR)return std::nullopt;
    if(auto slot=indirect_slot(x)){
        auto it=iat.find(*slot);if(it!=iat.end())return it->second;
    }
    auto target=direct_target(x);if(!target||!exec_file_rva(pe,*target,d.size()))return std::nullopt;
    auto thunk=decode_one(d,pe,*target);
    if(!thunk||thunk->ins.meta.category!=ZYDIS_CATEGORY_UNCOND_BR)return std::nullopt;
    auto slot=indirect_slot(*thunk);if(!slot)return std::nullopt;
    auto it=iat.find(*slot);return it==iat.end()?std::nullopt:std::optional<std::string>(it->second);
}

std::optional<std::pair<std::uint32_t,std::uint32_t>> function_bounds(const PeInfo&pe,std::uint32_t rva){
    for(const auto&rf:pe.exception.runtime_functions)
        if(rf.begin_rva<=rva&&rva<rf.end_rva&&rf.end_rva>rf.begin_rva)return std::pair{rf.begin_rva,rf.end_rva};
    return std::nullopt;
}

std::optional<std::vector<Decoded>> decode_function(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva){
    auto bounds=function_bounds(pe,rva);if(!bounds)return std::nullopt;
    ZydisDecoder dec;
    if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return std::nullopt;
    std::vector<Decoded> out;std::uint32_t cur=rva;
    while(cur<bounds->second&&out.size()<kMaxFunctionInstructions){
        auto off=rva_off(pe,cur,d.size());if(!off)return std::nullopt;
        const auto avail=std::min<std::size_t>(d.size()-*off,bounds->second-cur);
        Decoded x;x.rva=cur;
        if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,avail,&x.ins,x.ops.data()))||!x.ins.length)return std::nullopt;
        out.push_back(x);cur+=x.ins.length;
    }
    if(cur!=bounds->second||out.empty())return std::nullopt;
    return out;
}

enum class OriginKind { None, StaticPtr, GlobalLoad, CallReturn };
struct Origin {
    OriginKind kind=OriginKind::None;
    std::uint32_t rva=0;
    std::uint32_t call_rva=0;
    std::uint32_t call_target_rva=0;
    std::string import_name;
};

struct FrameSlot {
    ZydisRegister base=ZYDIS_REGISTER_NONE;
    std::int64_t disp=0;
    bool operator<(const FrameSlot&o)const{return std::tie(base,disp)<std::tie(o.base,o.disp);}
    bool operator==(const FrameSlot&o)const{return base==o.base&&disp==o.disp;}
};
std::optional<FrameSlot> frame_slot(const ZydisDecodedOperand&o){
    if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.size!=64||o.mem.index!=ZYDIS_REGISTER_NONE)return std::nullopt;
    const auto b=large(o.mem.base);if(b!=ZYDIS_REGISTER_RBP&&b!=ZYDIS_REGISTER_RSP)return std::nullopt;
    return FrameSlot{b,o.mem.disp.has_displacement?o.mem.disp.value:0};
}
bool volatile_win64(ZydisRegister r){
    r=large(r);return r==ZYDIS_REGISTER_RAX||r==ZYDIS_REGISTER_RCX||r==ZYDIS_REGISTER_RDX||
        r==ZYDIS_REGISTER_R8||r==ZYDIS_REGISTER_R9||r==ZYDIS_REGISTER_R10||r==ZYDIS_REGISTER_R11;
}

enum class LocationKind { Register, Frame };
struct Location {LocationKind kind=LocationKind::Register;ZydisRegister reg=ZYDIS_REGISTER_NONE;FrameSlot frame{};};

Origin origin_before(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,std::size_t before,
                     ZydisRegister start,const std::map<std::uint32_t,std::string>&iat){
    Origin none;Location cur{LocationKind::Register,large(start),{}};std::size_t seen=0;
    for(std::size_t z=before;z-->0&&seen<kMaxBackwardInstructions;){
        const auto&x=ins[z];++seen;
        if(cur.kind==LocationKind::Frame){
            if(x.ins.mnemonic!=ZYDIS_MNEMONIC_MOV||x.ins.operand_count_visible<2)continue;
            auto dst=frame_slot(x.ops[0]);if(!dst||!(*dst==cur.frame))continue;
            const auto&src=x.ops[1];
            if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){cur={LocationKind::Register,large(src.reg.value),{}};continue;}
            if(src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                auto r=va_rva(pe,src.imm.value.u,false,0);if(r)return Origin{OriginKind::StaticPtr,*r,0,0,{}};
            }
            return none;
        }
        const auto reg=cur.reg;
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){
            if(reg==ZYDIS_REGISTER_RAX){
                Origin o;o.kind=OriginKind::CallReturn;o.call_rva=x.rva;
                if(auto imp=import_at(d,pe,x,iat))o.import_name=*imp;
                else if(auto t=direct_target(x))o.call_target_rva=*t;
                return o;
            }
            if(volatile_win64(reg))return none;
        }
        if(!writes_reg(x,reg))continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&src=x.ops[1];
            if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){cur={LocationKind::Register,large(src.reg.value),{}};continue;}
            if(auto fs=frame_slot(src)){cur={LocationKind::Frame,ZYDIS_REGISTER_NONE,*fs};continue;}
            if(src.type==ZYDIS_OPERAND_TYPE_MEMORY){
                if(auto g=rip_mem_rva(x,src))return Origin{OriginKind::GlobalLoad,*g,0,0,{}};
                return none;
            }
            if(src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                auto r=va_rva(pe,src.imm.value.u,false,0);if(r)return Origin{OriginKind::StaticPtr,*r,0,0,{}};
                return none;
            }
            return none;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2){
            if(auto r=rip_mem_rva(x,x.ops[1]))return Origin{OriginKind::StaticPtr,*r,0,0,{}};
            return none;
        }
        return none;
    }
    return none;
}

bool valid_method_flags(std::uint32_t flags){
    constexpr std::uint32_t varargs=0x1,keywords=0x2,noargs=0x4,one=0x8;
    constexpr std::uint32_t cls=0x10,st=0x20,coexist=0x40,fast=0x80,method=0x200;
    constexpr std::uint32_t known=varargs|keywords|noargs|one|cls|st|coexist|fast|method;
    if(!flags||(flags&~known))return false;
    const auto cc=flags&(varargs|keywords|noargs|one|fast|method);
    return cc==varargs||cc==(varargs|keywords)||cc==noargs||cc==one||cc==fast||cc==(fast|keywords)||cc==(method|fast|keywords);
}

struct ParsedMethod {std::string name,doc;std::uint32_t flags=0,record_rva=0,callback_rva=0;};
std::optional<ParsedMethod> parse_method(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva){
    if(!nonexec_file(pe,rva,d.size()))return std::nullopt;
    std::uint64_t nva=0,fva=0,dva=0;std::uint32_t flags=0;
    if(!read_rva(d,pe,rva,nva)||!read_rva(d,pe,rva+8,fva)||!read_rva(d,pe,rva+16,flags)||!read_rva(d,pe,rva+24,dva))return std::nullopt;
    if(!nva||!fva||!valid_method_flags(flags))return std::nullopt;
    auto nr=va_rva(pe,nva,true,d.size()),fr=va_rva(pe,fva,true,d.size());
    if(!nr||!fr||!exec_file_rva(pe,*fr,d.size()))return std::nullopt;
    auto name=cstr(d,pe,*nr,kMaxName,false);if(!name||name->empty())return std::nullopt;
    ParsedMethod m;m.name=*name;m.flags=flags;m.record_rva=rva;m.callback_rva=*fr;
    if(dva){auto dr=va_rva(pe,dva,true,d.size());if(!dr)return std::nullopt;auto doc=cstr(d,pe,*dr,kMaxDoc,true);if(!doc)return std::nullopt;m.doc=*doc;}
    return m;
}

std::optional<std::vector<ParsedMethod>> parse_method_table(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva){
    std::vector<ParsedMethod> out;
    for(std::size_t i=0;i<kMaxTypeMethods;++i){
        const auto rr=std::uint64_t(rva)+i*32ull;if(rr>0xffffffffull)return std::nullopt;
        std::uint64_t nva=0;if(!read_rva(d,pe,static_cast<std::uint32_t>(rr),nva))return std::nullopt;
        if(!nva)return out;
        auto m=parse_method(d,pe,static_cast<std::uint32_t>(rr));if(!m)return std::nullopt;out.push_back(std::move(*m));
    }
    return std::nullopt;
}

bool tainted_methoddef_read(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t target,
                           ZydisRegister start_reg,int depth,std::set<std::tuple<std::uint32_t,int,int>>&vis){
    const auto key=std::make_tuple(target,int(large(start_reg)),depth);if(!vis.insert(key).second)return false;
    auto ins=decode_function(d,pe,target);if(!ins)return false;
    std::map<ZydisRegister,std::int64_t> regs;
    std::map<FrameSlot,std::int64_t> frames;
    regs[large(start_reg)]=0;
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    for(const auto&x:*ins){
        for(std::uint8_t k=0;k<x.ins.operand_count_visible;++k){
            const auto&o=x.ops[k];
            if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||!(o.actions&ZYDIS_OPERAND_ACTION_READ)||o.mem.index!=ZYDIS_REGISTER_NONE)continue;
            auto it=regs.find(large(o.mem.base));if(it==regs.end())continue;
            const auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;
            if(it->second+disp==0x10&&o.size==32)return true;
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){
            if(depth<1)if(auto tr=direct_target(x);tr&&exec_file_rva(pe,*tr,d.size())){
                for(auto r:{ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9})
                    if(regs.count(r)&&tainted_methoddef_read(d,pe,*tr,r,depth+1,vis))return true;
            }
            for(auto r:volatile_regs)regs.erase(r);
            continue;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            if(auto fs=frame_slot(x.ops[0])){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(large(src.reg.value));if(it!=regs.end())frames[*fs]=it->second;else frames.erase(*fs);}
                else frames.erase(*fs);
            }
        }
        if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||
           !(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE))continue;
        const auto dst=large(x.ops[0].reg.value);std::optional<std::int64_t> value;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&src=x.ops[1];
            if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(large(src.reg.value));if(it!=regs.end())value=it->second;}
            else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())value=it->second;}
        }else if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&x.ops[1].mem.index==ZYDIS_REGISTER_NONE){
            auto it=regs.find(large(x.ops[1].mem.base));if(it!=regs.end())value=it->second+(x.ops[1].mem.disp.has_displacement?x.ops[1].mem.disp.value:0);
        }else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&
                 x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
            auto it=regs.find(dst);if(it!=regs.end()){
                const auto imm=static_cast<std::int64_t>(x.ops[1].imm.value.u);
                value=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?it->second+imm:it->second-imm;
            }
        }
        if(value)regs[dst]=*value;else regs.erase(dst);
    }
    return false;
}

bool local_constructor_consumes_methoddef(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t target){
    std::set<std::tuple<std::uint32_t,int,int>>vis;
    return tainted_methoddef_read(d,pe,target,ZYDIS_REGISTER_RCX,0,vis);
}

std::optional<std::uint32_t> memory_static_target(std::span<const std::uint8_t>d,const PeInfo&pe,
                                                  const std::vector<Decoded>&ins,std::size_t at,
                                                  const ZydisDecodedOperand&mem,
                                                  const std::map<std::uint32_t,std::string>&iat){
    if(mem.type!=ZYDIS_OPERAND_TYPE_MEMORY||mem.mem.index!=ZYDIS_REGISTER_NONE)return std::nullopt;
    if(auto r=rip_mem_rva(ins[at],mem))return r;
    const auto disp=mem.mem.disp.has_displacement?mem.mem.disp.value:0;
    if(disp!=0)return std::nullopt;
    auto base=origin_before(d,pe,ins,at,large(mem.mem.base),iat);
    return base.kind==OriginKind::StaticPtr?std::optional<std::uint32_t>(base.rva):std::nullopt;
}

bool global_is_module_dict(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,
                           std::size_t before,std::uint32_t global_rva,const std::map<std::uint32_t,std::string>&iat){
    for(std::size_t i=0;i<before;++i){
        const auto&x=ins[i];
        if(x.ins.mnemonic!=ZYDIS_MNEMONIC_MOV||x.ins.operand_count_visible<2||x.ops[0].type!=ZYDIS_OPERAND_TYPE_MEMORY||
           x.ops[1].type!=ZYDIS_OPERAND_TYPE_REGISTER)continue;
        auto dst=memory_static_target(d,pe,ins,i,x.ops[0],iat);if(!dst||*dst!=global_rva)continue;
        auto value=origin_before(d,pe,ins,i,large(x.ops[1].reg.value),iat);
        if(value.kind==OriginKind::CallReturn&&value.import_name=="PyModule_GetDict")return true;
    }
    return false;
}

bool is_module_dict_origin(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,
                           std::size_t before,const Origin&o,const std::map<std::uint32_t,std::string>&iat){
    if(o.kind==OriginKind::CallReturn&&o.import_name=="PyModule_GetDict")return true;
    return o.kind==OriginKind::GlobalLoad&&global_is_module_dict(d,pe,ins,before,o.rva,iat);
}

struct StaticGlobal {std::uint32_t value_rva=0,store_rva=0;};
std::map<std::uint32_t,StaticGlobal> static_globals(const PeInfo&pe,const std::vector<Decoded>&ins){
    std::map<ZydisRegister,std::uint32_t> regs;std::map<std::uint32_t,StaticGlobal> out;
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    for(const auto&x:ins){
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[0].type==ZYDIS_OPERAND_TYPE_MEMORY&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){
            auto it=regs.find(large(x.ops[1].reg.value));if(it!=regs.end())if(auto g=rip_mem_rva(x,x.ops[0]))out[*g]={it->second,x.rva};
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);std::optional<std::uint32_t> v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2)v=rip_mem_rva(x,x.ops[1]);
            else if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&s=x.ops[1];
                if(s.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(large(s.reg.value));if(it!=regs.end())v=it->second;}
                else if(s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE)v=va_rva(pe,s.imm.value.u,false,0);
            }
            if(v)regs[dst]=*v;else regs.erase(dst);
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)for(auto r:volatile_regs)regs.erase(r);
    }
    return out;
}

std::optional<std::uint32_t> origin_static(const Origin&o,const std::map<std::uint32_t,StaticGlobal>&globals,std::uint32_t before){
    if(o.kind==OriginKind::StaticPtr)return o.rva;
    if(o.kind==OriginKind::GlobalLoad){auto it=globals.find(o.rva);if(it!=globals.end()&&it->second.store_rva<before)return it->second.value_rva;}
    return std::nullopt;
}

std::optional<CPythonCythonType> parse_static_type(std::span<const std::uint8_t>d,const PeInfo&pe,
                                                   std::uint32_t type_rva,std::string_view module,
                                                   std::uint32_t ready_call){
    if(!nonexec_file(pe,type_rva,d.size()))return std::nullopt;
    std::uint64_t name_va=0,methods_va=0;std::int64_t basicsize=0;std::uint64_t flags=0;
    if(!read_rva(d,pe,type_rva+0x18,name_va)||!read_rva(d,pe,type_rva+0x20,basicsize)||
       !read_rva(d,pe,type_rva+0xa8,flags)||!read_rva(d,pe,type_rva+0xe8,methods_va))return std::nullopt;
    if(basicsize<=0||basicsize>(1ll<<24)||!flags)return std::nullopt;
    auto nr=va_rva(pe,name_va,true,d.size());if(!nr)return std::nullopt;
    auto name=cstr(d,pe,*nr,kMaxName,false);if(!name||name->empty())return std::nullopt;
    const auto prefix=std::string(module)+".";
    if(name->rfind(prefix,0)!=0||name->size()<=prefix.size())return std::nullopt;
    CPythonCythonType out;out.name=*name;out.type_rva=type_rva;out.ready_call_rva=ready_call;
    if(methods_va){
        auto mr=va_rva(pe,methods_va,true,d.size());if(!mr)return std::nullopt;
        auto ms=parse_method_table(d,pe,*mr);if(!ms)return std::nullopt;out.methods_rva=*mr;
        for(const auto&m:*ms)out.methods.push_back({m.name,m.doc,m.flags,m.record_rva,m.callback_rva});
    }
    return out;
}

struct SymValue {
    enum class Kind { Unknown, ModuleFieldAddress, StaticPtr } kind=Kind::Unknown;
    std::int64_t offset=0;
    std::uint32_t rva=0;
};

bool wrapper_passes_rcx_to_import(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t target,
                                  const std::map<std::uint32_t,std::string>&iat,std::string_view import_name){
    auto ins=decode_function(d,pe,target);if(!ins)return false;
    std::set<ZydisRegister> regs{ZYDIS_REGISTER_RCX};std::set<FrameSlot> frames;
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    for(const auto&x:*ins){
        if(auto imp=import_at(d,pe,x,iat);imp&&*imp==import_name&&regs.count(ZYDIS_REGISTER_RCX))return true;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            if(auto fs=frame_slot(x.ops[0])){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER&&regs.count(large(src.reg.value)))frames.insert(*fs);
                else frames.erase(*fs);
            }
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);bool tainted=false;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)tainted=regs.count(large(src.reg.value));
                else if(auto fs=frame_slot(src))tainted=frames.count(*fs);
            }
            if(tainted)regs.insert(dst);else regs.erase(dst);
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)for(auto r:volatile_regs)regs.erase(r);
    }
    return false;
}

struct RecoveredStateType {
    CPythonCythonType type;
    std::int64_t field_offset=-1;
    std::uint32_t body_rva=0;
};

std::vector<RecoveredStateType> recover_module_state_types(std::span<const std::uint8_t>d,const PeInfo&pe,
                                                          const std::vector<Decoded>&ins,std::string_view module,
                                                          const std::map<std::uint32_t,std::string>&iat,
                                                          std::map<std::uint32_t,bool>&ready_wrapper_cache){
    std::map<ZydisRegister,SymValue> regs;
    std::map<FrameSlot,SymValue> frames;
    std::map<std::int64_t,SymValue> fields;
    std::map<std::uint32_t,CPythonCythonType> ready;
    std::map<std::uint32_t,std::int64_t> type_fields;
    std::vector<RecoveredStateType> out;
    regs[ZYDIS_REGISTER_RCX]={SymValue::Kind::ModuleFieldAddress,0,0};
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    auto value_of_reg=[&](ZydisRegister r)->SymValue{auto it=regs.find(large(r));return it==regs.end()?SymValue{}:it->second;};
    auto address_of_mem=[&](const ZydisDecodedOperand&o)->SymValue{
        if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE)return{};
        auto b=value_of_reg(o.mem.base);if(b.kind!=SymValue::Kind::ModuleFieldAddress)return{};
        b.offset+=o.mem.disp.has_displacement?o.mem.disp.value:0;return b;
    };
    for(std::size_t i=0;i<ins.size();++i){
        const auto&x=ins[i];
        bool ready_call=false;
        if(auto imp=import_at(d,pe,x,iat);imp&&*imp=="PyType_Ready")ready_call=true;
        else if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)if(auto tr=direct_target(x);tr&&exec_file_rva(pe,*tr,d.size())){
            auto it=ready_wrapper_cache.find(*tr);
            if(it==ready_wrapper_cache.end())it=ready_wrapper_cache.emplace(*tr,wrapper_passes_rcx_to_import(d,pe,*tr,iat,"PyType_Ready")).first;
            ready_call=it->second;
        }
        if(ready_call){
            auto v=value_of_reg(ZYDIS_REGISTER_RCX);
            if(v.kind==SymValue::Kind::StaticPtr){
                auto t=parse_static_type(d,pe,v.rva,module,x.rva);if(t)ready[v.rva]=std::move(*t);
            }
        }
        if(auto imp=import_at(d,pe,x,iat);imp&&*imp=="PyObject_SetAttr"){
            auto v=value_of_reg(ZYDIS_REGISTER_R8);
            if(v.kind==SymValue::Kind::StaticPtr){
                auto it=ready.find(v.rva);if(it!=ready.end()&&!it->second.bind_call_rva){
                    it->second.bind_call_rva=x.rva;
                    auto fi=type_fields.find(v.rva);
                    out.push_back({it->second,fi==type_fields.end()?-1:fi->second});
                }
            }
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&dst=x.ops[0];const auto&src=x.ops[1];
            if(auto fs=frame_slot(dst)){
                SymValue v;
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=value_of_reg(src.reg.value);
                frames[*fs]=v;
            }else if(dst.type==ZYDIS_OPERAND_TYPE_MEMORY){
                auto addr=address_of_mem(dst);
                if(addr.kind==SymValue::Kind::ModuleFieldAddress){
                    SymValue v;if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=value_of_reg(src.reg.value);
                    fields[addr.offset]=v;
                    if(v.kind==SymValue::Kind::StaticPtr)type_fields[v.rva]=addr.offset;
                }
            }
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);SymValue v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=value_of_reg(src.reg.value);
                else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())v=it->second;}
                else if(src.type==ZYDIS_OPERAND_TYPE_MEMORY){
                    auto addr=address_of_mem(src);if(addr.kind==SymValue::Kind::ModuleFieldAddress){auto it=fields.find(addr.offset);if(it!=fields.end())v=it->second;}
                }
            }else if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&x.ops[1].mem.index==ZYDIS_REGISTER_NONE){
                if(auto r=rip_mem_rva(x,x.ops[1]))v={SymValue::Kind::StaticPtr,0,*r};
                else {auto b=value_of_reg(x.ops[1].mem.base);if(b.kind==SymValue::Kind::ModuleFieldAddress){b.offset+=x.ops[1].mem.disp.has_displacement?x.ops[1].mem.disp.value:0;v=b;}}
            }else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                v=value_of_reg(dst);if(v.kind==SymValue::Kind::ModuleFieldAddress){const auto n=static_cast<std::int64_t>(x.ops[1].imm.value.u);v.offset+=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?n:-n;}else v={};
            }
            regs[dst]=v;
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)for(auto r:volatile_regs)regs.erase(r);
    }
    return out;
}

enum class BindValueKind { Unknown, TypePtr, Key, Value, TypeDict };
struct BindValue { BindValueKind kind=BindValueKind::Unknown; std::int64_t offset=0; };

bool type_dict_helper_semantics(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t target,
                                const std::map<std::uint32_t,std::string>&iat){
    auto ins=decode_function(d,pe,target);if(!ins)return false;
    std::map<ZydisRegister,BindValue> regs;
    std::map<FrameSlot,BindValue> frames;
    regs[ZYDIS_REGISTER_RCX]={BindValueKind::TypePtr,0};
    regs[ZYDIS_REGISTER_RDX]={BindValueKind::Key,0};
    regs[ZYDIS_REGISTER_R8]={BindValueKind::Value,0};
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    auto get=[&](ZydisRegister r)->BindValue{auto it=regs.find(large(r));return it==regs.end()?BindValue{}:it->second;};
    bool dict_set=false,type_modified=false;
    for(const auto&x:*ins){
        if(auto imp=import_at(d,pe,x,iat)){
            if(*imp=="PyDict_SetItem"){
                const auto a=get(ZYDIS_REGISTER_RCX),b=get(ZYDIS_REGISTER_RDX),c=get(ZYDIS_REGISTER_R8);
                if(a.kind==BindValueKind::TypeDict&&b.kind==BindValueKind::Key&&c.kind==BindValueKind::Value)dict_set=true;
            }else if(*imp=="PyType_Modified"){
                const auto a=get(ZYDIS_REGISTER_RCX);
                if(dict_set&&a.kind==BindValueKind::TypePtr&&a.offset==0)type_modified=true;
            }
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            if(auto fs=frame_slot(x.ops[0])){
                BindValue v;const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(src.reg.value);
                frames[*fs]=v;
            }
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&
           (x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);BindValue v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(src.reg.value);
                else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())v=it->second;}
                else if(src.type==ZYDIS_OPERAND_TYPE_MEMORY&&src.mem.index==ZYDIS_REGISTER_NONE){
                    const auto b=get(src.mem.base);const auto disp=src.mem.disp.has_displacement?src.mem.disp.value:0;
                    if(b.kind==BindValueKind::TypePtr&&b.offset+disp==0x108&&src.size==64)v={BindValueKind::TypeDict,0};
                }
            }else if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&
                     x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&x.ops[1].mem.index==ZYDIS_REGISTER_NONE){
                v=get(x.ops[1].mem.base);
                if(v.kind==BindValueKind::TypePtr)v.offset+=x.ops[1].mem.disp.has_displacement?x.ops[1].mem.disp.value:0;
                else v={};
            }else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&
                     x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                v=get(dst);
                if(v.kind==BindValueKind::TypePtr){const auto n=static_cast<std::int64_t>(x.ops[1].imm.value.u);v.offset+=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?n:-n;}
                else v={};
            }
            regs[dst]=v;
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)for(auto r:volatile_regs)regs.erase(r);
    }
    return dict_set&&type_modified;
}

std::map<std::uint32_t,std::uint32_t> direct_call_static_rcx_bases(const PeInfo&pe,const std::vector<Decoded>&ins){
    std::map<ZydisRegister,std::uint32_t> regs;
    std::map<FrameSlot,std::uint32_t> frames;
    std::map<std::uint32_t,std::uint32_t> out;
    const std::array<ZydisRegister,7> volatile_regs={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    for(const auto&x:ins){
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)if(auto tr=direct_target(x)){
            auto it=regs.find(ZYDIS_REGISTER_RCX);if(it!=regs.end())out.emplace(*tr,it->second);
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            if(auto fs=frame_slot(x.ops[0])){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(large(src.reg.value));if(it!=regs.end())frames[*fs]=it->second;else frames.erase(*fs);}
                else frames.erase(*fs);
            }
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&
           (x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);std::optional<std::uint32_t> v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2)v=rip_mem_rva(x,x.ops[1]);
            else if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&src=x.ops[1];
                if(src.type==ZYDIS_OPERAND_TYPE_REGISTER){auto it=regs.find(large(src.reg.value));if(it!=regs.end())v=it->second;}
                else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())v=it->second;}
                else if(src.type==ZYDIS_OPERAND_TYPE_IMMEDIATE)v=va_rva(pe,src.imm.value.u,false,0);
            }else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&
                     x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                auto it=regs.find(dst);if(it!=regs.end()){
                    const auto n=static_cast<std::uint64_t>(x.ops[1].imm.value.u);
                    const auto base=std::uint64_t(it->second);
                    const auto z=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?base+n:(base>=n?base-n:0x100000000ull);
                    if(z<=0xffffffffull)v=static_cast<std::uint32_t>(z);
                }
            }
            if(v)regs[dst]=*v;else regs.erase(dst);
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)for(auto r:volatile_regs)regs.erase(r);
    }
    return out;
}

std::optional<std::uint32_t> off_rva(const PeInfo&pe,std::size_t off){
    if(off<pe.headers_size&&off<=0xffffffffu)return static_cast<std::uint32_t>(off);
    for(const auto&s:pe.sections){
        if(off<s.raw_offset||std::uint64_t(off)>=std::uint64_t(s.raw_offset)+s.raw_size)continue;
        const auto r=std::uint64_t(s.rva)+(off-s.raw_offset);
        if(r<=0xffffffffull)return static_cast<std::uint32_t>(r);
    }
    return std::nullopt;
}

std::vector<std::uint32_t> capi_reachable_bodies(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t root){
    std::vector<std::pair<std::uint32_t,int>>todo{{root,0}};std::set<std::uint32_t>seen;std::vector<std::uint32_t>out;
    for(std::size_t q=0;q<todo.size()&&out.size()<kMaxCapiReachableBodies;++q){
        const auto [body,depth]=todo[q];if(!seen.insert(body).second)continue;
        auto ins=decode_function(d,pe,body);if(!ins)continue;out.push_back(body);
        if(depth>=2)continue;
        for(const auto&x:*ins)if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)if(auto tr=direct_target(x);tr&&exec_file_rva(pe,*tr,d.size())){
            auto bounds=function_bounds(pe,*tr);if(!bounds)continue;
            const auto canonical=bounds->first;
            if(!seen.count(canonical)&&todo.size()<kMaxCapiReachableBodies*2)todo.push_back({canonical,depth+1});
        }
    }
    return out;
}

enum class CapiToken { Unknown, Name, Native, Signature, Dict, Capsule };
struct CapiHelperContract {int mode=0;std::uint32_t helper_rva=0,capsule_call_rva=0,dict_set_call_rva=0;};

std::optional<CapiHelperContract> capi_helper_contract(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t target,
                                                       const std::map<std::uint32_t,std::string>&iat,int mode){
    auto ins=decode_function(d,pe,target);if(!ins||!(mode==3||mode==4))return std::nullopt;
    std::map<ZydisRegister,CapiToken>regs;std::map<FrameSlot,CapiToken>frames;
    if(mode==3){regs[ZYDIS_REGISTER_RCX]=CapiToken::Name;regs[ZYDIS_REGISTER_RDX]=CapiToken::Native;regs[ZYDIS_REGISTER_R8]=CapiToken::Signature;}
    else{regs[ZYDIS_REGISTER_RCX]=CapiToken::Dict;regs[ZYDIS_REGISTER_RDX]=CapiToken::Name;regs[ZYDIS_REGISTER_R8]=CapiToken::Native;regs[ZYDIS_REGISTER_R9]=CapiToken::Signature;}
    const std::array<ZydisRegister,7>vol={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    auto get=[&](ZydisRegister r){auto it=regs.find(large(r));return it==regs.end()?CapiToken::Unknown:it->second;};
    bool capsule=false;CapiHelperContract out{mode,target,0,0};
    for(const auto&x:*ins){
        auto imp=import_at(d,pe,x,iat);
        if(imp&&*imp=="PyCapsule_New"&&get(ZYDIS_REGISTER_RCX)==CapiToken::Native&&get(ZYDIS_REGISTER_RDX)==CapiToken::Signature){
            capsule=true;out.capsule_call_rva=x.rva;
        }
        if(imp&&*imp=="PyDict_SetItemString"&&capsule&&get(ZYDIS_REGISTER_RDX)==CapiToken::Name&&get(ZYDIS_REGISTER_R8)==CapiToken::Capsule&&
           (mode==3||get(ZYDIS_REGISTER_RCX)==CapiToken::Dict)){
            out.dict_set_call_rva=x.rva;return out;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2)if(auto fs=frame_slot(x.ops[0])){
            CapiToken v=CapiToken::Unknown;if(x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(x.ops[1].reg.value);frames[*fs]=v;
        }
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);CapiToken v=CapiToken::Unknown;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
                const auto&src=x.ops[1];if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(src.reg.value);else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())v=it->second;}
            }
            regs[dst]=v;
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){
            for(auto r:vol)regs.erase(r);
            if(imp&&*imp=="PyCapsule_New"&&capsule)regs[ZYDIS_REGISTER_RAX]=CapiToken::Capsule;
        }
    }
    return std::nullopt;
}

bool capi_identifier_char(unsigned char c){return c=='_'||(c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z');}
bool capi_identifier(std::string_view x){
    if(x.empty()||x.size()>255||!((x[0]>='A'&&x[0]<='Z')||(x[0]>='a'&&x[0]<='z')||x[0]=='_'))return false;
    return std::all_of(x.begin()+1,x.end(),[](unsigned char c){return capi_identifier_char(c);});
}
bool capi_signature(std::string_view x){
    if(x.size()<4||x.size()>256||x.back()!=')')return false;
    auto lp=x.find('(');if(lp==std::string_view::npos||lp==0||lp+1>=x.size())return false;
    int depth=0;bool alpha=false;
    for(std::size_t i=0;i<x.size();++i){const unsigned char c=x[i];if(c<0x20||c>=0x7f)return false;if((c>='A'&&c<='Z')||(c>='a'&&c<='z')||c=='_')alpha=true;if(c=='(')++depth;else if(c==')'&&--depth<0)return false;}
    return alpha&&depth==0;
}

struct CapiPackedBlock {
    std::vector<std::pair<std::string,std::string>>items; // signature,name
    std::uint32_t compressed_rva=0,compressed_size=0,decompressed_size=0;
    std::size_t signature_bytes=0;
};

std::optional<CapiPackedBlock> parse_capi_packed_at(std::span<const std::uint8_t>plain,std::size_t start,std::size_t n,
                                                    std::optional<std::size_t>expected_signature_bytes,
                                                    std::uint32_t crva,std::uint32_t csize){
    if(!n||n>kMaxCapiExports)return std::nullopt;
    std::size_t p=start;std::vector<std::string>sigs,names;
    for(std::size_t i=0;i<n;++i){
        const auto b=p;while(p<plain.size()&&plain[p])++p;if(p>=plain.size())return std::nullopt;
        std::string x(reinterpret_cast<const char*>(plain.data()+b),p-b);if(!capi_signature(x))return std::nullopt;sigs.push_back(std::move(x));++p;
    }
    const auto sigbytes=p-start;if(expected_signature_bytes&&sigbytes!=*expected_signature_bytes)return std::nullopt;
    for(std::size_t i=0;i<n;++i){
        if(p>=plain.size()||!((plain[p]>='A'&&plain[p]<='Z')||(plain[p]>='a'&&plain[p]<='z')||plain[p]=='_'))return std::nullopt;
        const auto b=p;while(p<plain.size()&&capi_identifier_char(plain[p]))++p;
        std::string x(reinterpret_cast<const char*>(plain.data()+b),p-b);if(!capi_identifier(x))return std::nullopt;names.push_back(std::move(x));
        if(i+1<n){if(p>=plain.size()||plain[p]!=0)return std::nullopt;++p;}else if(p<plain.size()&&plain[p]==0)++p;
    }
    CapiPackedBlock out;out.compressed_rva=crva;out.compressed_size=csize;out.decompressed_size=static_cast<std::uint32_t>(plain.size());out.signature_bytes=sigbytes;
    for(std::size_t i=0;i<n;++i)out.items.push_back({sigs[i],names[i]});
    return out;
}

std::vector<CapiPackedBlock> capi_packed_candidates(std::span<const std::uint8_t>d,const PeInfo&pe,std::size_t n,
                                                    std::optional<std::size_t>expected_signature_bytes){
    std::vector<CapiPackedBlock>out;std::size_t streams=0;
    for(const auto&s:pe.sections){
        if(s.characteristics&0x20000000u||!s.raw_size||s.raw_offset>=d.size())continue;
        const auto len=std::min<std::size_t>(s.raw_size,d.size()-s.raw_offset);
        for(std::size_t j=0;j+2<=len&&streams<kMaxCapiZlibStreams;++j){
            const auto off=std::size_t(s.raw_offset)+j;const auto cmf=d[off],flg=d[off+1];
            if((cmf&0x0fu)!=8u||(cmf>>4)>7u||((std::uint32_t(cmf)<<8)|flg)%31u||(flg&0x20u))continue;
            std::vector<unsigned char>plain(kMaxCapiDecompressed);mz_ulong plen=static_cast<mz_ulong>(plain.size());mz_ulong slen=static_cast<mz_ulong>(std::min<std::size_t>(kMaxCapiCompressedInput,d.size()-off));
            if(mz_uncompress2(plain.data(),&plen,d.data()+off,&slen)!=MZ_OK||!plen||plen>kMaxCapiDecompressed||!slen)continue;
            ++streams;plain.resize(plen);auto rva=off_rva(pe,off);if(!rva||slen>0xffffffffu)continue;
            for(std::size_t start=0;start<plain.size();++start)if(auto c=parse_capi_packed_at(plain,start,n,expected_signature_bytes,*rva,static_cast<std::uint32_t>(slen)))out.push_back(std::move(*c));
        }
    }
    return out;
}

struct RelValue {std::uint64_t root=0;std::int64_t offset=0;bool valid=false;};
std::optional<std::size_t> capi_relative_name_delta(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,
                                                    const std::map<std::uint32_t,std::string>&iat,
                                                    std::optional<std::uint32_t>helper_target){
    std::map<ZydisRegister,RelValue>regs;std::map<FrameSlot,RelValue>frames;std::uint64_t next_root=1;std::optional<RelValue>pending_sig;
    const std::array<ZydisRegister,7>vol={ZYDIS_REGISTER_RAX,ZYDIS_REGISTER_RCX,ZYDIS_REGISTER_RDX,ZYDIS_REGISTER_R8,ZYDIS_REGISTER_R9,ZYDIS_REGISTER_R10,ZYDIS_REGISTER_R11};
    auto get=[&](ZydisRegister r){auto it=regs.find(large(r));return it==regs.end()?RelValue{}:it->second;};
    for(const auto&x:ins){
        auto imp=import_at(d,pe,x,iat);auto tr=direct_target(x);
        if(helper_target&&tr&&*tr==*helper_target){const auto name=get(ZYDIS_REGISTER_RDX),sig=get(ZYDIS_REGISTER_R9);if(name.valid&&sig.valid&&name.root==sig.root&&name.offset>=sig.offset)return std::size_t(name.offset-sig.offset);}
        if(!helper_target&&imp&&*imp=="PyCapsule_New"&&!pending_sig)pending_sig=get(ZYDIS_REGISTER_RDX);
        if(!helper_target&&imp&&*imp=="PyDict_SetItemString"&&pending_sig){const auto name=get(ZYDIS_REGISTER_RDX);if(name.valid&&pending_sig->valid&&name.root==pending_sig->root&&name.offset>=pending_sig->offset)return std::size_t(name.offset-pending_sig->offset);}
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2)if(auto fs=frame_slot(x.ops[0])){RelValue v;if(x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(x.ops[1].reg.value);frames[*fs]=v;}
        if(x.ins.operand_count_visible&&x.ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)){
            const auto dst=large(x.ops[0].reg.value);RelValue v;
            if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){const auto&src=x.ops[1];if(src.type==ZYDIS_OPERAND_TYPE_REGISTER)v=get(src.reg.value);else if(auto fs=frame_slot(src)){auto it=frames.find(*fs);if(it!=frames.end())v=it->second;}else if(src.type==ZYDIS_OPERAND_TYPE_MEMORY&&src.mem.base==ZYDIS_REGISTER_RIP&&src.mem.index==ZYDIS_REGISTER_NONE){auto rr=rip_mem_rva(x,src);if(rr)v={0x100000000ull+*rr,0,true};}}
            else if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&x.ops[1].mem.index==ZYDIS_REGISTER_NONE){if(x.ops[1].mem.base==ZYDIS_REGISTER_RIP){auto rr=rip_mem_rva(x,x.ops[1]);if(rr)v={0x200000000ull+*rr,0,true};}else{v=get(x.ops[1].mem.base);if(v.valid)v.offset+=x.ops[1].mem.disp.has_displacement?x.ops[1].mem.disp.value:0;}}
            else if((x.ins.mnemonic==ZYDIS_MNEMONIC_ADD||x.ins.mnemonic==ZYDIS_MNEMONIC_SUB)&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE){v=get(dst);if(v.valid){auto z=static_cast<std::int64_t>(x.ops[1].imm.value.u);v.offset+=x.ins.mnemonic==ZYDIS_MNEMONIC_ADD?z:-z;}}
            regs[dst]=v;
        }
        if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){for(auto r:vol)regs.erase(r);regs[ZYDIS_REGISTER_RAX]={0x300000000ull+next_root++,0,true};}
    }
    return std::nullopt;
}

struct ExpandedCapiCall {std::uint32_t callback_rva=0,capsule_call_rva=0,dict_set_call_rva=0;};
std::vector<ExpandedCapiCall> expanded_capi_calls(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,
                                                 const std::map<std::uint32_t,std::string>&iat){
    std::vector<ExpandedCapiCall>out;
    for(std::size_t i=0;i<ins.size()&&out.size()<kMaxCapiExports;++i){auto imp=import_at(d,pe,ins[i],iat);if(!imp||*imp!="PyCapsule_New")continue;
        auto cb=origin_before(d,pe,ins,i,ZYDIS_REGISTER_RCX,iat);if(cb.kind!=OriginKind::StaticPtr||!exec_file_rva(pe,cb.rva,d.size()))continue;
        for(std::size_t j=i+1;j<std::min(ins.size(),i+160);++j){auto q=import_at(d,pe,ins[j],iat);if(q&&*q=="PyCapsule_New")break;if(!q||*q!="PyDict_SetItemString")continue;
            auto cap=origin_before(d,pe,ins,j,ZYDIS_REGISTER_R8,iat);if(cap.kind==OriginKind::CallReturn&&cap.call_rva==ins[i].rva){out.push_back({cb.rva,ins[i].rva,ins[j].rva});break;}
        }
    }
    return out;
}

std::vector<std::vector<std::uint32_t>> capi_pointer_arrays(std::span<const std::uint8_t>d,const PeInfo&pe,const std::vector<Decoded>&ins,std::size_t call_index){
    const auto lo=call_index>320?call_index-320:0;std::set<std::uint32_t>refs,lea_sources;
    for(std::size_t i=lo;i<call_index;++i){
        const auto&x=ins[i];
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&s=x.ops[1];if(s.type==ZYDIS_OPERAND_TYPE_MEMORY&&s.size==64&&s.mem.base==ZYDIS_REGISTER_RIP&&s.mem.index==ZYDIS_REGISTER_NONE)if(auto r=rip_mem_rva(x,s))refs.insert(*r);
        }else if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&
                 x.ops[1].mem.base==ZYDIS_REGISTER_RIP&&x.ops[1].mem.index==ZYDIS_REGISTER_NONE){
            if(auto r=rip_mem_rva(x,x.ops[1]))lea_sources.insert(*r);
        }
    }
    std::vector<std::vector<std::uint32_t>>out;std::set<std::vector<std::uint32_t>>unique;
    auto add_array=[&](std::uint32_t start)->void{
        std::vector<std::uint32_t>cbs;
        for(std::size_t i=0;i<=kMaxCapiExports;++i){
            const auto rr=std::uint64_t(start)+i*8ull;if(rr>0xffffffffull)return;std::uint64_t va=0;
            if(!read_rva(d,pe,static_cast<std::uint32_t>(rr),va))return;
            if(!va){if(!cbs.empty()&&unique.insert(cbs).second)out.push_back(cbs);return;}
            auto r=va_rva(pe,va,true,d.size());if(!r||!exec_file_rva(pe,*r,d.size()))return;cbs.push_back(*r);
        }
    };
    std::vector<std::uint32_t>v(refs.begin(),refs.end());
    for(std::size_t i=0;i<v.size();){
        std::size_t j=i+1;while(j<v.size()&&v[j]==v[j-1]+8)++j;
        if(j-i>=2)add_array(v[i]);
        i=j;
    }
    for(auto r:lea_sources)add_array(r);
    return out;
}

std::vector<CPythonCythonCAPIExport> recover_capi_exports(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t root,
                                                         const std::map<std::uint32_t,std::string>&iat){
    const auto bodies=capi_reachable_bodies(d,pe,root);std::map<std::uint32_t,CapiHelperContract>h3,h4;
    for(auto b:bodies){if(auto h=capi_helper_contract(d,pe,b,iat,3))h3[b]=*h;if(auto h=capi_helper_contract(d,pe,b,iat,4))h4[b]=*h;}
    std::vector<CPythonCythonCAPIExport>out;std::set<std::tuple<std::string,std::string,std::uint32_t>>seen;
    // Legacy/static helper callers: all three exported facts are direct file/image pointers.
    for(auto body:bodies){auto ins=decode_function(d,pe,body);if(!ins)continue;for(std::size_t i=0;i<ins->size();++i){auto tr=direct_target((*ins)[i]);if(!tr)continue;auto hi=h3.find(*tr);if(hi==h3.end())continue;
            auto no=origin_before(d,pe,*ins,i,ZYDIS_REGISTER_RCX,iat),fo=origin_before(d,pe,*ins,i,ZYDIS_REGISTER_RDX,iat),so=origin_before(d,pe,*ins,i,ZYDIS_REGISTER_R8,iat);
            if(no.kind!=OriginKind::StaticPtr||fo.kind!=OriginKind::StaticPtr||so.kind!=OriginKind::StaticPtr||!exec_file_rva(pe,fo.rva,d.size()))continue;
            auto name=cstr(d,pe,no.rva,kMaxName,false),sig=cstr(d,pe,so.rva,512,false);if(!name||!sig||!capi_identifier(*name)||!capi_signature(*sig))continue;
            if(seen.insert({*name,*sig,fo.rva}).second)out.push_back({*name,*sig,"legacy_helper_static",fo.rva,*tr,(*ins)[i].rva,hi->second.capsule_call_rva,hi->second.dict_set_call_rva,0,0,0});
    }}
    // Modern helper loop: callback sequence is copied from consecutive image qwords and
    // packed signatures/names are recovered only from a unique bounded zlib table.
    for(auto body:bodies){auto ins=decode_function(d,pe,body);if(!ins)continue;for(std::size_t i=0;i<ins->size();++i){auto tr=direct_target((*ins)[i]);if(!tr)continue;auto hi=h4.find(*tr);if(hi==h4.end())continue;
            auto arrays=capi_pointer_arrays(d,pe,*ins,i);if(arrays.size()!=1)continue;auto delta=capi_relative_name_delta(d,pe,*ins,iat,*tr);if(!delta)continue;
            auto packs=capi_packed_candidates(d,pe,arrays[0].size(),*delta);if(packs.size()!=1)continue;const auto&pk=packs[0];if(pk.items.size()!=arrays[0].size())continue;
            for(std::size_t q=0;q<arrays[0].size();++q)if(seen.insert({pk.items[q].second,pk.items[q].first,arrays[0][q]}).second)out.push_back({pk.items[q].second,pk.items[q].first,"modern_compressed_helper_loop",arrays[0][q],*tr,(*ins)[i].rva,hi->second.capsule_call_rva,hi->second.dict_set_call_rva,pk.compressed_rva,pk.compressed_size,pk.decompressed_size});
    }}
    // Modern optimized expansion: direct capsule calls carry exact native callbacks; packed
    // block pairing additionally requires the observed first-name/signature relative delta.
    for(auto body:bodies){auto ins=decode_function(d,pe,body);if(!ins)continue;auto calls=expanded_capi_calls(d,pe,*ins,iat);if(calls.empty())continue;auto delta=capi_relative_name_delta(d,pe,*ins,iat,std::nullopt);if(!delta)continue;auto packs=capi_packed_candidates(d,pe,calls.size(),*delta);if(packs.size()!=1)continue;const auto&pk=packs[0];
        for(std::size_t q=0;q<calls.size();++q)if(seen.insert({pk.items[q].second,pk.items[q].first,calls[q].callback_rva}).second)out.push_back({pk.items[q].second,pk.items[q].first,"modern_compressed_expanded",calls[q].callback_rva,0,body,calls[q].capsule_call_rva,calls[q].dict_set_call_rva,pk.compressed_rva,pk.compressed_size,pk.decompressed_size});
    }
    std::sort(out.begin(),out.end(),[](const auto&a,const auto&b){return std::tie(a.name,a.signature,a.callback_rva)<std::tie(b.name,b.signature,b.callback_rva);});return out;
}

bool contains_ascii(std::span<const std::uint8_t>d,std::string_view s){
    return std::search(d.begin(),d.end(),s.begin(),s.end())!=d.end();
}

}

CPythonCythonInfo analyze_cpython_cython(std::span<const std::uint8_t>d,const PeInfo&pe,const CPythonExtensionInfo&ext){
    CPythonCythonInfo out;
    if(!pe.valid||!pe.pe64||pe.machine!=0x8664u||!ext.valid){out.state="NOT_CPYTHON_EXTENSION";return out;}
    std::vector<const CPythonExtensionModule*> mods;
    for(const auto&m:ext.modules)if(m.registration_source=="PyInit_export")mods.push_back(&m);
    if(mods.size()!=1){out.state="NOT_CPYTHON_EXTENSION";out.error="Cython refinement currently requires exactly one structurally recovered PyInit module";return out;}
    const auto&mod=*mods.front();out.module_name=mod.module_name;out.moduledef_rva=mod.moduledef_rva;
    for(const auto&s:mod.slots)if(s.slot==2&&s.value_kind=="CALLBACK_RVA")out.exec_rva=s.value_rva;
    if(!out.exec_rva){out.state="NO_PEP489_EXEC";return out;}
    auto root=decode_function(d,pe,out.exec_rva);
    if(!root){out.state="NO_PEP489_EXEC";out.error="Py_mod_exec lacks a bounded x64 RuntimeFunction body";return out;}
    const auto iat=iat_names(pe);
    std::map<std::uint32_t,bool> local_ctor_cache;
    std::vector<CPythonCythonFunction> runtime_functions;
    std::set<std::tuple<std::uint32_t,std::uint32_t>> seen_runtime;
    for(std::size_t i=0;i<root->size();++i){
        auto imp=import_at(d,pe,(*root)[i],iat);if(!imp||*imp!="PyDict_SetItem")continue;
        auto dict=origin_before(d,pe,*root,i,ZYDIS_REGISTER_RCX,iat);
        if(!is_module_dict_origin(d,pe,*root,i,dict,iat))continue;
        auto value=origin_before(d,pe,*root,i,ZYDIS_REGISTER_R8,iat);
        if(value.kind!=OriginKind::CallReturn||value.call_rva>=(*root)[i].rva)continue;
        std::size_t ci=root->size();for(std::size_t q=0;q<i;++q)if((*root)[q].rva==value.call_rva){ci=q;break;}
        if(ci==root->size())continue;
        std::string constructor_kind;std::uint32_t constructor_rva=0;
        if(value.import_name=="PyCMethod_New"||value.import_name=="PyCFunction_New"||value.import_name=="PyCFunction_NewEx")constructor_kind="CPython_method_constructor";
        else if(value.call_target_rva&&exec_file_rva(pe,value.call_target_rva,d.size())){
            auto it=local_ctor_cache.find(value.call_target_rva);
            if(it==local_ctor_cache.end())it=local_ctor_cache.emplace(value.call_target_rva,local_constructor_consumes_methoddef(d,pe,value.call_target_rva)).first;
            if(!it->second)continue;
            constructor_kind="local_method_constructor";
            constructor_rva=value.call_target_rva;
        }else continue;
        auto method_origin=origin_before(d,pe,*root,ci,ZYDIS_REGISTER_RCX,iat);
        if(method_origin.kind!=OriginKind::StaticPtr)continue;
        auto method=parse_method(d,pe,method_origin.rva);if(!method)continue;
        if(!seen_runtime.insert({method->record_rva,(*root)[i].rva}).second)continue;
        CPythonCythonFunction f;f.name=method->name;f.doc=method->doc;f.source="runtime_bound";f.constructor_kind=constructor_kind;
        f.flags=method->flags;f.methoddef_rva=method->record_rva;f.callback_rva=method->callback_rva;f.constructor_rva=constructor_rva;
        f.constructor_call_rva=value.call_rva;f.bind_call_rva=(*root)[i].rva;runtime_functions.push_back(std::move(f));
    }

    std::set<std::uint32_t> bodies{out.exec_rva};
    for(const auto&x:*root){
        if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL)continue;
        auto t=direct_target(x);if(!t||!exec_file_rva(pe,*t,d.size())||!function_bounds(pe,*t))continue;
        if(bodies.size()<kMaxDirectHelpers+1)bodies.insert(*t);
    }
    std::vector<CPythonCythonType> types;std::set<std::uint32_t> seen_types;
    for(auto body:bodies){
        auto ins=(body==out.exec_rva)?root:decode_function(d,pe,body);if(!ins)continue;
        const auto globals=static_globals(pe,*ins);
        for(std::size_t i=0;i<ins->size();++i){
            auto imp=import_at(d,pe,(*ins)[i],iat);if(!imp||*imp!="PyType_Ready")continue;
            auto o=origin_before(d,pe,*ins,i,ZYDIS_REGISTER_RCX,iat);auto type_rva=origin_static(o,globals,(*ins)[i].rva);if(!type_rva)continue;
            auto type=parse_static_type(d,pe,*type_rva,out.module_name,(*ins)[i].rva);if(!type||seen_types.count(type->type_rva))continue;
            for(std::size_t j=i+1;j<ins->size();++j){
                auto bimp=import_at(d,pe,(*ins)[j],iat);if(!bimp||*bimp!="PyObject_SetAttr")continue;
                auto vo=origin_before(d,pe,*ins,j,ZYDIS_REGISTER_R8,iat);auto vr=origin_static(vo,globals,(*ins)[j].rva);
                if(vr&&*vr==type->type_rva){type->bind_call_rva=(*ins)[j].rva;break;}
            }
            if(!type->bind_call_rva)continue;
            seen_types.insert(type->type_rva);types.push_back(std::move(*type));
        }
    }
    std::map<std::uint32_t,bool> ready_wrapper_cache;
    std::vector<RecoveredStateType> state_types;
    for(auto body:bodies){
        auto ins=(body==out.exec_rva)?root:decode_function(d,pe,body);if(!ins)continue;
        for(auto rel:recover_module_state_types(d,pe,*ins,out.module_name,iat,ready_wrapper_cache)){
            rel.body_rva=body;
            if(seen_types.insert(rel.type.type_rva).second)types.push_back(rel.type);
            state_types.push_back(std::move(rel));
        }
    }

    // Map file-visible storage slots back to the exact structurally recovered type.
    // O2 commonly stores the static type directly in a RIP-relative global; O0 modern
    // Cython commonly stores it in a module-state field reached through a static state base.
    std::map<std::uint32_t,std::uint32_t> type_for_storage;
    std::set<std::uint32_t> known_type_rvas;
    for(const auto&t:types)known_type_rvas.insert(t.type_rva);
    for(auto body:bodies){
        auto ins=(body==out.exec_rva)?root:decode_function(d,pe,body);if(!ins)continue;
        for(const auto&[slot,g]:static_globals(pe,*ins))if(known_type_rvas.count(g.value_rva))type_for_storage[slot]=g.value_rva;
    }
    const auto call_bases=direct_call_static_rcx_bases(pe,*root);
    for(const auto&r:state_types)if(r.field_offset>=0){
        auto bi=call_bases.find(r.body_rva);if(bi==call_bases.end())continue;
        const auto storage=std::uint64_t(bi->second)+static_cast<std::uint64_t>(r.field_offset);
        if(storage<=0xffffffffull)type_for_storage[static_cast<std::uint32_t>(storage)]=r.type.type_rva;
    }

    std::map<std::uint32_t,bool> type_dict_helper_cache;
    std::set<std::tuple<std::uint32_t,std::uint32_t>> seen_type_runtime;
    for(std::size_t i=0;i<root->size();++i){
        const auto&x=(*root)[i];if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL)continue;
        auto target=direct_target(x);if(!target||!exec_file_rva(pe,*target,d.size()))continue;
        auto hc=type_dict_helper_cache.find(*target);
        if(hc==type_dict_helper_cache.end())hc=type_dict_helper_cache.emplace(*target,type_dict_helper_semantics(d,pe,*target,iat)).first;
        if(!hc->second)continue;
        auto to=origin_before(d,pe,*root,i,ZYDIS_REGISTER_RCX,iat);
        std::optional<std::uint32_t> type_rva;
        if(to.kind==OriginKind::StaticPtr&&known_type_rvas.count(to.rva))type_rva=to.rva;
        else if(to.kind==OriginKind::GlobalLoad){auto ti=type_for_storage.find(to.rva);if(ti!=type_for_storage.end())type_rva=ti->second;}
        if(!type_rva)continue;
        auto value=origin_before(d,pe,*root,i,ZYDIS_REGISTER_R8,iat);
        if(value.kind!=OriginKind::CallReturn||value.call_rva>=x.rva)continue;
        std::size_t ci=root->size();for(std::size_t q=0;q<i;++q)if((*root)[q].rva==value.call_rva){ci=q;break;}
        if(ci==root->size())continue;
        std::string constructor_kind;std::uint32_t constructor_rva=0;
        if(value.import_name=="PyCMethod_New"||value.import_name=="PyCFunction_New"||value.import_name=="PyCFunction_NewEx")constructor_kind="CPython_method_constructor";
        else if(value.call_target_rva&&exec_file_rva(pe,value.call_target_rva,d.size())){
            auto it=local_ctor_cache.find(value.call_target_rva);
            if(it==local_ctor_cache.end())it=local_ctor_cache.emplace(value.call_target_rva,local_constructor_consumes_methoddef(d,pe,value.call_target_rva)).first;
            if(!it->second)continue;
            constructor_kind="local_method_constructor";constructor_rva=value.call_target_rva;
        }else continue;
        auto mo=origin_before(d,pe,*root,ci,ZYDIS_REGISTER_RCX,iat);if(mo.kind!=OriginKind::StaticPtr)continue;
        auto method=parse_method(d,pe,mo.rva);if(!method)continue;
        if(!seen_type_runtime.insert({*type_rva,method->record_rva}).second)continue;
        auto ti=std::find_if(types.begin(),types.end(),[&](const auto&t){return t.type_rva==*type_rva;});if(ti==types.end())continue;
        CPythonCythonRuntimeTypeMethod m;
        m.name=method->name;m.doc=method->doc;m.constructor_kind=constructor_kind;m.flags=method->flags;
        m.methoddef_rva=method->record_rva;m.callback_rva=method->callback_rva;m.constructor_rva=constructor_rva;
        m.constructor_call_rva=value.call_rva;m.bind_helper_rva=*target;m.bind_call_rva=x.rva;
        ti->runtime_methods.push_back(std::move(m));
    }
    for(auto&t:types)std::sort(t.runtime_methods.begin(),t.runtime_methods.end(),[](const auto&a,const auto&b){return std::tie(a.name,a.callback_rva)<std::tie(b.name,b.callback_rva);});

    const std::array<std::string_view,4> markers={"__pyx_vtable__","__pyx_capi__","cython_function_or_method","__pyx_module_is_main_"};
    for(auto m:markers)if(contains_ascii(d,m))out.markers.emplace_back(m);
    out.marker_support=!out.markers.empty();
    if(out.marker_support||!runtime_functions.empty()||!types.empty())
        out.c_api_exports=recover_capi_exports(d,pe,out.exec_rva,iat);
    if(runtime_functions.empty()&&types.empty()&&out.c_api_exports.empty()){out.state="NO_GENERATED_RELATIONS";return out;}

    std::set<std::tuple<std::string,std::uint32_t,std::string>> seen_functions;
    for(const auto&m:mod.methods){
        CPythonCythonFunction f;f.name=m.name;f.doc=m.doc;f.source="module_method";f.constructor_kind="PyModuleDef.m_methods";
        f.flags=m.flags;f.methoddef_rva=m.record_rva;f.callback_rva=m.callback_rva;
        if(seen_functions.insert({f.name,f.callback_rva,f.source}).second)out.functions.push_back(std::move(f));
    }
    for(auto&f:runtime_functions)if(seen_functions.insert({f.name,f.callback_rva,f.source}).second)out.functions.push_back(std::move(f));
    std::sort(out.functions.begin(),out.functions.end(),[](const auto&a,const auto&b){return std::tie(a.source,a.name,a.callback_rva)<std::tie(b.source,b.name,b.callback_rva);});
    out.types=std::move(types);std::sort(out.types.begin(),out.types.end(),[](const auto&a,const auto&b){return a.type_rva<b.type_rva;});
    if(out.marker_support){out.valid=true;out.state="CONFIRMED_CYTHON";}else out.state="STRUCTURAL_RELATIONS";
    return out;
}

}
