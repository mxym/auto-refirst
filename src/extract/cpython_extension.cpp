#include "prts/cpython_extension.hpp"
extern "C" {
#include "Zydis.h"
}
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

namespace prts { namespace {
constexpr std::size_t kInitWindow=384;
constexpr std::size_t kMaxInitInstructions=512;
constexpr std::size_t kMaxBackwardInstructions=192;
constexpr std::size_t kMaxMethods=1024;
constexpr std::size_t kMaxSlots=64;
constexpr std::size_t kMaxInittab=4096;
constexpr std::size_t kMaxName=512;
constexpr std::size_t kMaxDoc=8192;
constexpr std::uint32_t kKnownModuleMethodFlags=0x00ffu;

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

bool mapped_rva(const PeInfo&pe,std::uint32_t rva){
    if(rva<pe.headers_size)return true;
    if(pe.image_size&&rva>=pe.image_size)return false;
    for(const auto&s:pe.sections){
        const auto span=std::max(s.vsize,s.raw_size);
        if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span)return true;
    }
    return false;
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

std::optional<std::uint32_t> va_image_rva(const PeInfo&pe,std::uint64_t va){
    if(va<pe.image_base)return std::nullopt;
    const auto delta=va-pe.image_base;
    if(delta>0xffffffffull)return std::nullopt;
    const auto rva=static_cast<std::uint32_t>(delta);
    if(!mapped_rva(pe,rva))return std::nullopt;
    return rva;
}

std::optional<std::uint32_t> va_file_rva(const PeInfo&pe,std::uint64_t va,std::size_t file_size){
    auto rva=va_image_rva(pe,va);
    if(!rva||!rva_off(pe,*rva,file_size))return std::nullopt;
    return rva;
}

enum class CStrKind { Name, Doc };
std::optional<std::string> cstr(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,
                                std::size_t limit,CStrKind kind){
    auto off=rva_off(pe,rva,d.size());
    if(!off)return std::nullopt;
    std::string out;
    for(std::size_t i=0;i<limit&&*off+i<d.size();++i){
        const auto c=d[*off+i];
        if(!c)return out;
        if(c<0x20u){
            if(kind==CStrKind::Doc&&(c=='\t'||c=='\r'||c=='\n'))out.push_back(static_cast<char>(c));
            else return std::nullopt;
        }else out.push_back(static_cast<char>(c));
    }
    return std::nullopt;
}

bool valid_module_method_flags(std::uint32_t flags){
    if(!flags||(flags&~kKnownModuleMethodFlags))return false;
    constexpr std::uint32_t varargs=0x0001u,keywords=0x0002u,noargs=0x0004u,one=0x0008u,fast=0x0080u;
    const auto cc=flags&(varargs|keywords|noargs|one|fast);
    return cc==varargs||cc==(varargs|keywords)||cc==noargs||cc==one||cc==fast||cc==(fast|keywords);
}

std::string expected_module_name(std::string_view export_name){
    constexpr std::string_view p="PyInit_";
    if(export_name.rfind(p,0)!=0||export_name.size()==p.size())return{};
    auto n=std::string(export_name.substr(p.size()));
    if(!std::all_of(n.begin(),n.end(),[](unsigned char c){
        return c=='_'||(c>='0'&&c<='9')||(c>='A'&&c<='Z')||(c>='a'&&c<='z');
    }))return{};
    return n;
}

struct Decoded {
    std::uint32_t rva=0;
    ZydisDecodedInstruction ins{};
    std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT> ops{};
};

ZydisRegister large(ZydisRegister r){
    return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);
}

bool writes_reg(const Decoded&x,ZydisRegister want){
    want=large(want);
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type==ZYDIS_OPERAND_TYPE_REGISTER&&large(o.reg.value)==want&&
           (o.actions&ZYDIS_OPERAND_ACTION_MASK_WRITE))return true;
    }
    return false;
}

bool control_barrier(const Decoded&x){
    return x.ins.meta.category==ZYDIS_CATEGORY_CALL||
           x.ins.meta.category==ZYDIS_CATEGORY_COND_BR||
           x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||
           x.ins.meta.category==ZYDIS_CATEGORY_RET||
           x.ins.meta.category==ZYDIS_CATEGORY_INTERRUPT||
           x.ins.meta.category==ZYDIS_CATEGORY_SYSTEM;
}

std::optional<std::uint32_t> pointer_before(std::span<const std::uint8_t>d,const PeInfo&pe,
                                            const std::vector<Decoded>&ins,ZydisRegister start){
    auto cur=large(start);std::size_t seen=0;
    for(std::size_t z=ins.size();z-->0&&seen<kMaxBackwardInstructions;){
        const auto&x=ins[z];++seen;
        if(control_barrier(x))return std::nullopt;
        if(!writes_reg(x,cur))continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&q=x.ops[1];
            if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=large(q.reg.value);continue;}
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){
                if(x.ops[0].size!=64)return std::nullopt;
                return va_image_rva(pe,q.imm.value.u);
            }
            if(q.type==ZYDIS_OPERAND_TYPE_MEMORY&&q.mem.index==ZYDIS_REGISTER_NONE&&
               q.mem.base==ZYDIS_REGISTER_RIP){
                const auto disp=q.mem.disp.has_displacement?q.mem.disp.value:0;
                const auto sr=std::int64_t(x.rva+x.ins.length)+disp;
                if(sr<0||sr>0xffffffffll)return std::nullopt;
                std::uint64_t va=0;
                if(!read_rva(d,pe,static_cast<std::uint32_t>(sr),va))return std::nullopt;
                return va_image_rva(pe,va);
            }
            return std::nullopt;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&
           x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){
            const auto&m=x.ops[1].mem;
            if(m.index!=ZYDIS_REGISTER_NONE||m.base!=ZYDIS_REGISTER_RIP)return std::nullopt;
            const auto disp=m.disp.has_displacement?m.disp.value:0;
            const auto target=std::int64_t(x.rva+x.ins.length)+disp;
            if(target<0||target>0xffffffffll)return std::nullopt;
            const auto rva=static_cast<std::uint32_t>(target);
            return mapped_rva(pe,rva)?std::optional<std::uint32_t>(rva):std::nullopt;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> scalar_before(const std::vector<Decoded>&ins,ZydisRegister start){
    auto cur=large(start);std::size_t seen=0;
    for(std::size_t z=ins.size();z-->0&&seen<kMaxBackwardInstructions;){
        const auto&x=ins[z];++seen;
        if(control_barrier(x))return std::nullopt;
        if(!writes_reg(x,cur))continue;
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2){
            const auto&q=x.ops[1];
            if(q.type==ZYDIS_OPERAND_TYPE_REGISTER){cur=large(q.reg.value);continue;}
            if(q.type==ZYDIS_OPERAND_TYPE_IMMEDIATE)return q.imm.value.u;
            return std::nullopt;
        }
        if(x.ins.mnemonic==ZYDIS_MNEMONIC_XOR&&x.ins.operand_count_visible>=2&&
           x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER&&large(x.ops[1].reg.value)==cur)return 0;
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> direct_target_rva(const Decoded&x){
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type!=ZYDIS_OPERAND_TYPE_IMMEDIATE||!o.imm.is_relative)continue;
        const auto target=std::int64_t(x.rva+x.ins.length)+o.imm.value.s;
        if(target<0||target>0xffffffffll)return std::nullopt;
        return static_cast<std::uint32_t>(target);
    }
    return std::nullopt;
}

std::optional<std::uint32_t> rip_indirect_slot_rva(const Decoded&x){
    for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){
        const auto&o=x.ops[i];
        if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||
           o.mem.base!=ZYDIS_REGISTER_RIP)continue;
        const auto disp=o.mem.disp.has_displacement?o.mem.disp.value:0;
        const auto slot=std::int64_t(x.rva+x.ins.length)+disp;
        if(slot>=0&&slot<=0xffffffffll)return static_cast<std::uint32_t>(slot);
    }
    return std::nullopt;
}

std::size_t init_span(const PeInfo&pe,std::uint32_t rva){
    std::size_t span=kInitWindow;
    for(const auto&rf:pe.exception.runtime_functions){
        if(rf.begin_rva<=rva&&rva<rf.end_rva){
            span=std::min<std::size_t>(span,rf.end_rva-rva);
            break;
        }
    }
    return span;
}

struct InitContract {
    std::uint32_t moduledef_rva=0;
    std::uint32_t api_version=0;
    std::string api;
};

std::optional<InitContract> find_init_contract(std::span<const std::uint8_t>d,const PeInfo&pe,
                                               std::uint32_t init_rva,
                                               const std::map<std::uint32_t,std::string>&iat,
                                               const std::map<std::uint32_t,std::string>&direct,
                                               std::string&error){
    auto entry_off=rva_off(pe,init_rva,d.size());
    if(!entry_off){error="PyInit/inittab callback RVA is not file-backed";return std::nullopt;}
    ZydisDecoder decoder;
    if(!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64))){
        error="Zydis decoder initialization failed";return std::nullopt;
    }
    const auto max_span=init_span(pe,init_rva);
    const auto max_rva=std::uint64_t(init_rva)+max_span;
    struct Work { std::uint32_t rva=0; std::vector<Decoded> prior; };
    std::deque<Work> todo;
    std::set<std::uint32_t> scheduled;
    auto enqueue=[&](std::uint32_t rva,const std::vector<Decoded>&prior){
        if(rva<init_rva||std::uint64_t(rva)>=max_rva||!rva_off(pe,rva,d.size()))return;
        if(scheduled.insert(rva).second)todo.push_back({rva,prior});
    };
    enqueue(init_rva,{});
    std::string last_api_error;
    std::size_t decoded=0;
    while(!todo.empty()&&decoded<kMaxInitInstructions){
        auto work=std::move(todo.front());todo.pop_front();
        auto cur=work.rva;auto prior=std::move(work.prior);
        while(decoded<kMaxInitInstructions&&std::uint64_t(cur)<max_rva){
            auto off=rva_off(pe,cur,d.size());
            if(!off){error="module-init decode reached non-file-backed bytes";return std::nullopt;}
            const auto avail=std::min<std::size_t>(d.size()-*off,static_cast<std::size_t>(max_rva-cur));
            Decoded x;x.rva=cur;
            if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,d.data()+*off,avail,&x.ins,x.ops.data()))||
               !x.ins.length){
                error="module-init instruction decode failed";return std::nullopt;
            }
            ++decoded;
            const auto next=static_cast<std::uint32_t>(std::uint64_t(cur)+x.ins.length);
            const bool transfer=x.ins.meta.category==ZYDIS_CATEGORY_CALL||
                                x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR;
            std::optional<std::string> api;
            if(transfer){
                if(auto tr=direct_target_rva(x)){
                    auto it=direct.find(*tr);
                    if(it!=direct.end())api=it->second;
                }
                if(!api)if(auto slot=rip_indirect_slot_rva(x)){
                    auto it=iat.find(*slot);
                    if(it!=iat.end())api=it->second;
                }
                if(api&&(*api=="PyModule_Create2"||*api=="PyModuleDef_Init")){
                    auto moduledef=pointer_before(d,pe,prior,ZYDIS_REGISTER_RCX);
                    if(!moduledef){
                        last_api_error="CPython init API transfer lacks straight-line RCX moduledef provenance";
                    }else if(*api=="PyModule_Create2"){
                        auto version=scalar_before(prior,ZYDIS_REGISTER_RDX);
                        if(!version||(static_cast<std::uint32_t>(*version)!=3u&&
                                      static_cast<std::uint32_t>(*version)!=1013u)){
                            last_api_error="PyModule_Create2 transfer lacks recognized straight-line EDX API/ABI version";
                        }else return InitContract{*moduledef,static_cast<std::uint32_t>(*version),*api};
                    }else return InitContract{*moduledef,0,*api};
                    if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR){
                        error=last_api_error;return std::nullopt;
                    }
                }
            }
            if(x.ins.meta.category==ZYDIS_CATEGORY_CALL){
                // Win64 calls may clobber RCX/RDX/R8/R9 and volatile temporaries.  A later
                // init transfer must establish fresh argument provenance after the call.
                prior.clear();cur=next;continue;
            }
            if(x.ins.meta.category==ZYDIS_CATEGORY_COND_BR){
                if(auto tr=direct_target_rva(x);tr&&*tr>cur)enqueue(*tr,prior);
                enqueue(next,prior);
                break;
            }
            if(x.ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR){
                if(auto tr=direct_target_rva(x);tr&&*tr>cur&&std::uint64_t(*tr)<max_rva){
                    enqueue(*tr,prior);
                }else if(!api){
                    last_api_error="module-init flow leaves bounded function before a validated CPython init API transfer";
                }
                break;
            }
            if(x.ins.meta.category==ZYDIS_CATEGORY_RET||
               x.ins.meta.category==ZYDIS_CATEGORY_INTERRUPT||
               x.ins.meta.category==ZYDIS_CATEGORY_SYSTEM)break;
            prior.push_back(x);
            if(prior.size()>kMaxBackwardInstructions)
                prior.erase(prior.begin(),prior.begin()+(prior.size()-kMaxBackwardInstructions));
            cur=next;
        }
    }
    error=!last_api_error.empty()?last_api_error:
          "no bounded PyModule_Create2/PyModuleDef_Init transfer with argument provenance";
    return std::nullopt;
}

bool validate_callback(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint64_t va,
                       std::string_view field,std::string&error){
    if(!va)return true;
    auto rva=va_image_rva(pe,va);
    if(!rva||!exec_file_rva(pe,*rva,d.size())){
        error=std::string(field)+" is not a file-backed executable current-image pointer";
        return false;
    }
    return true;
}

bool parse_methods(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint64_t methods_va,
                   CPythonExtensionModule&out,std::string&error){
    if(!methods_va){out.methods_state="NONE";return true;}
    auto methods_rva=va_image_rva(pe,methods_va);
    if(!methods_rva){error="PyModuleDef.m_methods is not a current-image pointer";return false;}
    out.methods_rva=*methods_rva;
    if(!rva_off(pe,*methods_rva,d.size())){
        out.methods_state="UNAVAILABLE_NON_FILE_BACKED";out.state="PARTIAL";return true;
    }
    bool terminated=false;
    for(std::size_t i=0;i<kMaxMethods;++i){
        const auto rr=std::uint64_t(*methods_rva)+i*32ull;
        if(rr>0xffffffffull){error="PyMethodDef table RVA overflow";return false;}
        const auto record_rva=static_cast<std::uint32_t>(rr);
        std::uint64_t method_name_va=0,callback_va=0,method_doc_va=0;std::uint32_t flags=0;
        if(!read_rva(d,pe,record_rva,method_name_va)||!read_rva(d,pe,record_rva+8,callback_va)||
           !read_rva(d,pe,record_rva+16,flags)||!read_rva(d,pe,record_rva+24,method_doc_va)){
            error="truncated PyMethodDef table";return false;
        }
        if(!method_name_va){
            terminated=true;break;
        }
        auto method_name_rva=va_file_rva(pe,method_name_va,d.size());
        auto callback_rva=va_image_rva(pe,callback_va);
        if(!method_name_rva||!callback_rva||!exec_file_rva(pe,*callback_rva,d.size())){
            error="PyMethodDef name/callback pointer is invalid";return false;
        }
        auto method_name=cstr(d,pe,*method_name_rva,kMaxName,CStrKind::Name);
        if(!method_name||method_name->empty()){
            error="PyMethodDef.ml_name is not a bounded non-empty C string";return false;
        }
        if(!valid_module_method_flags(flags)){
            error="PyMethodDef.ml_flags is not a supported module-function calling convention";return false;
        }
        CPythonExtensionMethod m;
        m.name=*method_name;m.flags=flags;m.record_rva=record_rva;
        m.name_rva=*method_name_rva;m.callback_rva=*callback_rva;
        if(method_doc_va){
            auto doc_rva=va_file_rva(pe,method_doc_va,d.size());
            if(!doc_rva){error="PyMethodDef.ml_doc is not a file-backed current-image pointer";return false;}
            auto doc=cstr(d,pe,*doc_rva,kMaxDoc,CStrKind::Doc);
            if(!doc){error="PyMethodDef.ml_doc is not a bounded C string";return false;}
            m.doc=*doc;m.doc_rva=*doc_rva;
        }
        out.methods.push_back(std::move(m));
    }
    if(!terminated){error="PyMethodDef table exceeds bounded record limit";return false;}
    out.methods_state="CONFIRMED";
    return true;
}

bool parse_slots(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint64_t slots_va,
                 CPythonExtensionModule&out,std::string&error){
    if(!slots_va){out.slots_state="NONE";return true;}
    auto slots_rva=va_image_rva(pe,slots_va);
    if(!slots_rva){error="PyModuleDef.m_slots is not a current-image pointer";return false;}
    out.slots_rva=*slots_rva;
    if(!rva_off(pe,*slots_rva,d.size())){
        out.slots_state="UNAVAILABLE_NON_FILE_BACKED";out.state="PARTIAL";return true;
    }
    bool terminated=false,unsupported=false;
    for(std::size_t i=0;i<kMaxSlots;++i){
        const auto rr=std::uint64_t(*slots_rva)+i*16ull;
        if(rr>0xffffffffull){error="PyModuleDef_Slot table RVA overflow";return false;}
        const auto record_rva=static_cast<std::uint32_t>(rr);
        std::int32_t slot=0;std::uint64_t value=0;
        if(!read_rva(d,pe,record_rva,slot)||!read_rva(d,pe,record_rva+8,value)){
            error="truncated PyModuleDef_Slot table";return false;
        }
        if(slot==0){
            if(value){error="malformed PyModuleDef_Slot terminator";return false;}
            terminated=true;break;
        }
        if(slot<0){error="negative PyModuleDef slot id";return false;}
        CPythonExtensionSlot s;s.slot=slot;s.record_rva=record_rva;s.raw_value=value;
        if(slot==1||slot==2){
            auto vr=va_image_rva(pe,value);
            if(!vr||!exec_file_rva(pe,*vr,d.size())){
                error="Py_mod_create/Py_mod_exec slot is not a file-backed executable current-image pointer";
                return false;
            }
            s.value_rva=*vr;s.value_kind="CALLBACK_RVA";
        }else if(slot==3){
            if(value>2){error="Py_mod_multiple_interpreters value is outside the supported enum";return false;}
            s.value_kind="ENUM_VALUE";
        }else if(slot==4){
            if(value>1){error="Py_mod_gil value is outside the supported enum";return false;}
            s.value_kind="ENUM_VALUE";
        }else{
            s.value_kind="RAW_UNSUPPORTED";unsupported=true;
        }
        out.slots.push_back(std::move(s));
    }
    if(!terminated){error="PyModuleDef_Slot table exceeds bounded record limit";return false;}
    if(unsupported){out.slots_state="UNSUPPORTED_SLOT";out.state="PARTIAL";}
    else out.slots_state="CONFIRMED";
    return true;
}

std::optional<CPythonExtensionModule> parse_module(std::span<const std::uint8_t>d,const PeInfo&pe,
                                                   std::string export_name,std::string registration_source,
                                                   std::string registration_name,std::uint32_t init_rva,
                                                   const InitContract&ic,std::string&error){
    CPythonExtensionModule out;
    out.export_name=std::move(export_name);
    out.registration_source=std::move(registration_source);
    out.registration_name=std::move(registration_name);
    out.init_rva=init_rva;out.moduledef_rva=ic.moduledef_rva;
    out.api_version=ic.api_version;out.init_api=ic.api;out.state="CONFIRMED";
    if(out.registration_name.empty()){
        error="empty CPython module registration name";return std::nullopt;
    }
    auto moduledef_off=rva_off(pe,ic.moduledef_rva,d.size());
    if(!moduledef_off||exec_rva(pe,ic.moduledef_rva)){
        error="moduledef is not file-backed non-executable current-image data";return std::nullopt;
    }
    std::uint64_t name_va=0,doc_va=0,methods_va=0,slots_va=0,traverse_va=0,clear_va=0,free_va=0;
    std::int64_t module_size=0;
    if(!read_rva(d,pe,ic.moduledef_rva+0x28,name_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x30,doc_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x38,module_size)||
       !read_rva(d,pe,ic.moduledef_rva+0x40,methods_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x48,slots_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x50,traverse_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x58,clear_va)||
       !read_rva(d,pe,ic.moduledef_rva+0x60,free_va)){
        error="truncated PyModuleDef";return std::nullopt;
    }
    auto name_rva=va_file_rva(pe,name_va,d.size());
    if(!name_rva){error="PyModuleDef.m_name is not a file-backed current-image pointer";return std::nullopt;}
    auto name=cstr(d,pe,*name_rva,kMaxName,CStrKind::Name);
    if(!name||name->empty()){
        error="PyModuleDef.m_name is not a bounded non-empty C string";return std::nullopt;
    }
    out.module_name=*name;
    out.name_relation=out.module_name==out.registration_name?"EXACT":"ALIAS";
    out.module_size=module_size;
    if(module_size < -1 || module_size > (1ll<<30)){
        error="PyModuleDef.m_size is unreasonable";return std::nullopt;
    }
    if(doc_va){
        auto doc_rva=va_file_rva(pe,doc_va,d.size());
        if(!doc_rva){error="PyModuleDef.m_doc is not a file-backed current-image pointer";return std::nullopt;}
        auto doc=cstr(d,pe,*doc_rva,kMaxDoc,CStrKind::Doc);
        if(!doc){error="PyModuleDef.m_doc is not a bounded C string";return std::nullopt;}
        out.doc=*doc;
    }
    if(!validate_callback(d,pe,traverse_va,"PyModuleDef.m_traverse",error)||
       !validate_callback(d,pe,clear_va,"PyModuleDef.m_clear",error)||
       !validate_callback(d,pe,free_va,"PyModuleDef.m_free",error))return std::nullopt;
    if(ic.api=="PyModule_Create2"&&slots_va){
        error="single-phase PyModule_Create2 module has non-null m_slots";return std::nullopt;
    }
    if(slots_va&&module_size<0){
        error="multi-phase PyModuleDef has negative m_size";return std::nullopt;
    }
    if(!parse_methods(d,pe,methods_va,out,error)||!parse_slots(d,pe,slots_va,out,error))
        return std::nullopt;
    return out;
}
}

CPythonExtensionInfo analyze_cpython_extension(std::span<const std::uint8_t>d,const PeInfo&pe){
    CPythonExtensionInfo out;out.inittab_state="NOT_PRESENT";
    if(!pe.valid){out.state="INVALID_PE";return out;}
    if(!pe.pe64||pe.machine!=0x8664u){out.state="UNSUPPORTED_MACHINE";return out;}

    std::map<std::uint32_t,std::string> iat,direct;
    for(const auto&mod:pe.imports){
        if(!mod.iat_rva)continue;
        for(std::size_t i=0;i<mod.functions.size();++i){
            const auto&fn=mod.functions[i];
            if(fn.by_ordinal||fn.name.empty())continue;
            const auto slot=std::uint64_t(mod.iat_rva)+i*8ull;
            if(slot<=0xffffffffull)iat[static_cast<std::uint32_t>(slot)]=fn.name;
        }
    }
    for(const auto&ex:pe.exports){
        if(ex.forwarder.empty()&&(ex.name=="PyModule_Create2"||ex.name=="PyModuleDef_Init"))
            direct[ex.rva]=ex.name;
    }

    for(const auto&ex:pe.exports){
        if(ex.name.rfind("PyInit_",0)!=0)continue;
        ++out.pyinit_export_count;
        if(!ex.forwarder.empty()){
            out.rejected.push_back({ex.name,ex.rva,"forwarded PyInit export"});continue;
        }
        if(!exec_file_rva(pe,ex.rva,d.size())){
            out.rejected.push_back({ex.name,ex.rva,"PyInit export is not file-backed executable code"});continue;
        }
        const auto registration_name=expected_module_name(ex.name);
        if(registration_name.empty()){
            out.rejected.push_back({ex.name,ex.rva,"unsupported or malformed PyInit export name"});continue;
        }
        std::string error;
        auto ic=find_init_contract(d,pe,ex.rva,iat,direct,error);
        if(!ic){out.rejected.push_back({ex.name,ex.rva,std::move(error)});continue;}
        auto mod=parse_module(d,pe,ex.name,"PyInit_export",registration_name,ex.rva,*ic,error);
        if(!mod){out.rejected.push_back({ex.name,ex.rva,std::move(error)});continue;}
        out.modules.push_back(std::move(*mod));
    }

    auto ix=std::find_if(pe.exports.begin(),pe.exports.end(),
                         [](const PeExport&e){return e.name=="PyImport_Inittab";});
    if(ix!=pe.exports.end()&&ix->forwarder.empty()){
        out.inittab_export_rva=ix->rva;
        std::uint64_t table_va=0;
        if(!read_rva(d,pe,ix->rva,table_va)){
            out.inittab_state="REJECTED";
        }else if(auto table_rva=va_image_rva(pe,table_va);
                 table_rva&&rva_off(pe,*table_rva,d.size())){
            out.inittab_table_rva=*table_rva;
            bool terminated=false,malformed=false;
            for(std::size_t i=0;i<kMaxInittab;++i){
                const auto rr=std::uint64_t(*table_rva)+i*16ull;
                if(rr>0xffffffffull){malformed=true;break;}
                const auto record_rva=static_cast<std::uint32_t>(rr);
                std::uint64_t name_va=0,init_va=0;
                if(!read_rva(d,pe,record_rva,name_va)||
                   !read_rva(d,pe,record_rva+8,init_va)){malformed=true;break;}
                if(!name_va&&!init_va){terminated=true;break;}
                if(!name_va){malformed=true;break;}
                auto nr=va_file_rva(pe,name_va,d.size());
                if(!nr){malformed=true;break;}
                auto name=cstr(d,pe,*nr,kMaxName,CStrKind::Name);
                if(!name||name->empty()){malformed=true;break;}
                CPythonInittabEntry entry;
                entry.name=*name;entry.record_rva=record_rva;
                if(!init_va){
                    entry.init_is_null=true;
                    out.inittab.push_back(std::move(entry));
                    continue;
                }
                auto ir=va_image_rva(pe,init_va);
                if(!ir||!exec_file_rva(pe,*ir,d.size())){malformed=true;break;}
                entry.init_rva=*ir;
                std::string error;
                auto ic=find_init_contract(d,pe,*ir,iat,direct,error);
                if(ic){
                    auto mod=parse_module(d,pe,"","PyImport_Inittab",*name,*ir,*ic,error);
                    if(mod){entry.module_recovered=true;out.modules.push_back(std::move(*mod));}
                    else entry.reject_reason=std::move(error);
                }else entry.reject_reason=std::move(error);
                out.inittab.push_back(std::move(entry));
            }
            out.inittab_state=terminated&&!malformed?"CONFIRMED":"REJECTED";
        }else out.inittab_state="REJECTED";
    }

    const bool registration_valid=!out.modules.empty()||out.inittab_state=="CONFIRMED";
    const bool unresolved_inittab=std::any_of(out.inittab.begin(),out.inittab.end(),
        [](const CPythonInittabEntry&e){return !e.init_is_null&&!e.module_recovered;});
    const bool module_partial=std::any_of(out.modules.begin(),out.modules.end(),
        [](const CPythonExtensionModule&m){return m.state=="PARTIAL";});
    if(registration_valid){
        out.valid=true;
        out.state=(!out.rejected.empty()||unresolved_inittab||module_partial||
                   out.inittab_state=="REJECTED")?"PARTIAL":"CONFIRMED";
    }else if(out.pyinit_export_count||out.inittab_state=="REJECTED"){
        out.state="REJECTED";
    }else out.state="NO_REGISTRATION";
    return out;
}
}
