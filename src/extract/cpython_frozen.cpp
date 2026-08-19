#include "prts/cpython_frozen.hpp"
#include "prts/python_marshal.hpp"
#include "prts/sha256.hpp"
extern "C" {
#include "Zydis.h"
}
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <string_view>

namespace prts { namespace {
constexpr std::size_t kMaxFrozenTables=4;
constexpr std::size_t kMaxFrozenEntries=4096;
constexpr std::size_t kMaxFrozenName=512;
constexpr std::uint32_t kMaxFrozenBlob=64u*1024u*1024u;
constexpr std::size_t kMaxGetterBytes=128;
constexpr std::size_t kMaxGetterInstructions=48;
constexpr std::uint32_t kPy311CodeAdaptiveOffset=0xb8;
constexpr std::uint64_t kMaxPy311CodeUnits=1u<<20;

int minor_from_version(int v){return v>=300?v%100:(v>=30?v%10:v);}

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

std::optional<std::uint32_t> va_rva(const PeInfo&pe,std::uint64_t va,bool require_file,std::size_t file_size){
    if(va<pe.image_base)return std::nullopt;
    const auto x=va-pe.image_base;if(x>0xffffffffull)return std::nullopt;
    const auto rva=static_cast<std::uint32_t>(x);bool mapped=rva<pe.headers_size;
    for(const auto&s:pe.sections){const auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span){mapped=true;break;}}
    if(!mapped||(require_file&&!rva_off(pe,rva,file_size)))return std::nullopt;
    return rva;
}

template<class T> bool read_rva(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,T&out){
    auto off=rva_off(pe,rva,d.size());if(!off||*off+sizeof(T)>d.size())return false;std::memcpy(&out,d.data()+*off,sizeof(T));return true;
}

std::optional<std::string> cstr(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t rva,std::size_t limit){
    auto off=rva_off(pe,rva,d.size());if(!off)return std::nullopt;std::string out;
    for(std::size_t i=0;i<limit&&*off+i<d.size();++i){const auto c=d[*off+i];if(!c)return out;if(c<0x20u||c>=0x7fu)return std::nullopt;out.push_back(static_cast<char>(c));}
    return std::nullopt;
}

const PeExport* find_export(const PeInfo&pe,std::string_view name){
    auto it=std::find_if(pe.exports.begin(),pe.exports.end(),[&](const auto&e){return e.name==name;});return it==pe.exports.end()?nullptr:&*it;
}

std::optional<std::uint32_t> table_pointer(std::span<const std::uint8_t>d,const PeInfo&pe,const PeExport&ex){
    if(!ex.forwarder.empty()||exec_rva(pe,ex.rva))return std::nullopt;
    std::uint64_t va=0;if(!read_rva(d,pe,ex.rva,va)||!va)return std::nullopt;
    return va_rva(pe,va,true,d.size());
}

struct GetterValue {std::uint32_t object_rva=0;};
std::optional<GetterValue> py311_getter_value(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t getter_rva){
    if(!exec_file_rva(pe,getter_rva,d.size()))return std::nullopt;
    ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return std::nullopt;
    auto cur=getter_rva;const auto limit=std::uint64_t(getter_rva)+kMaxGetterBytes;std::optional<std::uint32_t>rax;
    for(std::size_t n=0;n<kMaxGetterInstructions&&std::uint64_t(cur)<limit;++n){
        auto off=rva_off(pe,cur,d.size());if(!off)return std::nullopt;const auto avail=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,d.size()-*off);
        ZydisDecodedInstruction ins{};std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT>ops{};
        if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+*off,avail,&ins,ops.data()))||!ins.length)return std::nullopt;
        if(ins.meta.category==ZYDIS_CATEGORY_CALL||ins.meta.category==ZYDIS_CATEGORY_COND_BR||
           ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR||ins.meta.category==ZYDIS_CATEGORY_INTERRUPT||ins.meta.category==ZYDIS_CATEGORY_SYSTEM)return std::nullopt;
        if(ins.mnemonic==ZYDIS_MNEMONIC_LEA&&ins.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&
           ops[0].reg.value==ZYDIS_REGISTER_RAX&&ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY&&ops[1].mem.base==ZYDIS_REGISTER_RIP&&ops[1].mem.index==ZYDIS_REGISTER_NONE){
            const auto disp=ops[1].mem.disp.has_displacement?ops[1].mem.disp.value:0;const auto t=std::int64_t(cur+ins.length)+disp;
            if(t<0||t>0xffffffffll)return std::nullopt;
            const auto r=static_cast<std::uint32_t>(t);if(!rva_off(pe,r,d.size()))return std::nullopt;rax=r;
        }else if(ins.mnemonic==ZYDIS_MNEMONIC_MOV&&ins.operand_count_visible>=2&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[0].reg.value==ZYDIS_REGISTER_RAX){
            const auto&s=ops[1];
            if(s.type==ZYDIS_OPERAND_TYPE_IMMEDIATE){auto r=va_rva(pe,s.imm.value.u,true,d.size());if(!r)return std::nullopt;rax=*r;}
            else if(s.type==ZYDIS_OPERAND_TYPE_MEMORY&&s.mem.base==ZYDIS_REGISTER_RIP&&s.mem.index==ZYDIS_REGISTER_NONE){
                const auto disp=s.mem.disp.has_displacement?s.mem.disp.value:0;const auto sr=std::int64_t(cur+ins.length)+disp;if(sr<0||sr>0xffffffffll)return std::nullopt;
                std::uint64_t va=0;if(!read_rva(d,pe,static_cast<std::uint32_t>(sr),va))return std::nullopt;auto r=va_rva(pe,va,true,d.size());if(!r)return std::nullopt;rax=*r;
            }else if(s.type!=ZYDIS_OPERAND_TYPE_REGISTER||s.reg.value!=ZYDIS_REGISTER_RAX)return std::nullopt;
        }else if(ins.operand_count_visible&&ops[0].type==ZYDIS_OPERAND_TYPE_REGISTER&&ops[0].reg.value==ZYDIS_REGISTER_RAX&&
                 (ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE))return std::nullopt;
        if(ins.meta.category==ZYDIS_CATEGORY_RET)return rax?std::optional<GetterValue>(GetterValue{*rax}):std::nullopt;
        cur=static_cast<std::uint32_t>(std::uint64_t(cur)+ins.length);
    }
    return std::nullopt;
}

bool fill_py311_deep(std::span<const std::uint8_t>d,const PeInfo&pe,std::uint32_t code_type_rva,CPythonFrozenModule&m){
    auto fail=[&](std::string e){m.state="MALFORMED";m.marshal_state="UNAVAILABLE_DEEP_FROZEN_OBJECT_GRAPH";m.error=std::move(e);return false;};
    auto gv=py311_getter_value(d,pe,m.getter_rva);if(!gv)return fail("getter does not yield a bounded deterministic static object");
    const auto obj=gv->object_rva;if(exec_rva(pe,obj))return fail("getter result is executable, not a static PyCodeObject");
    std::uint64_t type_va=0;std::int64_t units=0;if(!read_rva(d,pe,obj+8,type_va)||!read_rva(d,pe,obj+16,units))return fail("static PyCodeObject header is truncated");
    auto tr=va_rva(pe,type_va,true,d.size());if(!tr||*tr!=code_type_rva)return fail("getter result ob_type is not PyCode_Type");
    if(units<0||std::uint64_t(units)>kMaxPy311CodeUnits)return fail("static PyCodeObject Py_SIZE is out of bounds");
    const auto bytes=std::uint64_t(units)*2ull;const auto ar=std::uint64_t(obj)+kPy311CodeAdaptiveOffset;
    if(ar>0xffffffffull||bytes>0xffffffffull)return fail("adaptive code range overflows RVA");
    const auto adaptive=static_cast<std::uint32_t>(ar);auto ao=rva_off(pe,adaptive,d.size());
    if(!ao||bytes>d.size()-*ao)return fail("adaptive code range is not file-backed");
    m.state="DEEP_FROZEN_STATIC_CODE_OBJECT";m.marshal_state="UNAVAILABLE_DEEP_FROZEN_OBJECT_GRAPH";m.reference_state="UNAVAILABLE_DEEP_FROZEN_OBJECT_GRAPH";
    m.code_object_rva=obj;m.adaptive_code_rva=adaptive;m.adaptive_code_file_offset=*ao;m.adaptive_code_size=static_cast<std::uint32_t>(bytes);return true;
}

bool fill_raw(std::span<const std::uint8_t>d,const PeInfo&pe,int minor,std::uint64_t code_va,std::int64_t raw_size,CPythonFrozenModule&m){
    auto fail=[&](std::string e){m.state="MALFORMED";m.marshal_state="PARSE_FAILED";m.error=std::move(e);return false;};
    if(raw_size<=0||std::uint64_t(raw_size)>kMaxFrozenBlob)return fail("raw frozen size is out of bounds");
    auto cr=va_rva(pe,code_va,true,d.size());if(!cr)return fail("raw frozen code pointer is not current-image file-backed data");
    auto co=rva_off(pe,*cr,d.size());if(!co||std::uint64_t(raw_size)>d.size()-*co)return fail("raw frozen blob exceeds file-backed bytes");
    const auto size=static_cast<std::uint32_t>(raw_size);auto sem=semantic_hash_python_marshal(d.subspan(*co,size),300+minor);
    m.raw_code_rva=*cr;m.raw_code_file_offset=*co;m.raw_code_size=size;m.raw_sha256=sha256_bytes(d.subspan(*co,size));m.reference_state="NOT_CHECKED";
    if(!sem.valid){m.state="MALFORMED";m.marshal_state="PARSE_FAILED";m.error="marshal parse failed at +0x"+[] (std::uint64_t v){static const char*h="0123456789abcdef";std::string s;if(!v)return std::string("0");while(v){s.insert(s.begin(),h[v&15]);v>>=4;}return s;}(sem.error_offset)+": "+sem.error;return false;}
    m.state="RAW_MARSHAL";m.marshal_state="CONFIRMED";m.semantic_sha256=sem.sha256;m.marshal_object_count=sem.object_count;m.marshal_code_object_count=sem.code_object_count;
    for(const auto&r:sem.code_ranges){
        if(r.offset>size||r.size>size-r.offset){m.state="MALFORMED";m.marshal_state="PARSE_FAILED";m.error="marshal code range exceeds frozen blob";return false;}
        const auto file=std::uint64_t(*co)+r.offset;const auto rr=std::uint64_t(*cr)+r.offset;if(rr>0xffffffffull){m.state="MALFORMED";m.error="marshal code range RVA overflow";return false;}
        m.code_ranges.push_back({r.offset,file,static_cast<std::uint32_t>(rr),r.size,r.name,r.filename,r.qualname,r.first_line});
    }
    return true;
}

CPythonFrozenTable parse_table(std::span<const std::uint8_t>d,const PeInfo&pe,int minor,const PeExport&ex,std::uint32_t code_type_rva){
    CPythonFrozenTable out;out.export_name=ex.name;out.export_rva=ex.rva;out.record_size=(minor>=11&&minor<=12)?32u:24u;
    auto tr=table_pointer(d,pe,ex);if(!tr){out.state="REJECTED";out.error="frozen export is not a file-backed pointer to a table";return out;}out.table_rva=*tr;
    bool terminated=false,partial=false;
    for(std::size_t i=0;i<kMaxFrozenEntries;++i){
        const auto rr=std::uint64_t(*tr)+i*out.record_size;if(rr>0xffffffffull){out.state="REJECTED";out.error="frozen table RVA overflow";return out;}
        const auto record=static_cast<std::uint32_t>(rr);std::uint64_t name_va=0,code_va=0;if(!read_rva(d,pe,record,name_va)||!read_rva(d,pe,record+8,code_va)){out.state="REJECTED";out.error="frozen table is truncated";return out;}
        std::int32_t size=0,is_package=0;std::uint64_t getter_va=0;
        if(!read_rva(d,pe,record+16,size)){out.state="REJECTED";out.error="frozen size field is truncated";return out;}
        if(minor>=11){if(!read_rva(d,pe,record+20,is_package)){out.state="REJECTED";out.error="frozen package field is truncated";return out;}}
        if(minor>=11&&minor<=12)if(!read_rva(d,pe,record+24,getter_va)){out.state="REJECTED";out.error="frozen getter field is truncated";return out;}
        if(!name_va){
            const bool bad=code_va||size||is_package||getter_va;if(bad){out.state="REJECTED";out.error="malformed frozen table terminator";return out;}terminated=true;break;
        }
        auto nr=va_rva(pe,name_va,true,d.size());auto name=nr?cstr(d,pe,*nr,kMaxFrozenName):std::nullopt;if(!nr||!name||name->empty()){out.state="REJECTED";out.error="frozen module name pointer/string is invalid";return out;}
        CPythonFrozenModule m;m.table=ex.name;m.name=*name;m.record_rva=record;m.name_rva=*nr;
        if(minor<=10){
            if(size==std::numeric_limits<std::int32_t>::min()){m.state="MALFORMED";m.error="legacy frozen size is INT_MIN";partial=true;}
            else{m.is_package=size<0;const auto n=size<0?-std::int64_t(size):std::int64_t(size);if(!fill_raw(d,pe,minor,code_va,n,m))partial=true;}
        }else{
            if(is_package!=0&&is_package!=1){m.state="MALFORMED";m.error="frozen is_package is not boolean";partial=true;}
            else{m.is_package=is_package!=0;
                if(getter_va){auto gr=va_rva(pe,getter_va,true,d.size());if(!gr||!exec_file_rva(pe,*gr,d.size())){m.state="MALFORMED";m.error="frozen getter is not file-backed executable current-image code";partial=true;}else m.getter_rva=*gr;}
                if(!partial||m.state.empty()){
                    if(code_va||size){if(!code_va||size<=0){m.state="MALFORMED";m.error="raw frozen code/size pair is inconsistent";partial=true;}else if(!fill_raw(d,pe,minor,code_va,size,m))partial=true;}
                    else if(minor==11&&m.getter_rva){if(!fill_py311_deep(d,pe,code_type_rva,m))partial=true;}
                    else{m.state="UNAVAILABLE";m.marshal_state="UNAVAILABLE_NO_RAW_CODE";m.reference_state="UNAVAILABLE_MODULE_NOT_RECOVERED";m.error="frozen entry has no raw marshal payload";partial=true;}
                }
            }
        }
        out.modules.push_back(std::move(m));
    }
    if(!terminated){out.state="REJECTED";out.error="frozen table exceeds bounded entry limit";return out;}
    out.state=partial?"PARTIAL":"CONFIRMED";return out;
}
}

CPythonFrozenInfo analyze_cpython_frozen(std::span<const std::uint8_t>d,const PeInfo&pe,int version){
    CPythonFrozenInfo out;out.python_minor=minor_from_version(version);
    if(!pe.valid||!pe.pe64||pe.machine!=0x8664u){out.state="NO_FROZEN_EXPORTS";out.error="x64 PE required";return out;}
    if(out.python_minor<8||out.python_minor>14){out.state="REJECTED";out.error="frozen parser supports Python 3.8-3.14";return out;}
    std::vector<const PeExport*>exports;
    auto add=[&](std::string_view n){if(auto*e=find_export(pe,n))exports.push_back(e);};
    if(out.python_minor<=10)add("PyImport_FrozenModules");
    else{
        add("_PyImport_FrozenBootstrap");add("_PyImport_FrozenStdlib");add("_PyImport_FrozenTest");
        if(auto*custom=find_export(pe,"PyImport_FrozenModules")){std::uint64_t va=0;if(read_rva(d,pe,custom->rva,va)&&va)exports.push_back(custom);}
    }
    if(exports.empty()){out.state="NO_FROZEN_EXPORTS";return out;}
    if(exports.size()>kMaxFrozenTables){out.state="REJECTED";out.error="too many frozen table exports";return out;}
    std::uint32_t code_type_rva=0;if(out.python_minor==11){auto*ct=find_export(pe,"PyCode_Type");if(!ct||!ct->forwarder.empty()||exec_rva(pe,ct->rva)||!rva_off(pe,ct->rva,d.size())){out.state="REJECTED";out.error="Python 3.11 PyCode_Type export unavailable";return out;}code_type_rva=ct->rva;}
    bool any=false,rejected=false,partial=false;
    std::set<std::uint32_t>seen_tables;
    for(auto*ex:exports){auto t=parse_table(d,pe,out.python_minor,*ex,code_type_rva);if(t.table_rva&&!seen_tables.insert(t.table_rva).second)continue;if(t.state=="REJECTED")rejected=true;else{any=true;if(t.state=="PARTIAL")partial=true;}
        for(const auto&m:t.modules){if(m.state=="RAW_MARSHAL")++out.raw_module_count;else if(m.state=="DEEP_FROZEN_STATIC_CODE_OBJECT")++out.deep_frozen_module_count;else ++out.unavailable_module_count;}out.tables.push_back(std::move(t));}
    if(!any){out.state=rejected?"REJECTED":"NO_FROZEN_EXPORTS";return out;}
    out.valid=true;out.state=(rejected||partial)?"PARTIAL":"CONFIRMED";return out;
}
}
