#include "prts/macho.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <set>
#include <sstream>
#include <tuple>
#include <vector>

namespace prts {
void analyze_macho_swift(std::span<const std::uint8_t>,std::uint64_t,MachOSlice&);
namespace {
template<class T>T swapv(T v){T o=0;for(std::size_t i=0;i<sizeof(T);++i){o=static_cast<T>((o<<8)|(v&0xff));v=static_cast<T>(v>>8);}return o;}
template<class T>bool rd(std::span<const std::uint8_t>d,std::size_t o,bool le,T&v){if(o>d.size()||sizeof(T)>d.size()-o)return false;std::memcpy(&v,d.data()+o,sizeof(T));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
 if(!le)v=swapv(v);
#else
 if(le)v=swapv(v);
#endif
 return true;}
double ent(std::span<const std::uint8_t>d){if(d.empty())return 0;std::array<std::size_t,256>c{};for(auto b:d)++c[b];double e=0;for(auto x:c)if(x){double q=double(x)/double(d.size());e-=q*std::log2(q);}return e;}
std::string name16(std::span<const std::uint8_t>d,std::size_t o){if(o+16>d.size())return{};std::size_t n=0;while(n<16&&d[o+n])++n;return std::string(reinterpret_cast<const char*>(d.data()+o),n);}
std::string bounded_zstr(std::span<const std::uint8_t>d,std::size_t o,std::size_t end){if(o>=end||end>d.size())return{};std::size_t p=o;while(p<end&&d[p])++p;if(p==end)return{};return std::string(reinterpret_cast<const char*>(d.data()+o),p-o);}
bool zerofill_type(std::uint32_t t){return t==1||t==0xc||t==0x12;}
void unique_push(std::vector<std::uint64_t>&v,std::uint64_t x){if(x&&std::find(v.begin(),v.end(),x)==v.end())v.push_back(x);}
std::string uuid_text(std::span<const std::uint8_t>d,std::size_t o){if(o+16>d.size())return{};std::ostringstream s;s<<std::hex<<std::setfill('0');for(int i=0;i<16;i++){if(i==4||i==6||i==8||i==10)s<<'-';s<<std::setw(2)<<unsigned(d[o+i]);}return s.str();}
struct Seg {std::string name;std::uint64_t vmaddr=0,vmsize=0,fileoff=0,filesize=0;};
struct SymtabCmd {bool present=false;std::uint32_t symoff=0,nsyms=0,stroff=0,strsize=0;};
struct LinkeditCmd {bool present=false;std::uint32_t off=0,size=0;};

bool map_file_va(const std::vector<Seg>&segs,std::uint64_t va,std::uint64_t base,std::uint64_t&off){
    for(const auto&s:segs){if(va<s.vmaddr)continue;auto delta=va-s.vmaddr;if(delta>=s.filesize)continue;if(s.fileoff>UINT64_MAX-delta||base>UINT64_MAX-s.fileoff-delta)return false;off=base+s.fileoff+delta;return true;}return false;
}
bool parse_symtab(std::span<const std::uint8_t>d,bool le,bool is64,const SymtabCmd&c,MachOSlice&out,std::string&err){
    if(!c.present)return true;
    const std::size_t es=is64?16:12;
    if(c.nsyms>1000000){err="LC_SYMTAB symbol count unreasonable";return false;}
    const auto symbytes=std::uint64_t(c.nsyms)*es;
    if(c.symoff>d.size()||symbytes>d.size()-c.symoff){err="LC_SYMTAB symbol table exceeds slice";return false;}
    if(c.stroff>d.size()||c.strsize>d.size()-c.stroff){err="LC_SYMTAB string table exceeds slice";return false;}
    out.symbols.clear();out.symbols.reserve(std::min<std::uint32_t>(c.nsyms,65536));
    for(std::uint32_t i=0;i<c.nsyms;++i){
        const auto o=std::size_t(c.symoff)+std::size_t(i)*es;
        std::uint32_t strx=0;std::uint16_t desc=0;std::uint64_t value=0;
        if(!rd(d,o,le,strx)||!rd(d,o+6,le,desc)){err="LC_SYMTAB entry truncated";return false;}
        const auto type=d[o+4],sect=d[o+5];
        if(is64){if(!rd(d,o+8,le,value)){err="LC_SYMTAB nlist_64 value truncated";return false;}}
        else{std::uint32_t v=0;if(!rd(d,o+8,le,v)){err="LC_SYMTAB nlist value truncated";return false;}value=v;}
        std::string name;
        if(strx){
            if(strx>=c.strsize){err="LC_SYMTAB string index out of bounds";return false;}
            const auto no=std::size_t(c.stroff)+strx,end=std::size_t(c.stroff)+c.strsize;
            auto z=std::find(d.begin()+static_cast<std::ptrdiff_t>(no),d.begin()+static_cast<std::ptrdiff_t>(end),std::uint8_t(0));
            if(z==d.begin()+static_cast<std::ptrdiff_t>(end)){err="LC_SYMTAB symbol name is not NUL-terminated";return false;}
            name.assign(reinterpret_cast<const char*>(d.data()+no),static_cast<std::size_t>(z-(d.begin()+static_cast<std::ptrdiff_t>(no))));
        }
        if(type&0xe0)continue;
        const auto kind=type&0x0e;
        if(kind==0x0e&&(!sect||sect>out.sections.size())){err="LC_SYMTAB N_SECT ordinal out of bounds";return false;}
        if(kind==0x0a&&value>=c.strsize){err="LC_SYMTAB N_INDR target string index out of bounds";return false;}
        if(name.empty())continue;
        MachOSymbol x;x.name=std::move(name);x.value=value;x.desc=desc;x.type=type;x.section=sect;x.external=type&1;x.private_external=type&0x10;x.defined=kind==0x0e;
        if(x.defined){const auto&sec=out.sections[sect-1];const auto st=sec.flags&0xff;if(!zerofill_type(st)&&value>=sec.address&&value-sec.address<sec.size)x.file_offset=sec.offset+(value-sec.address);}
        out.symbols.push_back(std::move(x));
    }
    return true;
}
bool read_uleb(std::span<const std::uint8_t>d,std::size_t&p,std::uint64_t&v){
    v=0;unsigned shift=0;
    for(unsigned i=0;i<10;++i){
        if(p>=d.size())return false;
        const auto b=d[p++];
        const auto part=std::uint64_t(b&0x7f);
        if(shift==63&&part>1)return false;
        v|=part<<shift;
        if(!(b&0x80))return true;
        shift+=7;
    }
    return false;
}
bool parse_function_starts(std::span<const std::uint8_t>d,const std::vector<Seg>&segs,std::uint64_t base,const LinkeditCmd&c,MachOSlice&out,std::string&err){
    if(!c.present)return true;
    if(c.off>d.size()||c.size>d.size()-c.off){err="LC_FUNCTION_STARTS data exceeds slice";return false;}
    if(!c.size)return true;
    auto ti=std::find_if(segs.begin(),segs.end(),[](const Seg&s){return s.name=="__TEXT";});
    if(ti==segs.end()){err="LC_FUNCTION_STARTS present without __TEXT segment";return false;}
    auto bytes=d.subspan(c.off,c.size);std::size_t p=0;std::uint64_t rel=0;bool terminated=false;out.function_starts.clear();
    while(p<bytes.size()){
        std::uint64_t delta=0;if(!read_uleb(bytes,p,delta)){err="LC_FUNCTION_STARTS malformed/truncated ULEB128";return false;}
        if(!delta){terminated=true;break;}
        if(rel>UINT64_MAX-delta||ti->vmaddr>UINT64_MAX-(rel+delta)){err="LC_FUNCTION_STARTS address overflow";return false;}
        rel+=delta;const auto va=ti->vmaddr+rel;std::uint64_t off=0;
        if(!map_file_va(segs,va,base,off)){err="LC_FUNCTION_STARTS function address is not file-backed";return false;}
        out.function_starts.push_back({va,off,{}});if(out.function_starts.size()>1000000){err="LC_FUNCTION_STARTS function count unreasonable";return false;}
    }
    if(!terminated){err="LC_FUNCTION_STARTS missing zero terminator";return false;}
    for(;p<bytes.size();++p)if(bytes[p]){err="LC_FUNCTION_STARTS non-zero bytes after terminator";return false;}
    return true;
}
void attach_function_names(MachOSlice&out){
    for(auto&f:out.function_starts){
        const MachOSymbol*best=nullptr;
        for(const auto&s:out.symbols){if(!s.defined||s.value!=f.address)continue;if(!best||(s.external&&!best->external))best=&s;}
        if(best)f.symbol=best->name;
    }
}

MachOSlice parse_thin(std::span<const std::uint8_t>d,std::uint64_t absolute_base){
    MachOSlice out;out.slice_offset=absolute_base;out.slice_size=d.size();
    if(d.size()<4){out.error="Mach-O header too small";return out;}
    bool le=false,is64=false;
    if(d[0]==0xce&&d[1]==0xfa&&d[2]==0xed&&d[3]==0xfe){le=true;is64=false;}
    else if(d[0]==0xcf&&d[1]==0xfa&&d[2]==0xed&&d[3]==0xfe){le=true;is64=true;}
    else if(d[0]==0xfe&&d[1]==0xed&&d[2]==0xfa&&d[3]==0xce){le=false;is64=false;}
    else if(d[0]==0xfe&&d[1]==0xed&&d[2]==0xfa&&d[3]==0xcf){le=false;is64=true;}
    else{out.error="not Mach-O";return out;}
    out.little_endian=le;out.macho64=is64;const std::size_t hs=is64?32:28;
    if(d.size()<hs){out.error="Mach-O header truncated";return out;}
    std::uint32_t cpu=0,sub=0,ncmds=0,cmdbytes=0;if(!rd(d,4,le,cpu)||!rd(d,8,le,sub)||!rd(d,12,le,out.filetype)||!rd(d,16,le,ncmds)||!rd(d,20,le,cmdbytes)||!rd(d,24,le,out.flags)){out.error="Mach-O header read failed";return out;}out.cpu_type=static_cast<std::int32_t>(cpu);out.cpu_subtype=static_cast<std::int32_t>(sub);
    out.cpu_subtype_base=sub&0x00ffffffu;
    out.arm64e=cpu==0x0100000cu&&out.cpu_subtype_base==2u;
    out.ptrauth_versioned=out.arm64e&&(sub&0x80000000u);
    out.ptrauth_kernel=out.arm64e&&(sub&0x40000000u);
    out.ptrauth_abi_version=out.arm64e?((sub&0x0f000000u)>>24):0u;
    out.architecture=macho_architecture_name(out.cpu_type,out.cpu_subtype);
    out.load_command_count=ncmds;
    out.load_commands.reserve(std::min<std::uint32_t>(ncmds,4096));
    if(ncmds>65536){out.error="Mach-O load-command count unreasonable";return out;}if(cmdbytes>d.size()-hs){out.error="Mach-O load-command table exceeds slice";return out;}
    std::size_t p=hs,cmd_end=hs+cmdbytes;std::vector<Seg>segs;bool have_build=false;SymtabCmd symtab;LinkeditCmd function_starts;
    for(std::uint32_t ci=0;ci<ncmds;++ci){
        std::uint32_t cmd=0,sz=0;if(p+8>cmd_end||!rd(d,p,le,cmd)||!rd(d,p+4,le,sz)){out.error="Mach-O load command truncated";return out;}if(sz<8||sz>cmd_end-p){out.error="Mach-O load command size invalid";return out;}if(sz%(is64?8u:4u)){out.error="Mach-O load command alignment invalid";return out;}const auto basecmd=cmd&0x7fffffffU;
        const auto command_name=macho_load_command_name(cmd);
        MachOLoadCommand command_record{command_name.empty()?"UNKNOWN":command_name,cmd,sz,absolute_base+p,!command_name.empty()};
        if(out.load_commands.size()<4096)out.load_commands.push_back(command_record);
        else out.load_commands_truncated=true;
        if(command_name.empty()){
            ++out.unknown_load_command_count;
            if(out.unknown_load_commands.size()<1024)out.unknown_load_commands.push_back(command_record);
            else out.unknown_load_commands_truncated=true;
            out.load_command_coverage_state="PARTIAL_UNKNOWN_COMMAND";
            out.coverage_state="PARTIAL";
            if(out.coverage_reasons.empty())out.coverage_reasons.push_back("unknown load command inventory is not semantically covered");
        }
        if(out.load_commands_truncated&&out.load_command_coverage_state=="COMPLETE")out.load_command_coverage_state="PARTIAL_RETENTION_BUDGET";
        if(out.load_commands_truncated){out.coverage_state="PARTIAL";if(std::find(out.coverage_reasons.begin(),out.coverage_reasons.end(),"load-command retention budget exceeded")==out.coverage_reasons.end())out.coverage_reasons.push_back("load-command retention budget exceeded");}
        if(cmd==1&&!is64){
            if(sz<56){out.error="LC_SEGMENT too small";return out;}std::uint32_t vm=0,vms=0,fo=0,fs=0,ns=0;rd(d,p+24,le,vm);rd(d,p+28,le,vms);rd(d,p+32,le,fo);rd(d,p+36,le,fs);rd(d,p+48,le,ns);if(ns>65536||std::uint64_t(56)+std::uint64_t(ns)*68>sz){out.error="LC_SEGMENT section table invalid";return out;}if(fo>d.size()||fs>d.size()-fo){out.error="LC_SEGMENT file range exceeds slice";return out;}segs.push_back({name16(d,p+8),vm,vms,fo,fs});
            for(std::uint32_t j=0;j<ns;++j){auto q=p+56+std::size_t(j)*68;MachOSection s;s.name=name16(d,q);s.segment=name16(d,q+16);std::uint32_t a=0,z=0,off=0;rd(d,q+32,le,a);rd(d,q+36,le,z);rd(d,q+40,le,off);rd(d,q+56,le,s.flags);s.address=a;s.size=z;auto t=s.flags&0xff;s.offset=zerofill_type(t)?0:absolute_base+off;if(!zerofill_type(t)){if(off>d.size()||s.size>d.size()-off){out.error="Mach-O section file range exceeds slice";return out;}auto b=d.subspan(off,static_cast<std::size_t>(s.size));s.entropy=ent(b);auto used=b.size();while(used&&(b[used-1]==0||b[used-1]==0xcc))--used;s.used_size=used;if(t==9||t==10||t==0x15){for(std::size_t x=0;x+4<=b.size()&&x/4<4096;x+=4){std::uint32_t v=0;rd(b,x,le,v);if(t==9){unique_push(out.init_functions,v);out.initializer_slots.push_back({"S_MOD_INIT_FUNC_POINTERS",s.address+x,s.offset+x,v,0,false});}else if(t==10)unique_push(out.term_functions,v);else{unique_push(out.thread_init_functions,v);out.initializer_slots.push_back({"S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",s.address+x,s.offset+x,v,0,false});}}}}out.sections.push_back(std::move(s));}
        } else if(cmd==0x19&&is64){
            if(sz<72){out.error="LC_SEGMENT_64 too small";return out;}std::uint64_t vm=0,vms=0,fo=0,fs=0;std::uint32_t ns=0;rd(d,p+24,le,vm);rd(d,p+32,le,vms);rd(d,p+40,le,fo);rd(d,p+48,le,fs);rd(d,p+64,le,ns);if(ns>65536||std::uint64_t(72)+std::uint64_t(ns)*80>sz){out.error="LC_SEGMENT_64 section table invalid";return out;}if(fo>d.size()||fs>d.size()-fo){out.error="LC_SEGMENT_64 file range exceeds slice";return out;}segs.push_back({name16(d,p+8),vm,vms,fo,fs});
            for(std::uint32_t j=0;j<ns;++j){auto q=p+72+std::size_t(j)*80;MachOSection s;s.name=name16(d,q);s.segment=name16(d,q+16);std::uint32_t off=0;rd(d,q+32,le,s.address);rd(d,q+40,le,s.size);rd(d,q+48,le,off);rd(d,q+64,le,s.flags);auto t=s.flags&0xff;s.offset=zerofill_type(t)?0:absolute_base+off;if(!zerofill_type(t)){if(off>d.size()||s.size>d.size()-off){out.error="Mach-O section_64 file range exceeds slice";return out;}auto b=d.subspan(off,static_cast<std::size_t>(s.size));s.entropy=ent(b);auto used=b.size();while(used&&(b[used-1]==0||b[used-1]==0xcc))--used;s.used_size=used;if(t==9||t==10||t==0x15){for(std::size_t x=0;x+8<=b.size()&&x/8<4096;x+=8){std::uint64_t v=0;rd(b,x,le,v);if(t==9){unique_push(out.init_functions,v);out.initializer_slots.push_back({"S_MOD_INIT_FUNC_POINTERS",s.address+x,s.offset+x,v,0,false});}else if(t==10)unique_push(out.term_functions,v);else{unique_push(out.thread_init_functions,v);out.initializer_slots.push_back({"S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",s.address+x,s.offset+x,v,0,false});}}}}out.sections.push_back(std::move(s));}
        } else if(cmd==0x2){
            if(sz<24){out.error="LC_SYMTAB too small";return out;}if(symtab.present){out.error="duplicate LC_SYMTAB";return out;}symtab.present=true;rd(d,p+8,le,symtab.symoff);rd(d,p+12,le,symtab.nsyms);rd(d,p+16,le,symtab.stroff);rd(d,p+20,le,symtab.strsize);
        } else if(cmd==0x26){
            if(sz<16){out.error="LC_FUNCTION_STARTS too small";return out;}if(function_starts.present){out.error="duplicate LC_FUNCTION_STARTS";return out;}function_starts.present=true;rd(d,p+8,le,function_starts.off);rd(d,p+12,le,function_starts.size);
        } else if(basecmd==0x28){
            if(sz<24){out.error="LC_MAIN too small";return out;}std::uint64_t eo=0;rd(d,p+8,le,eo);if(eo>=d.size()){out.error="LC_MAIN entry offset exceeds slice";return out;}out.entry_file_offset=absolute_base+eo;
        } else if(cmd==0x11&&!is64){if(sz<40){out.error="LC_ROUTINES too small";return out;}std::uint32_t x=0;rd(d,p+8,le,x);out.routine_init_address=x;out.routine_command_file_offset=absolute_base+p+8;
        } else if(cmd==0x1a&&is64){if(sz<72){out.error="LC_ROUTINES_64 too small";return out;}rd(d,p+8,le,out.routine_init_address);out.routine_command_file_offset=absolute_base+p+8;
        } else if(basecmd==0xc||basecmd==0x18||basecmd==0x1f||basecmd==0x20||basecmd==0x23){
            if(sz<24){out.error="Mach-O dylib command too small";return out;}std::uint32_t no=0;rd(d,p+8,le,no);if(no<24||no>=sz){out.error="Mach-O dylib name offset invalid";return out;}auto n=bounded_zstr(d,p+no,p+sz);if(n.empty()){out.error="Mach-O dylib name invalid";return out;}if(std::find(out.dylibs.begin(),out.dylibs.end(),n)==out.dylibs.end())out.dylibs.push_back(std::move(n));
        } else if(cmd==0x1b){if(sz<24){out.error="LC_UUID too small";return out;}out.uuid=uuid_text(d,p+8);
        } else if(cmd==0x1d){if(sz<16){out.error="LC_CODE_SIGNATURE too small";return out;}std::uint32_t off=0,n=0;rd(d,p+8,le,off);rd(d,p+12,le,n);if(off>d.size()||n>d.size()-off){out.error="LC_CODE_SIGNATURE range exceeds slice";return out;}out.code_signature=true;out.code_signature_offset=absolute_base+off;out.code_signature_size=n;
        } else if(cmd==0x21||cmd==0x2c){const auto need=cmd==0x2c?24u:20u;if(sz<need){out.error="LC_ENCRYPTION_INFO command too small";return out;}std::uint32_t off=0,n=0,id=0;rd(d,p+8,le,off);rd(d,p+12,le,n);rd(d,p+16,le,id);if(off>d.size()||n>d.size()-off){out.error="Mach-O encrypted range exceeds slice";return out;}out.crypt_offset=absolute_base+off;out.crypt_size=n;out.cryptid=id;out.encrypted=id!=0;
        } else if(cmd==0x32){if(sz<24){out.error="LC_BUILD_VERSION too small";return out;}std::uint32_t tools=0;rd(d,p+8,le,out.platform);rd(d,p+12,le,out.min_os);rd(d,p+16,le,out.sdk);rd(d,p+20,le,tools);if(std::uint64_t(24)+std::uint64_t(tools)*8>sz){out.error="LC_BUILD_VERSION tool table invalid";return out;}have_build=true;
        } else if(!have_build&&(cmd==0x24||cmd==0x25||cmd==0x2f||cmd==0x30)){if(sz<16){out.error="Mach-O minimum-version command too small";return out;}rd(d,p+8,le,out.min_os);rd(d,p+12,le,out.sdk);out.platform=cmd==0x24?1:cmd==0x25?2:cmd==0x2f?3:4;}
        p+=sz;
    }
    if(p!=cmd_end){out.error="Mach-O load-command size total mismatch";return out;}
    if(out.entry_file_offset){auto eo=out.entry_file_offset-absolute_base;for(const auto&s:segs)if(eo>=s.fileoff&&eo<s.fileoff+s.filesize){out.entry_va=s.vmaddr+(eo-s.fileoff);break;}if(!out.entry_va){out.error="LC_MAIN entry offset is not file-backed by a segment";return out;}}
    std::string post_error;if(!parse_symtab(d,le,is64,symtab,out,post_error)){out.error=std::move(post_error);return out;}if(!parse_function_starts(d,segs,absolute_base,function_starts,out,post_error)){out.error=std::move(post_error);return out;}attach_function_names(out);
    {
        auto&im=out.implicit_exec;bool partial=false;std::string partial_error;constexpr std::size_t max_facts=65536;
    out.code_signature_state=out.code_signature?"PRESENT_UNVERIFIED":"NOT_PRESENT";
    analyze_macho_swift(d,absolute_base,out);
    if(out.swift.coverage_state=="PARTIAL"){
        out.coverage_state="PARTIAL";
        out.coverage_reasons.push_back("Swift metadata coverage is partial: "+out.swift.error);
    }
    if(out.unknown_load_commands_truncated){out.coverage_state="PARTIAL";out.coverage_reasons.push_back("unknown load-command retention budget exceeded");}
        auto add=[&](ImplicitExecutionFact f){if(im.facts.size()>=max_facts){im.analysis_limited=true;partial=true;if(partial_error.empty())partial_error="Mach-O implicit execution fact budget exceeded";return;}f.index=static_cast<std::uint32_t>(im.facts.size());if(f.priority=="HIGH")++im.high_priority_count;else if(f.priority=="REVIEW")++im.review_count;else ++im.informational_count;if(!f.anomaly_class.empty()&&f.anomaly_class!="NONE")++im.anomaly_count;if(f.evidence_state=="UNRESOLVED_RUNTIME_SEMANTICS")++im.unresolved_runtime_semantics;im.facts.push_back(std::move(f));};
        auto target_name=[&](std::uint64_t va)->std::string{for(const auto&s:out.symbols)if(s.defined&&s.value==va&&!s.name.empty())return s.name;for(const auto&f:out.function_starts)if(f.address==va&&!f.symbol.empty())return f.symbol;return{};};
        if(out.routine_init_address){std::uint64_t fo=0;out.routine_target_file_backed=map_file_va(segs,out.routine_init_address,absolute_base,fo);if(out.routine_target_file_backed)out.routine_target_file_offset=fo;ImplicitExecutionFact f;f.format="Mach-O";f.ecosystem="dyld/native";f.phase="module_load";f.trigger=is64?"LC_ROUTINES_64":"LC_ROUTINES";f.relation="implicit_callback";f.source_kind=f.trigger;f.source_file_backed=true;f.source_file_offset=out.routine_command_file_offset;f.source_size=is64?8:4;f.target_kind="function_va";f.target_va=out.routine_init_address;f.target_file_backed=out.routine_target_file_backed;f.target_file_offset=out.routine_target_file_offset;f.target_name=target_name(out.routine_init_address);f.evidence_state=out.routine_target_file_backed?"EXACT":"UNRESOLVED_RUNTIME_SEMANTICS";f.mutability="IMMUTABLE_MACHO_LOAD_COMMAND";f.execution_condition="dyld/module loader may invoke the LC_ROUTINES initialization function as part of image initialization; the function is not executed by analysis";f.priority="INFORMATIONAL";f.priority_reason="legacy Mach-O loader initialization routine is an ordinary implicit module-load surface";if(!out.routine_target_file_backed){partial=true;if(partial_error.empty())partial_error="LC_ROUTINES initializer target is not directly file-backed; chained/bound target resolution is not implemented";}add(std::move(f));}
        for(auto&x:out.initializer_slots){std::uint64_t fo=0;x.target_file_backed=x.target_address&&map_file_va(segs,x.target_address,absolute_base,fo);if(x.target_file_backed)x.target_file_offset=fo;ImplicitExecutionFact f;f.format="Mach-O";f.ecosystem="dyld/native";f.phase=x.kind=="S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"?"runtime_initialization":"module_load";f.trigger=x.kind;f.relation="implicit_callback";f.source_kind=x.kind;f.source_file_backed=true;f.source_file_offset=x.slot_file_offset;f.source_va=x.slot_address;f.source_size=is64?8:4;f.target_kind="function_va";f.target_va=x.target_address;f.target_file_backed=x.target_file_backed;f.target_file_offset=x.target_file_offset;f.target_name=target_name(x.target_address);f.evidence_state=x.target_file_backed?"EXACT":"UNRESOLVED_RUNTIME_SEMANTICS";f.mutability="LOADER_FIXUP_CONTROLLED_POINTER_SLOT";f.execution_condition=x.kind=="S_THREAD_LOCAL_INIT_FUNCTION_POINTERS"?"runtime invokes this thread-local initializer pointer under thread/TLV initialization semantics; no callback code is executed by analysis":"dyld invokes this initializer pointer during image/module initialization; no callback code is executed by analysis";f.priority="INFORMATIONAL";f.priority_reason=x.target_file_backed?"ordinary structurally resolved Mach-O initializer pointer":"initializer slot exists but its final target requires dyld fixup/bind semantics that this bounded stage does not emulate";if(!x.target_file_backed){partial=true;if(partial_error.empty())partial_error="one or more Mach-O initializer pointers require unresolved dyld fixup/bind semantics";}add(std::move(f));}
        if(im.facts.empty())im.state=partial?"PARTIAL":"NOT_PRESENT";else im.state=partial?"PARTIAL":"RESOLVED";if(partial)im.error=partial_error;
    }
    out.valid=true;return out;
}
}

MachOInfo parse_macho(std::span<const std::uint8_t>d){
    MachOInfo out;
    if(d.size()<4){out.error="not Mach-O";return out;}
    bool fat=false,fat64=false,le=false;
    if(d[0]==0xca&&d[1]==0xfe&&d[2]==0xba&&(d[3]==0xbe||d[3]==0xbf)){fat=true;fat64=d[3]==0xbf;le=false;}
    else if((d[0]==0xbe||d[0]==0xbf)&&d[1]==0xba&&d[2]==0xfe&&d[3]==0xca){fat=true;fat64=d[0]==0xbf;le=true;}
    if(!fat){
        auto slice=parse_thin(d,0);if(!slice.valid){out.error=slice.error;return out;}
        out.valid=true;out.slices.push_back(std::move(slice));return out;
    }
    out.fat=true;out.fat64=fat64;
    if(d.size()<8){out.error="Mach-O universal header truncated";return out;}
    std::uint32_t count=0;rd(d,4,le,count);
    if(!count||count>64){out.error="Mach-O universal architecture count invalid";return out;}
    const std::size_t entry_size=fat64?32:20;
    if(std::uint64_t(8)+std::uint64_t(count)*entry_size>d.size()){out.error="Mach-O universal architecture table truncated";return out;}
    const std::uint64_t table_end=8+std::uint64_t(count)*entry_size;
    std::vector<std::pair<std::uint64_t,std::uint64_t>> ranges;
    std::set<std::pair<std::uint32_t,std::uint32_t>> architectures;
    for(std::uint32_t i=0;i<count;++i){
        const auto p=8+std::size_t(i)*entry_size;
        std::uint32_t cpu=0,subtype=0,align=0,reserved=0;
        std::uint64_t offset=0,size=0;
        rd(d,p,le,cpu);rd(d,p+4,le,subtype);
        if(fat64){
            rd(d,p+8,le,offset);rd(d,p+16,le,size);rd(d,p+24,le,align);rd(d,p+28,le,reserved);
            if(reserved){out.error="Mach-O universal64 reserved field is non-zero";return out;}
        }else{
            std::uint32_t offset32=0,size32=0;rd(d,p+8,le,offset32);rd(d,p+12,le,size32);rd(d,p+16,le,align);offset=offset32;size=size32;
        }
        if(align>31){out.error="Mach-O universal slice alignment exponent invalid";return out;}
        const auto alignment=std::uint64_t(1)<<align;
        if(offset%alignment){out.error="Mach-O universal slice offset violates declared alignment";return out;}
        if(!size||offset<table_end||offset>d.size()||size>d.size()-offset){out.error="Mach-O universal slice range invalid";return out;}
        for(const auto& range:ranges)if(offset<range.second&&range.first<offset+size){out.error="Mach-O universal slices overlap";return out;}
        if(!architectures.emplace(cpu,subtype).second){out.error="Mach-O universal duplicate CPU/subtype slice";return out;}
        ranges.push_back({offset,offset+size});
        auto slice=parse_thin(d.subspan(static_cast<std::size_t>(offset),static_cast<std::size_t>(size)),offset);
        if(!slice.valid){out.error="Mach-O universal slice "+std::to_string(i)+" invalid: "+slice.error;return out;}
        if(static_cast<std::uint32_t>(slice.cpu_type)!=cpu){out.error="Mach-O universal slice CPU type mismatch";return out;}
        if(static_cast<std::uint32_t>(slice.cpu_subtype)!=subtype){out.error="Mach-O universal slice CPU subtype mismatch";return out;}
        out.slices.push_back(std::move(slice));
    }
    out.valid=true;return out;
}
MachOInfo parse_macho(const std::filesystem::path&p){std::ifstream f(p,std::ios::binary);if(!f){MachOInfo o;o.error="open failed";return o;}std::vector<std::uint8_t>d((std::istreambuf_iterator<char>(f)),{});return parse_macho(d);}
std::string macho_cpu_name(std::int32_t c){auto u=static_cast<std::uint32_t>(c);switch(u){case 7:return"x86";case 0x01000007:return"x86_64";case 12:return"ARM";case 0x0100000c:return"arm64";case 0x0200000c:return"arm64_32";case 18:return"PowerPC";case 0x01000012:return"PowerPC64";default:{std::ostringstream o;o<<"CPU_0x"<<std::hex<<u;return o.str();}}}
std::string macho_filetype_name(std::uint32_t t){switch(t){case 1:return"OBJECT";case 2:return"EXECUTE";case 3:return"FVMLIB";case 4:return"CORE";case 5:return"PRELOAD";case 6:return"DYLIB";case 7:return"DYLINKER";case 8:return"BUNDLE";case 9:return"DYLIB_STUB";case 10:return"DSYM";case 11:return"KEXT_BUNDLE";case 12:return"FILESET";default:return"MH_"+std::to_string(t);}}
std::string macho_platform_name(std::uint32_t p){switch(p){case 1:return"macOS";case 2:return"iOS";case 3:return"tvOS";case 4:return"watchOS";case 5:return"bridgeOS";case 6:return"Mac Catalyst";case 7:return"iOS Simulator";case 8:return"tvOS Simulator";case 9:return"watchOS Simulator";case 10:return"DriverKit";case 11:return"visionOS";case 12:return"visionOS Simulator";default:return p?"platform_"+std::to_string(p):"unknown";}}
std::string macho_version_string(std::uint32_t v){return std::to_string(v>>16)+"."+std::to_string((v>>8)&0xff)+"."+std::to_string(v&0xff);}
}
