#include "prts/pe.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <vector>
namespace prts { namespace {
template<class T> bool rd(std::span<const std::uint8_t>d,std::size_t o,T&v){if(o+sizeof(T)>d.size())return false;std::memcpy(&v,d.data()+o,sizeof(T));return true;}
double entropy(const std::uint8_t* p,std::size_t n){if(!n)return 0;std::array<std::size_t,256>c{};for(std::size_t i=0;i<n;i++)c[p[i]]++;double e=0;for(auto x:c)if(x){double q=double(x)/double(n);e-=q*std::log2(q);}return e;}
std::optional<std::size_t> rva_off(const PeInfo& pe,std::uint32_t rva,std::size_t file_size){if(rva<pe.headers_size&&rva<file_size)return std::size_t(rva);for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span){auto delta=std::uint64_t(rva)-s.rva;if(delta>=s.raw_size)return std::nullopt;auto o=std::uint64_t(s.raw_offset)+delta;if(o<file_size)return std::size_t(o);}}return std::nullopt;}
std::string zstr(std::span<const std::uint8_t>d,std::size_t o,std::size_t max=4096){if(o>=d.size())return{};std::string s;while(o<d.size()&&s.size()<max&&d[o]){auto c=d[o++];if(c<0x20&&c!='\t')return{};s.push_back(char(c));}return s;}
bool contains_ascii(std::span<const std::uint8_t>d,std::string_view s){return std::search(d.begin(),d.end(),s.begin(),s.end())!=d.end();}
struct Dir {std::uint32_t rva=0,size=0;};
}
PeInfo parse_pe(std::span<const std::uint8_t>d){
    PeInfo out;
    if(d.size()<0x40||d[0]!='M'||d[1]!='Z'){out.error="not MZ";return out;}
    std::uint32_t lfanew=0;if(!rd(d,0x3c,lfanew)||std::size_t(lfanew)+24>d.size()){out.error="invalid e_lfanew";return out;}
    if(std::memcmp(d.data()+lfanew,"PE\0\0",4)){out.error="missing PE signature";return out;}
    std::uint16_t nsec=0,opt=0;rd(d,lfanew+4,out.machine);rd(d,lfanew+6,nsec);rd(d,lfanew+20,opt);rd(d,lfanew+22,out.coff_characteristics);out.dll=(out.coff_characteristics&0x2000u)!=0;
    auto oo=std::size_t(lfanew)+24;if(oo+opt>d.size()){out.error="truncated optional header";return out;}
    std::uint16_t magic=0;rd(d,oo,magic);out.pe64=magic==0x20b;if(!(magic==0x10b||magic==0x20b)){out.error="unknown optional header";return out;}
    rd(d,oo+16,out.entry_rva);rd(d,oo+56,out.image_size);rd(d,oo+60,out.headers_size);rd(d,oo+68,out.subsystem);
    if(out.pe64)rd(d,oo+24,out.image_base);else{std::uint32_t ib=0;rd(d,oo+28,ib);out.image_base=ib;}
    auto so=oo+opt;if(so+std::size_t(nsec)*40>d.size()){out.error="truncated section table";return out;}
    std::uint64_t raw_end=out.headers_size;
    for(std::uint16_t i=0;i<nsec;i++){
        auto o=so+std::size_t(i)*40;PeSection s;char nm[9]{};std::memcpy(nm,d.data()+o,8);s.name=nm;
        rd(d,o+8,s.vsize);rd(d,o+12,s.rva);rd(d,o+16,s.raw_size);rd(d,o+20,s.raw_offset);rd(d,o+36,s.characteristics);
        if(std::uint64_t(s.raw_offset)+s.raw_size<=d.size()&&s.raw_size){auto*base=d.data()+s.raw_offset;s.entropy=entropy(base,s.raw_size);std::size_t used=s.raw_size;while(used&&(base[used-1]==0x00||base[used-1]==0xCC))--used;s.used_size=static_cast<std::uint32_t>(used);}
        raw_end=std::max<std::uint64_t>(raw_end,std::uint64_t(s.raw_offset)+s.raw_size);
        if(s.name.rfind(".CRT",0)==0){out.init.has_crt_section=true;out.init.crt_sections.push_back(s.name);}
        out.sections.push_back(std::move(s));
    }
    if(raw_end<d.size()){out.overlay_offset=raw_end;out.overlay_size=d.size()-raw_end;}

    const std::size_t dd = oo + (out.pe64 ? 112 : 96);
    std::uint32_t num_dirs=0; rd(d,oo+(out.pe64?108:92),num_dirs); num_dirs=std::min<std::uint32_t>(num_dirs,16);
    std::array<Dir,16> dirs{};
    for(std::size_t i=0;i<num_dirs&&dd+(i+1)*8<=oo+opt;i++){rd(d,dd+i*8,dirs[i].rva);rd(d,dd+i*8+4,dirs[i].size);}
    auto setdir=[](PeDirectoryInfo&x,const Dir&v){x.present=v.rva&&v.size;x.rva=v.rva;x.size=v.size;};
    setdir(out.resources,dirs[2]);setdir(out.relocations,dirs[5]);setdir(out.debug,dirs[6]);setdir(out.clr,dirs[14]);

    // Exception directory.
    if(dirs[3].rva&&dirs[3].size){
        out.exception.present=true;out.exception.rva=dirs[3].rva;out.exception.size=dirs[3].size;
        if(out.pe64){
            out.exception.runtime_function_count=dirs[3].size/12;
            auto po=rva_off(out,dirs[3].rva,d.size());std::set<std::uint32_t> handlers;
            if(po){for(std::uint32_t i=0;i<out.exception.runtime_function_count;i++){auto e=*po+std::size_t(i)*12;if(e+12>d.size())break;PeRuntimeFunction rf;rd(d,e,rf.begin_rva);rd(d,e+4,rf.end_rva);rd(d,e+8,rf.unwind_rva);if(rf.begin_rva<rf.end_rva&&rf.end_rva<=out.image_size)out.exception.runtime_functions.push_back(rf);auto unwind=rf.unwind_rva;auto uo=rva_off(out,unwind,d.size());if(!uo||*uo+4>d.size())continue;auto vf=d[*uo],count=d[*uo+2];auto flags=vf>>3;std::size_t extra=4+std::size_t(count)*2;extra=(extra+3)&~std::size_t(3);if((flags&3)&&*uo+extra+4<=d.size()){std::uint32_t hr=0;rd(d,*uo+extra,hr);if(hr)handlers.insert(hr);}}}
            out.exception.handler_rvas.assign(handlers.begin(),handlers.end());
        }
    }

    // TLS callbacks. Base parser remains permissive; the implicit plane below independently qualifies exact target mapping.
    if(dirs[9].rva&&dirs[9].size){auto to=rva_off(out,dirs[9].rva,d.size());if(to){out.tls.present=true;out.tls.directory_rva=dirs[9].rva;out.tls.directory_file_offset=*to;std::uint64_t cbva=0;if(out.pe64){rd(d,*to+24,cbva);}else{std::uint32_t x=0;rd(d,*to+12,x);cbva=x;}out.tls.callbacks_va=cbva;if(cbva>=out.image_base&&cbva-out.image_base<=0xffffffffull){auto cro=rva_off(out,static_cast<std::uint32_t>(cbva-out.image_base),d.size());if(cro){out.tls.callbacks_file_offset=*cro;const std::size_t w=out.pe64?8:4;for(std::size_t i=0;i<128;i++){std::uint64_t v=0;if(out.pe64){if(!rd(d,*cro+i*w,v))break;}else{std::uint32_t x=0;if(!rd(d,*cro+i*w,x))break;v=x;}if(!v)break;out.tls.callback_vas.push_back(v);PeTlsCallback c;c.slot_va=cbva+i*w;c.slot_file_offset=*cro+i*w;c.target_va=v;if(v>=out.image_base&&v-out.image_base<=0xffffffffull){if(auto vo=rva_off(out,static_cast<std::uint32_t>(v-out.image_base),d.size())){c.target_file_backed=true;c.target_file_offset=*vo;}}out.tls.callbacks.push_back(c);}}}}}

    // Imports.
    if(dirs[1].rva&&dirs[1].size){auto io=rva_off(out,dirs[1].rva,d.size());if(io){for(std::size_t idx=0;idx<4096;idx++){auto p=*io+idx*20;if(p+20>d.size())break;std::uint32_t oft=0,name_rva=0,ft=0,tds=0,fc=0;rd(d,p,oft);rd(d,p+4,tds);rd(d,p+8,fc);rd(d,p+12,name_rva);rd(d,p+16,ft);if(!oft&&!name_rva&&!ft)break;auto no=rva_off(out,name_rva,d.size());if(!no)break;PeImportModule m;m.name=zstr(d,*no);m.descriptor_rva=dirs[1].rva+static_cast<std::uint32_t>(idx*20);m.iat_rva=ft;auto tr=oft?oft:ft;auto to=rva_off(out,tr,d.size());if(to){const std::size_t w=out.pe64?8:4;for(std::size_t j=0;j<65536;j++){std::uint64_t tv=0;if(out.pe64){if(!rd(d,*to+j*w,tv))break;}else{std::uint32_t x=0;if(!rd(d,*to+j*w,x))break;tv=x;}if(!tv)break;PeImportFunction fn;const std::uint64_t ordmask=out.pe64?0x8000000000000000ull:0x80000000ull;if(tv&ordmask){fn.by_ordinal=true;fn.ordinal=static_cast<std::uint16_t>(tv&0xffff);}else if(tv<=0xffffffffull){auto hn=rva_off(out,static_cast<std::uint32_t>(tv),d.size());if(hn){rd(d,*hn,fn.hint);fn.name=zstr(d,*hn+2);}}m.functions.push_back(std::move(fn));}}out.imports.push_back(std::move(m));}}}

    // Exports.
    if(dirs[0].rva&&dirs[0].size){auto eo=rva_off(out,dirs[0].rva,d.size());if(eo&&*eo+40<=d.size()){std::uint32_t base=0,nfunc=0,nname=0,fr=0,nr=0,orva=0;rd(d,*eo+16,base);rd(d,*eo+20,nfunc);rd(d,*eo+24,nname);rd(d,*eo+28,fr);rd(d,*eo+32,nr);rd(d,*eo+36,orva);nfunc=std::min<std::uint32_t>(nfunc,1u<<20);nname=std::min<std::uint32_t>(nname,1u<<20);auto fo=rva_off(out,fr,d.size()),no=rva_off(out,nr,d.size()),oo2=rva_off(out,orva,d.size());std::map<std::uint16_t,std::string>names;if(no&&oo2){for(std::uint32_t i=0;i<nname;i++){std::uint32_t sr=0;std::uint16_t oi=0;if(!rd(d,*no+i*4,sr)||!rd(d,*oo2+i*2,oi))break;auto so2=rva_off(out,sr,d.size());if(so2)names[oi]=zstr(d,*so2);}}if(fo){for(std::uint32_t i=0;i<nfunc;i++){std::uint32_t rv=0;if(!rd(d,*fo+i*4,rv))break;if(!rv)continue;PeExport e;e.rva=rv;e.ordinal=static_cast<std::uint16_t>(base+i);auto ni=names.find(static_cast<std::uint16_t>(i));if(ni!=names.end())e.name=ni->second;if(rv>=dirs[0].rva&&rv<dirs[0].rva+dirs[0].size){auto fwd=rva_off(out,rv,d.size());if(fwd)e.forwarder=zstr(d,*fwd);}out.exports.push_back(std::move(e));}}}}

    // Load config (selected fields only; guarded by structure size).
    if(dirs[10].rva&&dirs[10].size){auto lo=rva_off(out,dirs[10].rva,d.size());if(lo){out.load_config.present=true;out.load_config.rva=dirs[10].rva;out.load_config.size=dirs[10].size;std::uint32_t struct_size=0;rd(d,*lo,struct_size);auto avail=std::min<std::uint32_t>(struct_size,dirs[10].size);if(out.pe64){if(avail>=96)rd(d,*lo+88,out.load_config.security_cookie);if(avail>=112){rd(d,*lo+96,out.load_config.seh_table);rd(d,*lo+104,out.load_config.seh_count);}if(avail>=148)rd(d,*lo+144,out.load_config.guard_flags);}else{std::uint32_t x=0;if(avail>=64&&rd(d,*lo+60,x))out.load_config.security_cookie=x;if(avail>=72&&rd(d,*lo+64,x))out.load_config.seh_table=x;if(avail>=72&&rd(d,*lo+68,x))out.load_config.seh_count=x;if(avail>=92)rd(d,*lo+88,out.load_config.guard_flags);}}}

    out.init.references_initterm=contains_ascii(d,"_initterm");out.init.references_initterm_e=contains_ascii(d,"_initterm_e");
    {
        auto&im=out.implicit_exec;bool partial=false;std::string partial_error;constexpr std::size_t max_facts=65536;
        auto add=[&](ImplicitExecutionFact f){if(im.facts.size()>=max_facts){im.analysis_limited=true;partial=true;if(partial_error.empty())partial_error="PE implicit execution fact budget exceeded";return;}f.index=static_cast<std::uint32_t>(im.facts.size());if(f.priority=="HIGH")++im.high_priority_count;else if(f.priority=="REVIEW")++im.review_count;else ++im.informational_count;if(!f.anomaly_class.empty()&&f.anomaly_class!="NONE")++im.anomaly_count;if(f.evidence_state=="UNRESOLVED_RUNTIME_SEMANTICS")++im.unresolved_runtime_semantics;im.facts.push_back(std::move(f));};
        auto exact_target_name=[&](std::uint64_t va)->std::string{if(va<out.image_base||va-out.image_base>0xffffffffull)return{};const auto rva=static_cast<std::uint32_t>(va-out.image_base);for(const auto&e:out.exports)if(e.rva==rva&&!e.name.empty())return e.name;return{};};
        for(std::size_t i=0;i<out.tls.callbacks.size();++i){const auto&c=out.tls.callbacks[i];ImplicitExecutionFact f;f.format="PE";f.ecosystem="Windows loader/native";f.phase="loader_pre_entry";f.trigger="PE_TLS_CALLBACK";f.relation="implicit_callback";f.source_kind="TLS_CALLBACK_SLOT";f.source_index=i;f.source_file_backed=true;f.source_file_offset=c.slot_file_offset;f.source_va=c.slot_va;f.source_size=out.pe64?8:4;f.target_kind="function_va";f.target_va=c.target_va;f.target_file_backed=c.target_file_backed;f.target_file_offset=c.target_file_offset;f.target_name=exact_target_name(c.target_va);f.evidence_state=c.target_file_backed?"EXACT":"UNRESOLVED_RUNTIME_SEMANTICS";f.mutability="LOADER_CONSUMED_TLS_CALLBACK_POINTER";f.execution_condition="Windows loader invokes TLS callbacks for process/thread attach-detach according to PE TLS semantics; this static plane does not execute or observe the callback";f.priority="INFORMATIONAL";f.priority_reason="TLS callbacks are ordinary loader pre-entry surfaces; presence alone is not suspicious";if(!c.target_file_backed){partial=true;if(partial_error.empty())partial_error="one or more TLS callback targets are not directly file-backed in the current image";}add(std::move(f));}
        if(out.dll&&out.entry_rva){ImplicitExecutionFact f;f.format="PE";f.ecosystem="Windows loader/native";f.phase="module_load";f.trigger="PE_DLL_ENTRYPOINT";f.relation="implicit_callback";f.source_kind="OPTIONAL_HEADER_ADDRESS_OF_ENTRY_POINT";f.source_file_backed=true;f.source_file_offset=oo+16;f.source_size=4;f.target_kind="dll_entrypoint_rva";f.target_va=out.image_base+out.entry_rva;if(auto eo=rva_off(out,out.entry_rva,d.size())){f.target_file_backed=true;f.target_file_offset=*eo;}f.target_name=exact_target_name(f.target_va);f.evidence_state=f.target_file_backed?"EXACT":"UNRESOLVED_RUNTIME_SEMANTICS";f.mutability="IMMUTABLE_PE_HEADER";f.execution_condition="Windows loader invokes the image DLL entry point for loader notifications; this may be a CRT wrapper around user DllMain and is not relabeled as the user callback without stronger evidence";f.priority="INFORMATIONAL";f.priority_reason="DLL entry is an ordinary loader-invoked module surface";if(!f.target_file_backed){partial=true;if(partial_error.empty())partial_error="DLL entry point is not directly file-backed in the current image";}add(std::move(f));}
        struct Cap{const char*name;const char*trigger;const char*kind;};
        static constexpr std::array<Cap,8> caps{{
            {"VirtualProtect","PE_IMPORTED_MEMORY_PROTECT_API","permission_mutation_capability"},{"VirtualProtectEx","PE_IMPORTED_MEMORY_PROTECT_API","permission_mutation_capability"},
            {"NtProtectVirtualMemory","PE_IMPORTED_MEMORY_PROTECT_API","permission_mutation_capability"},{"ZwProtectVirtualMemory","PE_IMPORTED_MEMORY_PROTECT_API","permission_mutation_capability"},
            {"VirtualAlloc","PE_IMPORTED_MEMORY_ALLOCATE_API","executable_materialization_capability"},{"VirtualAllocEx","PE_IMPORTED_MEMORY_ALLOCATE_API","executable_materialization_capability"},
            {"NtAllocateVirtualMemory","PE_IMPORTED_MEMORY_ALLOCATE_API","executable_materialization_capability"},{"ZwAllocateVirtualMemory","PE_IMPORTED_MEMORY_ALLOCATE_API","executable_materialization_capability"}}};
        std::uint64_t cap_index=0;const std::size_t iw=out.pe64?8:4;
        for(const auto&m:out.imports)for(std::size_t j=0;j<m.functions.size();++j){const auto&fn=m.functions[j];if(fn.by_ordinal||fn.name.empty())continue;const Cap*hit=nullptr;for(const auto&c:caps)if(fn.name==c.name){hit=&c;break;}if(!hit)continue;ImplicitExecutionFact f;f.format="PE";f.ecosystem="Windows native";f.phase="runtime_capability";f.trigger=hit->trigger;f.relation="stage2_precursor";f.source_kind="IAT_IMPORT_SLOT";f.source_index=cap_index++;f.source_va=out.image_base+std::uint64_t(m.iat_rva)+j*iw;f.source_size=iw;if(auto io=rva_off(out,static_cast<std::uint32_t>(std::uint64_t(m.iat_rva)+j*iw),d.size())){f.source_file_backed=true;f.source_file_offset=*io;}f.target_kind=hit->kind;f.target_name=m.name+"!"+fn.name;f.evidence_state="EXACT";f.mutability="LOADER_RESOLVED_IAT_SLOT";f.execution_condition="static import proves this API capability is available to the image; no call, protection change, allocation, write, or execution transition is inferred";f.priority="INFORMATIONAL";f.priority_reason="permission/allocation API import is only a static stage-2 precursor; runtime evidence is required to confirm a transition";add(std::move(f));}
        if(im.facts.empty())im.state=partial?"PARTIAL":"NOT_PRESENT";else im.state=partial?"PARTIAL":"RESOLVED";if(partial)im.error=partial_error;
    }
    out.valid=true;return out;
}
PeInfo parse_pe(const std::filesystem::path&p){std::ifstream f(p,std::ios::binary);if(!f){PeInfo o;o.error="open failed";return o;}std::vector<std::uint8_t>d((std::istreambuf_iterator<char>(f)),{});return parse_pe(d);}
std::string pe_machine_name(std::uint16_t m){switch(m){case 0x014c:return"x86";case 0x8664:return"x64";case 0xaa64:return"ARM64";case 0x01c4:return"ARMv7";default:return"0x"+std::to_string(m);}}
std::string pe_subsystem_name(std::uint16_t s){switch(s){case 1:return"Native";case 2:return"Windows GUI";case 3:return"Windows Console";case 7:return"POSIX Console";case 9:return"Windows CE GUI";case 10:return"EFI Application";case 14:return"Xbox";case 16:return"Windows Boot";default:return"Unknown";}}
}
