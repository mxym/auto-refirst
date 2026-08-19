#include "prts/rust.hpp"
#include "prts/byte_search.hpp"
extern "C" {
#include "../../third_party/rustc_demangle/demangle.h"
}
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <optional>
#include <set>
#include <string_view>
namespace prts { namespace {
std::uint16_t u16(std::span<const std::uint8_t>d,std::size_t o,bool le=true){if(o+2>d.size())return 0;return le?(std::uint16_t(d[o])|(std::uint16_t(d[o+1])<<8)):(std::uint16_t(d[o])<<8|d[o+1]);}
std::uint32_t u32(std::span<const std::uint8_t>d,std::size_t o,bool le=true){if(o+4>d.size())return 0;if(le)return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);return std::uint32_t(d[o])<<24|std::uint32_t(d[o+1])<<16|std::uint32_t(d[o+2])<<8|d[o+3];}
std::uint64_t u64(std::span<const std::uint8_t>d,std::size_t o,bool le=true){if(o+8>d.size())return 0;std::uint64_t v=0;if(le){for(int i=7;i>=0;--i)v=(v<<8)|d[o+i];}else{for(int i=0;i<8;++i)v=(v<<8)|d[o+i];}return v;}
std::string zstr(std::span<const std::uint8_t>d,std::size_t o,std::size_t max=1<<20){if(o>=d.size())return{};auto q=o;while(q<d.size()&&q-o<max&&d[q])++q;return std::string(reinterpret_cast<const char*>(d.data()+o),q-o);}
std::string demangle_rust(const std::string&m){demangle d{};rust_demangle_demangle(m.c_str(),&d);if(!rust_demangle_is_known(&d))return{};std::array<char,16384>buf{};if(rust_demangle_display_demangle(&d,buf.data(),buf.size(),true)!=OverflowOk)return{};return std::string(buf.data());}
void add_symbol(RustInfo&r,std::uint64_t va,std::uint64_t rva,std::uint64_t sz,const std::string&name){auto dm=demangle_rust(name);if(dm.empty())return;r.symbol_table_present=true;for(const auto&x:r.symbols)if(x.va==va&&x.mangled==name)return;r.symbols.push_back({va,rva,sz,name,std::move(dm)});}
void parse_elf_syms(std::span<const std::uint8_t>d,const ElfInfo&elf,RustInfo&r){if(!elf.valid||d.size()<64)return;bool is64=elf.elf64,le=elf.little_endian;std::uint64_t shoff=is64?u64(d,40,le):u32(d,32,le);std::uint16_t shents=u16(d,is64?58:46,le),shnum=u16(d,is64?60:48,le);if(!shoff||!shents||!shnum||shoff+std::uint64_t(shents)*shnum>d.size())return;struct S{std::uint32_t type=0,link=0;std::uint64_t off=0,size=0,ents=0;};std::vector<S>ss(shnum);for(std::uint16_t i=0;i<shnum;++i){auto o=std::size_t(shoff)+std::size_t(i)*shents;if(is64){ss[i].type=u32(d,o+4,le);ss[i].off=u64(d,o+24,le);ss[i].size=u64(d,o+32,le);ss[i].link=u32(d,o+40,le);ss[i].ents=u64(d,o+56,le);}else{ss[i].type=u32(d,o+4,le);ss[i].off=u32(d,o+16,le);ss[i].size=u32(d,o+20,le);ss[i].link=u32(d,o+24,le);ss[i].ents=u32(d,o+36,le);}}
    for(const auto&s:ss){if((s.type!=2&&s.type!=11)||s.link>=ss.size()||!s.ents||s.off+s.size>d.size())continue;const auto&str=ss[s.link];if(str.off+str.size>d.size())continue;for(std::uint64_t p=s.off;p+s.ents<=s.off+s.size;p+=s.ents){std::uint32_t no=u32(d,p,le);std::uint8_t info=is64?d[p+4]:d[p+12];if((info&0xf)!=2||!no||no>=str.size)continue;auto name=zstr(d,str.off+no,4096);std::uint64_t va=is64?u64(d,p+8,le):u32(d,p+4,le),sz=is64?u64(d,p+16,le):u32(d,p+8,le);add_symbol(r,va,va,sz,name);}}
}
void parse_elf_dynamic_syms(const ElfInfo&elf,RustInfo&r){
    if(!r.symbols.empty()||elf.dynamic.state!="RESOLVED")return;
    for(const auto&s:elf.dynamic.symbols){if(s.type!=2||!s.exported||!s.value||s.name.empty())continue;add_symbol(r,s.value,s.value,s.size,s.name);}
}
void parse_pe_coff(std::span<const std::uint8_t>d,const PeInfo&pe,RustInfo&r){if(!pe.valid||d.size()<0x40)return;auto lf=u32(d,0x3c);if(lf+24>d.size())return;auto coff=lf+4;auto sym=u32(d,coff+8),n=u32(d,coff+12);if(!sym||!n||sym+std::uint64_t(n)*18+4>d.size()||n>500000)return;auto strbase=std::size_t(sym)+std::size_t(n)*18;auto strsz=u32(d,strbase);for(std::uint32_t i=0;i<n;){auto o=std::size_t(sym)+std::size_t(i)*18;if(o+18>d.size())break;std::string name;if(u32(d,o)==0){auto so=u32(d,o+4);if(so>=4&&so<strsz&&strbase+so<d.size())name=zstr(d,strbase+so,4096);}else{name.assign(reinterpret_cast<const char*>(d.data()+o),8);auto z=name.find('\0');if(z!=std::string::npos)name.resize(z);}auto val=u32(d,o+8);auto secno=std::int16_t(u16(d,o+12));auto type=u16(d,o+14);auto aux=d[o+17];if(secno>0&&std::size_t(secno)<=pe.sections.size()&&(type&0x20)){const auto&s=pe.sections[secno-1];auto rva=std::uint64_t(s.rva)+val;add_symbol(r,pe.image_base+rva,rva,0,name);}i+=1u+aux;}}
bool hex40(std::string_view s){if(s.size()!=40)return false;for(auto c:s)if(!std::isxdigit(static_cast<unsigned char>(c)))return false;return true;}
void scan_paths(std::span<const std::uint8_t>d,RustInfo&r){
    std::set<std::string>seenstd,seencrate;
    auto printable_end=[&](std::size_t p){while(p<d.size()&&d[p]>=0x20&&d[p]<=0x7e)++p;return p;};
    constexpr std::string_view rustc="/rustc/";
    for(std::size_t hit=0;;){hit=detail::find_exact(d,rustc,hit);if(hit==std::string::npos)break;auto e=printable_end(hit);std::string_view v(reinterpret_cast<const char*>(d.data()+hit),e-hit);auto h=rustc.size();if(h+40<=v.size()&&hex40(v.substr(h,40))){if(r.rustc_source_hash.empty())r.rustc_source_hash=std::string(v.substr(h,40));auto q=v.find("/library/",h+40);if(q!=std::string_view::npos){auto z=v.find_first_of(" \t\r\n",q);std::string path(v.substr(0,z==std::string_view::npos?v.size():z));if(seenstd.insert(path).second&&r.std_source_paths.size()<128)r.std_source_paths.push_back(std::move(path));}}++hit;}
    constexpr std::string_view cargo="/.cargo/registry/src/";
    for(std::size_t hit=0;;){hit=detail::find_exact(d,cargo,hit);if(hit==std::string::npos)break;auto e=printable_end(hit);std::string_view v(reinterpret_cast<const char*>(d.data()+hit),e-hit);auto after=v.find('/',cargo.size());if(after!=std::string_view::npos){auto pkgstart=after+1;auto slash=v.find('/',pkgstart);if(slash!=std::string_view::npos){auto pkg=v.substr(pkgstart,slash-pkgstart);auto dash=pkg.rfind('-');if(dash!=std::string_view::npos&&dash+1<pkg.size()){std::string key(pkg);if(seencrate.insert(key).second&&r.crates.size()<128)r.crates.push_back({std::string(pkg.substr(0,dash)),std::string(pkg.substr(dash+1)),std::string(v.substr(0,slash))});}}}++hit;}
}
}
RustInfo detect_rust(std::span<const std::uint8_t>d,const PeInfo&pe,const ElfInfo&elf){RustInfo r;parse_elf_syms(d,elf,r);parse_elf_dynamic_syms(elf,r);parse_pe_coff(d,pe,r);scan_paths(d,r);auto has=[&](std::string_view s){return detail::contains_exact(d,s);};if(!r.symbols.empty()||!r.rustc_source_hash.empty()||has("rust_begin_unwind")||has("core::panicking")||has("library/core/src/panicking.rs"))r.valid=true;if(r.valid&&r.symbols.empty())r.error="Rust runtime/source evidence present but usable Rust function symbols are stripped/absent";return r;}
Finding rust_finding(const RustInfo&r){Finding f;f.kind="runtime";f.family="Rust";if(!r.valid){f.state="FAILED";return f;}f.state="CONFIRMED";f.evidence.push_back(!r.symbols.empty()?"Rust mangled symbols decoded with rustc-demangle native C":"Rust standard-library source/runtime paths detected");if(!r.rustc_source_hash.empty())f.fields["rustc_source_hash"]=r.rustc_source_hash;f.fields["demangled_symbols"]=std::to_string(r.symbols.size());f.fields["crate_hints"]=std::to_string(r.crates.size());if(!r.error.empty())f.negative_evidence.push_back(r.error);return f;}
}
