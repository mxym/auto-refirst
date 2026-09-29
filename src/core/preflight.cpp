#include "prts/preflight.hpp"
#include "prts/python_bytecode.hpp"
#include <algorithm>
#include <array>
#include <initializer_list>
#include <utility>

namespace prts { namespace {
using Format=PreflightFormat;
bool starts(std::span<const std::uint8_t>d,std::initializer_list<std::uint8_t> bytes){return d.size()>=bytes.size()&&std::equal(bytes.begin(),bytes.end(),d.begin());}
std::uint64_t read(std::span<const std::uint8_t>d,std::size_t offset,std::size_t width,bool le=true){
    if(offset>d.size()||width>d.size()-offset)return 0;
    std::uint64_t value=0;
    for(std::size_t i=0;i<width;++i)value|=std::uint64_t(d[offset+i])<<(8*(le?i:width-1-i));
    return value;
}
PreflightHeader hint(Format format,std::string_view type,std::string_view role,int boost,std::string_view reason,std::string_view confidence="medium",bool executable=false){
    return {format,type,role,confidence,reason,boost,executable};
}
bool thin_macho(std::span<const std::uint8_t>d,std::uint64_t file_size){
    const bool le=starts(d,{0xce,0xfa,0xed,0xfe})||starts(d,{0xcf,0xfa,0xed,0xfe});
    const bool be=starts(d,{0xfe,0xed,0xfa,0xce})||starts(d,{0xfe,0xed,0xfa,0xcf});
    if(!le&&!be)return false;
    const bool is64=le?d[0]==0xcf:d[3]==0xcf;
    const std::size_t header=is64?32:28;
    if(d.size()<header||file_size<header)return false;
    const auto type=read(d,12,4,le),count=read(d,16,4,le),bytes=read(d,20,4,le);
    return read(d,4,4,le)!=0&&type>=1&&type<=12&&bytes<=file_size-header&&((count==0&&bytes==0)||(count!=0&&count<=bytes/8));
}
bool fat_macho(std::span<const std::uint8_t>d,std::uint64_t file_size,bool le,bool fat64){
    if(d.size()<8)return false;
    const auto count=read(d,4,4,le);
    if(!count||count>64)return false;
    const std::size_t stride=fat64?32:20;
    const auto end=8+count*stride;
    if(end>d.size())return false;
    std::array<std::pair<std::uint64_t,std::uint64_t>,64> ranges{};
    std::array<std::uint64_t,64> architectures{};
    for(std::size_t i=0;i<count;++i){
        const auto p=8+i*stride;
        const auto cpu=read(d,p,4,le),subtype=read(d,p+4,4,le);
        const auto offset=read(d,p+8,fat64?8:4,le),size=read(d,p+(fat64?16:12),fat64?8:4,le);
        const auto align=read(d,p+(fat64?24:16),4,le);
        if(!cpu||align>31||(fat64&&read(d,p+28,4,le))||offset<end||offset>file_size||size<28||size>file_size-offset)return false;
        if(offset%(std::uint64_t{1}<<align))return false;
        const auto architecture=(cpu<<32)|subtype;
        for(std::size_t j=0;j<i;++j)if(architectures[j]==architecture||(offset<ranges[j].second&&ranges[j].first<offset+size))return false;
        ranges[i]={offset,offset+size};architectures[i]=architecture;
    }
    return true;
}
bool jvm_header(std::span<const std::uint8_t>d){
    if(d.size()<11)return false;
    const auto major=read(d,6,2,false),count=read(d,8,2,false);
    if(major<45||major>100||count<2)return false;
    switch(d[10]){case 1:case 3:case 4:case 5:case 6:case 7:case 8:case 9:case 10:case 11:case 12:case 15:case 16:case 17:case 18:case 19:case 20:return true;default:return false;}
}
bool lua_header(std::span<const std::uint8_t>d){
    if(d.size()<6||d[5]!=0||d[4]<0x51||d[4]>0x55)return false;
    if(d[4]<=0x52){
        if(d.size()<(d[4]==0x51?12u:18u))return false;
        if(d[6]>1||d[7]<2||d[7]>8||d[8]<4||d[8]>8||d[9]!=4||(d[10]!=4&&d[10]!=8)||d[11]>1)return false;
        return d[4]==0x51||starts(d.subspan(12),{0x19,0x93,0x0d,0x0a,0x1a,0x0a});
    }
    if(d.size()<15||!starts(d.subspan(6),{0x19,0x93,0x0d,0x0a,0x1a,0x0a}))return false;
    if(d[4]==0x53){
        if(d.size()<17||d[12]<2||d[12]>8||d[13]<4||d[13]>8||d[14]!=4||(d[15]!=4&&d[15]!=8)||(d[16]!=4&&d[16]!=8))return false;
        return d.size()>=17u+d[15]+d[16]&&(read(d,17,d[15])==0x5678||read(d,17,d[15],false)==0x5678);
    }
    if(d[4]==0x54)return d[12]==4&&(d[13]==4||d[13]==8)&&(d[14]==4||d[14]==8)&&d.size()>=15u+d[13]+d[14]&&read(d,15,d[13])==0x5678;
    // 5.5 interleaves size bytes with numeric sentinels; it does not have the
    // consecutive instruction/integer/number-size layout used by 5.4.
    std::size_t p=12;
    auto negative_marker=[&](std::uint8_t width){
        if(width<2||width>8||width>d.size()-p)return false;
        const auto mask=width==8?~std::uint64_t{0}:(std::uint64_t{1}<<(width*8))-1;
        const bool match=read(d,p,width)==((std::uint64_t{0}-0x5678)&mask);p+=width;return match;
    };
    const auto int_size=d[p++];if(!negative_marker(int_size)||p>=d.size())return false;
    const auto instruction_size=d[p++];if(instruction_size!=4||d.size()-p<5||read(d,p,4)!=0x12345678)return false;p+=4;
    const auto integer_size=d[p++];if(!negative_marker(integer_size)||p>=d.size())return false;
    const auto number_size=d[p++];return (number_size==4||number_size==8)&&number_size<=d.size()-p;
}
bool asar_header(std::span<const std::uint8_t>d,std::uint64_t file_size){
    if(d.size()<16||file_size<16||read(d,0,4)!=4)return false;
    const auto header_size=read(d,4,4),payload_size=read(d,8,4),json_size=read(d,12,4);
    if(header_size<8||header_size>64ull*1024*1024||header_size>file_size-8)return false;
    if(payload_size+4!=header_size||std::uint64_t(json_size)>payload_size-4||16ull+json_size>file_size)return false;
    if(16ull+json_size>d.size()||json_size<9)return false;
    return d[16]=='{'&&d[17]=='\"'&&d[18]=='f'&&d[19]=='i'&&d[20]=='l'&&d[21]=='e'&&d[22]=='s';
}
bool javascript_prefix(std::span<const std::uint8_t>d){
    if(d.empty())return false;
    std::string_view text(reinterpret_cast<const char*>(d.data()),d.size());
    static constexpr std::array<std::string_view,7> tokens={"module.exports","exports.","require(","WebAssembly.","fetch(","import ","const "};
    std::size_t hits=0;for(const auto token:tokens)if(text.find(token)!=std::string_view::npos)++hits;
    return hits>=2;
}
}

PreflightHeader probe_preflight_header(std::span<const std::uint8_t>d,std::uint64_t file_size){
    d=d.first(std::min(d.size(),static_cast<std::size_t>(std::min<std::uint64_t>(file_size,kPreflightPrefixBytes))));
    if(d.size()>=64&&starts(d,{'M','Z'})){
        const auto offset=read(d,0x3c,4);
        if(offset<=d.size()&&d.size()-offset>=24&&starts(d.subspan(static_cast<std::size_t>(offset)),{'P','E',0,0})){
            const bool dll=(read(d,static_cast<std::size_t>(offset)+22,2)&0x2000)!=0;
            return hint(Format::PE,dll?"PE DLL":"PE executable",dll?"shared_library":"executable_root",dll?60:100,"bounded PE/COFF header validates in preflight","high",!dll);
        }
        return hint(Format::Unknown,"MZ/DOS-like","unknown",5,"MZ prefix is only a route hint; PE structure did not fit the bounded preflight","low");
    }
    if(starts(d,{0x7f,'E','L','F'})){
        const bool header_shape=d.size()>=20&&file_size>=20&&(d[4]==1||d[4]==2)&&(d[5]==1||d[5]==2)&&d[6]==1;
        if(!header_shape)return hint(Format::ELF,"ELF-like","unknown",5,"ELF magic is present but class, byte order, or version is not a plausible bounded header","low");
        const auto type=read(d,16,2,d[5]==1);
        return hint(Format::ELF,"ELF",type==2?"executable_root":(type==3?"elf_dynamic_image":"object"),type==2?100:(type==3?65:45),"ELF identity and header type route bounded full validation","high",type==2);
    }
    if(thin_macho(d,file_size))return hint(Format::MachO,"Mach-O","native_image",65,"Mach-O fixed header and load-command byte/count bounds; commands still require full parsing");
    if(starts(d,{0xce,0xfa,0xed,0xfe})||starts(d,{0xcf,0xfa,0xed,0xfe})||starts(d,{0xfe,0xed,0xfa,0xce})||starts(d,{0xfe,0xed,0xfa,0xcf}))
        return hint(Format::MachO,"Mach-O","native_image",5,"Mach-O signature without a complete plausible fixed header","low");
    const bool fat_be=starts(d,{0xca,0xfe,0xba,0xbe})||starts(d,{0xca,0xfe,0xba,0xbf});
    const bool fat_le=starts(d,{0xbe,0xba,0xfe,0xca})||starts(d,{0xbf,0xba,0xfe,0xca});
    if(fat_be||fat_le){
        const bool fat64=fat_le?d[0]==0xbf:d[3]==0xbf;
        const bool macho=fat_macho(d,file_size,fat_le,fat64);
        const bool jvm=!fat_le&&!fat64&&jvm_header(d);
        if(macho&&!jvm)return hint(Format::MachO,"Mach-O","native_image",65,"bounded universal architecture table and non-overlapping file ranges; slices still require full parsing");
        if(jvm&&!macho)return hint(Format::JvmClass,"JVM Class","bytecode_module",55,"JVM version and first constant-pool tag distinguish the shared CAFEBABE prefix");
        return hint(Format::MachOOrJvm,"Mach-O/JVM candidate","ambiguous_format",5,"shared signature is ambiguous or lacks a plausible bounded format header","low");
    }
    if(starts(d,{0xc6,0x1f,0xbc,0x03,0xc1,0x03,0x19,0x1f})){
        const auto version=read(d,8,4);
        const bool plausible=d.size()>=128&&file_size>=148&&read(d,32,4)==file_size&&(version==89||version==96||version==98);
        return hint(Format::Hermes,"Hermes HBC","bytecode_module",plausible?55:5,plausible?"Hermes known epoch and fixed-header fileLength agree; tables and footer still require full parsing":"Hermes signature is truncated, unsupported, or lacks plausible header geometry",plausible?"medium":"low");
    }
    if(starts(d,{0x1b,'L','u','a'})){
        const bool plausible=lua_header(d);
        return hint(Format::Lua,"Lua","bytecode_module",plausible?55:5,plausible?"Lua 5.1-5.5 version/format and fixed header anchors; prototypes still require full parsing":"Lua signature without a supported plausible header",plausible?"medium":"low");
    }
    if(identify_cpython_pyc_magic(d).known){
        const bool plausible=d.size()>16&&(read(d,4,4)&~std::uint64_t{3})==0&&(d[16]&0x7f)==0x63;
        return hint(Format::PythonBytecode,"CPython bytecode","bytecode_payload",plausible?55:5,plausible?"shared CPython minor-family magic registry plus pyc flags and root-code tag; marshal validation remains pending":"known CPython magic without a plausible complete pyc/code header",plausible?"medium":"low");
    }
    if(starts(d,{0,'a','s','m'}))return hint(Format::Wasm,"WebAssembly","bytecode_module",55,"WebAssembly signature routes full structural validation","high");
    if(d.size()>=8&&starts(d,{'d','e','x','\n'}))return hint(Format::Dex,"DEX","bytecode_module",55,"DEX header prefix routes full validation","high");
    if(starts(d,{'P','K',3,4})||starts(d,{'P','K',5,6})||starts(d,{'P','K',7,8}))return hint(Format::Zip,"ZIP/container","container",50,"ZIP signature routes APK/JAR/container validation");
    if(starts(d,{'-','=','=', '-', '-', '=', '=', '-', '-', '=', '=', '-', '-', '=', '=', '-'}))return hint(Format::IoStore,"Unreal IoStore TOC","iostore_toc",55,"fixed IoStore UTOC magic routes full bounded section and partition validation","high");
    if(starts(d,{'G','D','P','C'}))return hint(Format::GodotPck,"Godot PCK","container",50,"Godot PCK magic routes full structural validation");
    if(asar_header(d,file_size))return hint(Format::Asar,"Electron ASAR","container",55,"bounded ASAR Pickle geometry and JSON files marker route full container validation","medium");
    if(starts(d,{'#','!'}))return hint(Format::Script,"script","script",30,"shebang identifies a script; it remains static-only by default");
    if(javascript_prefix(d))return hint(Format::Script,"JavaScript-like script","script",25,"bounded source tokens identify a JavaScript-like script; parsing remains static-only","low");
    return {};
}
}
