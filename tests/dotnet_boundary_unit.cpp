#include "prts/dotnet_boundary.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

namespace {
prts::PeInfo base_pe(){
    prts::PeInfo pe;pe.valid=true;pe.pe64=true;pe.image_base=0x140000000ull;pe.headers_size=0x200;pe.image_size=0x5000;pe.entry_rva=0x1010;pe.clr.present=true;pe.clr.rva=0x1000;pe.clr.size=0x40;
    prts::PeSection text;text.name=".text";text.rva=0x1000;text.vsize=0x400;text.raw_offset=0x200;text.raw_size=0x400;text.characteristics=0x60000020u;pe.sections.push_back(text);
    pe.imports.push_back({"kernel32.dll",0,0,{{"LoadLibraryW",0,false,0}}});
    pe.imports.push_back({"mscoree.dll",0,0,{{"_CorExeMain",0,false,0}}});
    pe.exports.push_back({"NativeBridge",{},0x1200,1});
    return pe;
}

std::vector<std::uint8_t> clr_header(){
    std::vector<std::uint8_t> data(0x1000,0);
    auto put=[&](std::size_t offset,std::uint32_t value){for(unsigned i=0;i<4;++i)data[offset+i]=static_cast<std::uint8_t>(value>>(8*i));};
    put(0x200+16,0x10);put(0x200+20,0x1100);
    return data;
}
}

int main(){
    auto data=clr_header();auto pe=base_pe();prts::DotNetInfo dotnet;dotnet.valid=true;dotnet.entry_point_native=true;dotnet.clr_flags=0x10;dotnet.entry_point_token_or_rva=0x1100;
    prts::DotNetMethod bridge;bridge.token=0x06000001;bridge.rva=0x1150;bridge.name="NativeThunk";bridge.type_name="Bridge";bridge.body_file_backed=false;dotnet.methods.push_back(bridge);
    prts::DotNetMethod pinvoke;pinvoke.token=0x06000002;pinvoke.name="Load";pinvoke.type_name="Bridge";pinvoke.pinvoke=true;pinvoke.import_module="kernel32.dll";pinvoke.import_name="LoadLibraryW";dotnet.methods.push_back(pinvoke);
    auto mixed=prts::analyze_dotnet_boundary(data,pe,dotnet);
    if(mixed.state!="CONFIRMED"||mixed.boundary_kind!="MIXED_NATIVE_MANAGED_BOUNDARY"||!mixed.native_entry_file_backed||!mixed.native_entry_executable||!mixed.entry_rva_diverges||mixed.non_file_backed_method_count!=1||mixed.pinvoke_method_count!=1||mixed.dependencies.empty())return 1;
    auto finding=prts::dotnet_boundary_finding(mixed);if(finding.state!="CONFIRMED"||finding.fields["runtime_resolution"]!="NOT_PERFORMED"||finding.fields["clr_rva"]!="0x1000"||finding.ranges.empty())return 2;

    auto malformed=pe;malformed.clr.rva=0x4f00;malformed.clr.size=0x80;auto failed=prts::analyze_dotnet_boundary(data,malformed,dotnet);if(failed.state!="FAILED"||failed.boundary_kind!="UNRESOLVED_BOUNDARY")return 3;

    auto dependency=base_pe();dependency.clr.rva=0x1000;dependency.clr.size=0x40;auto managed=dotnet;managed.entry_point_native=false;managed.clr_flags=0;managed.entry_point_token_or_rva=0x06000001;auto managed_data=clr_header();managed_data[0x200+16]=0;auto likely=prts::analyze_dotnet_boundary(managed_data,dependency,managed);if(likely.state!="LIKELY"||likely.boundary_kind!="MANAGED_NATIVE_DEPENDENCY_SURFACE")return 4;

    auto absent=base_pe();absent.clr.present=false;auto no_clr=prts::analyze_dotnet_boundary(data,absent,dotnet);if(no_clr.candidate||no_clr.state!="ABSENT")return 5;
    std::cout<<"PASS\n";return 0;
}
