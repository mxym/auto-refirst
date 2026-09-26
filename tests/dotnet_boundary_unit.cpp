#include "prts/dotnet_boundary.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
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
    if(mixed.state!="CONFIRMED"||mixed.boundary_kind!="MIXED_NATIVE_MANAGED_BOUNDARY"||!mixed.native_entry_file_backed||!mixed.native_entry_executable||!mixed.entry_rva_diverges||mixed.non_file_backed_method_count!=1||mixed.body_geometry_invalid_method_count!=1||mixed.pinvoke_method_count!=1||mixed.dependencies.empty()||mixed.bridge_methods.front().state!="METHOD_BODY_GEOMETRY_INVALID")return 1;
    auto finding=prts::dotnet_boundary_finding(mixed);if(finding.state!="CONFIRMED"||finding.fields["runtime_resolution"]!="NOT_PERFORMED"||finding.fields["clr_rva"]!="0x1000"||finding.fields["body_geometry_invalid_methods"]!="1"||finding.ranges.empty())return 2;

    auto resources=dotnet;
    prts::DotNetResource embedded;embedded.rid=1;embedded.name="payload.dll";embedded.embedded=true;embedded.size_known=true;embedded.data_offset=0x380;embedded.size=64;
    prts::DotNetResource external;external.rid=2;external.name="satellite.resources";external.implementation_token=0x23000001;external.implementation="Satellite";external.implementation_kind="AssemblyRef";
    prts::DotNetResource external_file;external_file.rid=3;external_file.name="native.dat";external_file.implementation_token=0x26000001;external_file.implementation_kind="File";
    resources.resources={embedded,external,external_file};
    auto resource_finding=prts::dotnet_resources_finding(resources);
    if(resource_finding.state!="CONFIRMED"||resource_finding.variant!="embedded-and-external"||resource_finding.fields["embedded_count"]!="1"||resource_finding.fields["external_reference_count"]!="2"||resource_finding.fields["external_assembly_ref_count"]!="1"||resource_finding.fields["external_file_count"]!="1"||resource_finding.fields["resource_semantics"]!="NOT_ATTEMPTED_STATIC_ONLY"||resource_finding.ranges.size()!=1||resource_finding.ranges.front().coordinate_space!=prts::CoordinateSpace::FILE_OFFSET||resource_finding.ranges.front().basis!=prts::CoordinateBasis::CURRENT_INPUT_FILE||resource_finding.ranges.front().offset!=0x380||resource_finding.ranges.front().size!=64)return 6;

    for(std::size_t i=0;i<64;++i)data[0x380+i]=static_cast<std::uint8_t>(i+1);
    std::error_code ec;auto resource_dir=std::filesystem::temp_directory_path(ec)/"auto-refirst-dotnet-resources-unit";if(ec)return 7;std::filesystem::remove_all(resource_dir,ec);ec.clear();
    auto extracted=prts::extract_dotnet_resources(data,resources,resource_dir,false,64,1);
    if(!extracted.success||extracted.written_count!=1||extracted.output_bytes!=64||extracted.files.size()!=1)return 8;
    std::ifstream resource_file(extracted.files.front(),std::ios::binary);std::vector<std::uint8_t>resource_bytes((std::istreambuf_iterator<char>(resource_file)),{});if(resource_bytes.size()!=64||resource_bytes.front()!=1||resource_bytes.back()!=64)return 9;
    std::filesystem::remove_all(resource_dir,ec);ec.clear();auto limited=prts::extract_dotnet_resources(data,resources,resource_dir,true,32,1);if(limited.success||!limited.budget_exhausted||limited.omitted_count!=1||!limited.files.empty())return 10;std::filesystem::remove_all(resource_dir,ec);

    auto malformed=pe;malformed.clr.rva=0x4f00;malformed.clr.size=0x80;auto failed=prts::analyze_dotnet_boundary(data,malformed,dotnet);if(failed.state!="FAILED"||failed.boundary_kind!="UNRESOLVED_BOUNDARY")return 3;

    auto dependency=base_pe();dependency.clr.rva=0x1000;dependency.clr.size=0x40;auto managed=dotnet;managed.entry_point_native=false;managed.clr_flags=0;managed.entry_point_token_or_rva=0x06000001;auto managed_data=clr_header();managed_data[0x200+16]=0;auto likely=prts::analyze_dotnet_boundary(managed_data,dependency,managed);if(likely.state!="LIKELY"||likely.boundary_kind!="MANAGED_NATIVE_DEPENDENCY_SURFACE")return 4;

    auto modified=managed;prts::DotNetMethod missing;missing.token=0x06000003;missing.name="Replaced";missing.type_name="Bridge";missing.impl_flags=0;missing.flags=0x0010;modified.methods.push_back(missing);auto modified_result=prts::analyze_dotnet_boundary(managed_data,dependency,modified);if(modified_result.suspicious_rva_absent_method_count!=1||modified_result.bridge_methods.empty()||modified_result.bridge_methods.back().state!="METHOD_RVA_ABSENT_SUSPICIOUS")return 11;auto modified_finding=prts::dotnet_boundary_finding(modified_result);if(modified_finding.fields["suspicious_rva_absent_methods"]!="1")return 12;

    auto absent=base_pe();absent.clr.present=false;auto no_clr=prts::analyze_dotnet_boundary(data,absent,dotnet);if(no_clr.candidate||no_clr.state!="ABSENT")return 5;
    std::cout<<"PASS\n";return 0;
}
