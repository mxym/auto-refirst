#include "prts/dotnet.hpp"
#include <iostream>

namespace {
prts::DotNetMemberRef member(std::uint32_t token,const char* parent,const char* name){
    prts::DotNetMemberRef out;out.token=token;out.parent=parent;out.name=name;return out;
}
}

int main(){
    prts::DotNetInfo empty;
    if(prts::dotnet_dynamic_surface_finding(empty))return 1;

    prts::DotNetInfo one;one.valid=true;
    one.member_refs.push_back(member(0x0a000001,"System.Reflection.Assembly","Load"));
    if(prts::dotnet_dynamic_surface_finding(one))return 2;

    prts::DotNetInfo loader;loader.valid=true;
    loader.member_refs={
        member(0x0a000001,"System.Reflection.Assembly","Load"),
        member(0x0a000002,"System.Reflection.Assembly","GetManifestResourceStream"),
        member(0x0a000003,"System.Reflection.MethodBase","Invoke"),
    };
    prts::DotNetMethod native;native.token=0x06000001;native.pinvoke=true;native.import_module="kernel32.dll";native.import_name="VirtualProtect";loader.methods.push_back(native);
    const auto finding=prts::dotnet_dynamic_surface_finding(loader);
    if(!finding||finding->family!="Managed dynamic loader surface"||finding->state!="LIKELY")return 3;
    if(finding->fields.at("managed_assembly_load_refs")!="1"||finding->fields.at("resource_access_refs")!="1"||finding->fields.at("reflection_invoke_refs")!="1"||finding->fields.at("native_loader_bridge_refs")!="1")return 4;
    if(finding->fields.at("runtime_reachability")!="NOT_RESOLVED")return 5;

    prts::DotNetResource embedded;embedded.rid=1;embedded.name="payload.bin";embedded.embedded=true;embedded.size_known=true;embedded.data_offset=0x380;embedded.size=64;loader.resources.push_back(embedded);
    const auto route=prts::dotnet_resource_loader_finding(loader);
    if(!route||route->family!="Managed resource loader route"||route->state!="LIKELY")return 7;
    if(route->variant!="EMBEDDED_RESOURCE_TO_ASSEMBLY"||route->fields.at("resource_access_refs")!="1"||route->fields.at("assembly_load_refs")!="1"||route->fields.at("embedded_resource_count")!="1"||route->fields.at("embedded_resource_bytes")!="64")return 8;
    if(route->ranges.size()!=1||route->ranges.front().coordinate_space!=prts::CoordinateSpace::FILE_OFFSET||route->ranges.front().offset!=0x380)return 9;

    prts::DotNetInfo context;context.valid=true;context.member_refs={member(0x0a000020,"System.Resources.ResourceManager","GetObject"),member(0x0a000021,"System.Runtime.Loader.AssemblyLoadContext","LoadFromStream")};
    const auto context_route=prts::dotnet_resource_loader_finding(context);
    if(!context_route||context_route->variant!="UNRESOLVED_RESOURCE_TO_ASSEMBLY_LOAD_CONTEXT"||context_route->state!="SUSPECTED")return 10;
    if(context_route->fields.at("assembly_load_context_refs")!="1"||context_route->fields.at("resource_scope")!="UNRESOLVED")return 11;

    prts::DotNetInfo ordinary;ordinary.valid=true;
    ordinary.member_refs={member(0x0a000010,"System.String","Concat"),member(0x0a000011,"System.Reflection.Assembly","GetName")};
    prts::DotNetMethod benign;benign.token=0x06000010;benign.pinvoke=true;benign.import_module="user32.dll";benign.import_name="MessageBoxW";ordinary.methods.push_back(benign);
    if(prts::dotnet_dynamic_surface_finding(ordinary))return 6;
    if(prts::dotnet_resource_loader_finding(ordinary))return 12;

    std::cout<<"PASS\n";
    return 0;
}
