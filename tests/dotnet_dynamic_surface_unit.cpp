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

    prts::DotNetInfo ordinary;ordinary.valid=true;
    ordinary.member_refs={member(0x0a000010,"System.String","Concat"),member(0x0a000011,"System.Reflection.Assembly","GetName")};
    prts::DotNetMethod benign;benign.token=0x06000010;benign.pinvoke=true;benign.import_module="user32.dll";benign.import_name="MessageBoxW";ordinary.methods.push_back(benign);
    if(prts::dotnet_dynamic_surface_finding(ordinary))return 6;

    std::cout<<"PASS\n";
    return 0;
}
