#include "unity_generic_class_profile.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

namespace {
void need(bool ok,const char* what) {
    if(!ok){std::cerr<<"FAIL: "<<what<<'\n';std::exit(1);}
}
}
int main() {
    using namespace prts;
    auto p24=unity_generic_class_layout_profile(24,"");
    auto p31=unity_generic_class_layout_profile(31,"");
    auto p106=unity_generic_class_layout_profile(106,"106");
    auto p1061=unity_generic_class_layout_profile(106,"106.1");
    auto p107=unity_generic_class_layout_profile(107,"106");
    auto p1071=unity_generic_class_layout_profile(107,"106.1");
    auto p108=unity_generic_class_layout_profile(108,"108");
    need(p24&&*p24==UnityGenericClassLayoutProfile::Context32,"v24 context-32");
    need(p31&&*p31==UnityGenericClassLayoutProfile::Context32,"v31 context-32");
    need(p106&&*p106==UnityGenericClassLayoutProfile::Context32,"normalized 106 context-32");
    need(p1061&&*p1061==UnityGenericClassLayoutProfile::Compact24,"normalized 106.1 compact-24");
    need(p107&&*p107==UnityGenericClassLayoutProfile::Context32,"v107 backport context-32");
    need(p1071&&*p1071==UnityGenericClassLayoutProfile::Compact24,"v107 forward compact-24");
    need(p108&&*p108==UnityGenericClassLayoutProfile::Compact24,"v108 compact-24");
    need(!unity_generic_class_layout_profile(106,"106|106.1"),"ambiguous v106 rejected");
    need(!unity_generic_class_layout_profile(107,""),"unresolved v107 rejected");
    need(!unity_generic_class_layout_profile(109,""),"post-v108 rejected");
    need(unity_generic_class_record_size(*p106)==32&&unity_generic_class_cached_class_offset(*p106)==24&&unity_generic_class_has_method_inst(*p106),"context-32 geometry");
    need(unity_generic_class_record_size(*p1061)==24&&unity_generic_class_cached_class_offset(*p1061)==16&&!unity_generic_class_has_method_inst(*p1061),"compact-24 geometry");
    need(std::string(unity_generic_class_layout_profile_name(*p106))=="context-32"&&std::string(unity_generic_class_layout_profile_name(*p1061))=="class-inst-24","profile names");
    std::cout<<"PASS\n";
}
