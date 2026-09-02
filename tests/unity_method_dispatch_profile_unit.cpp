#include "unity_method_dispatch_profile.hpp"
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
namespace { void need(bool ok,const char*msg){if(!ok){std::cerr<<msg<<'\n';std::exit(1);}} }
int main(){
    using namespace prts;
    need(unity_pre108_method_dispatch_profile_supported(106,"106"),"v106 traditional profile");
    need(unity_pre108_method_dispatch_profile_supported(106,"106.1"),"v106.1 normalized profile");
    need(unity_pre108_method_dispatch_profile_supported(107,"106"),"v107 backport profile");
    need(unity_pre108_method_dispatch_profile_supported(107,"106.1"),"v107 extended profile");
    need(!unity_pre108_method_dispatch_profile_supported(108,"108"),"v108 uses separate profile");
    const std::array<std::uint32_t,4> tokens{0x06000001u,0x06000002u,0x06000003u,0x06000004u};
    const std::array<std::int32_t,4> invokers{2,-1,0,4};
    const std::array<std::uint32_t,2> adjustors{0x06000002u,0x06000004u};
    auto ok=validate_unity_pre108_method_dispatch_tables(106,"106",tokens,4,invokers,5,adjustors);
    need(ok.valid&&ok.invoker_resolved==3&&ok.invoker_missing==1,"valid dispatch table");
    auto ext=validate_unity_pre108_method_dispatch_tables(107,"106.1",tokens,4,invokers,5,adjustors);
    need(ext.valid,"v107 normalized 106.1 shares dispatch layout");
    auto bad_count=validate_unity_pre108_method_dispatch_tables(106,"106",tokens,3,invokers,5,adjustors);need(!bad_count.valid,"method count mismatch rejected");
    auto gap=tokens;gap[2]=0x06000004u;auto bad_gap=validate_unity_pre108_method_dispatch_tables(106,"106",gap,4,invokers,5,adjustors);need(!bad_gap.valid,"token RID gap rejected");
    auto bad_inv=invokers;bad_inv[1]=5;auto inv=validate_unity_pre108_method_dispatch_tables(106,"106",tokens,4,bad_inv,5,adjustors);need(!inv.valid,"invoker overflow rejected");
    auto bad_adj=adjustors;bad_adj[0]=0x06000004u;bad_adj[1]=0x06000002u;auto adj_order=validate_unity_pre108_method_dispatch_tables(106,"106",tokens,4,invokers,5,bad_adj);need(!adj_order.valid,"adjustor order rejected");
    bad_adj=adjustors;bad_adj[1]=0x06000005u;auto adj_owner=validate_unity_pre108_method_dispatch_tables(106,"106",tokens,4,invokers,5,bad_adj);need(!adj_owner.valid,"adjustor owner rejected");
    std::cout<<"PASS\n";return 0;
}
