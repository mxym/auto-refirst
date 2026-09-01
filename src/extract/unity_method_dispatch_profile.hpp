#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace prts {
struct UnityPre108MethodDispatchValidation {
    bool valid=false;
    std::uint32_t invoker_resolved=0,invoker_missing=0;
    std::string error;
};
inline bool unity_pre108_method_dispatch_profile_supported(int metadata_version,std::string_view normalized_variant) {
    return (metadata_version==106||metadata_version==107) &&
           (normalized_variant=="106"||normalized_variant=="106.1");
}
inline UnityPre108MethodDispatchValidation validate_unity_pre108_method_dispatch_tables(
    int metadata_version,std::string_view normalized_variant,
    std::span<const std::uint32_t> method_tokens,std::uint32_t module_method_pointer_count,
    std::span<const std::int32_t> invoker_indices,std::uint32_t global_invoker_count,
    std::span<const std::uint32_t> adjustor_tokens) {
    UnityPre108MethodDispatchValidation out;
    if(!unity_pre108_method_dispatch_profile_supported(metadata_version,normalized_variant)) {
        out.error="unsupported pre-v108 method-dispatch profile";return out;
    }
    if(module_method_pointer_count!=method_tokens.size()||invoker_indices.size()!=method_tokens.size()) {
        out.error="module method/invoker table count differs from image-local MethodDef count";return out;
    }
    for(std::size_t i=0;i<method_tokens.size();++i) {
        const auto expect=0x06000000u|static_cast<std::uint32_t>(i+1);
        if(method_tokens[i]!=expect) {out.error="image-local MethodDef tokens are not dense RID order";return out;}
        const auto ii=invoker_indices[i];
        if(ii==-1)++out.invoker_missing;
        else if(ii>=0&&static_cast<std::uint32_t>(ii)<global_invoker_count)++out.invoker_resolved;
        else {out.error="module invoker index is outside global invoker table";return out;}
    }
    std::uint32_t prev=0;
    for(std::size_t i=0;i<adjustor_tokens.size();++i) {
        const auto tok=adjustor_tokens[i];
        const auto rid=tok&0x00ffffffu;
        if((tok&0xff000000u)!=0x06000000u||!rid||rid>method_tokens.size()) {
            out.error="adjustor thunk token has no image-local MethodDef owner";return out;
        }
        if(i&&tok<=prev) {out.error="adjustor thunk tokens are not strictly increasing";return out;}
        if(method_tokens[rid-1]!=tok) {out.error="adjustor thunk token does not match MethodDef RID";return out;}
        prev=tok;
    }
    out.valid=true;return out;
}
}
