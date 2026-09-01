#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace prts {
enum class UnityModuleRgctxProfile {
    LegacyIndex8,
    TraditionalHandle16,
    CompactInline8,
};

inline std::optional<UnityModuleRgctxProfile> unity_module_rgctx_profile(
    int metadata_version,std::string_view normalized_variant) {
    if(metadata_version==24)return UnityModuleRgctxProfile::LegacyIndex8;
    if(metadata_version==31)return UnityModuleRgctxProfile::TraditionalHandle16;
    if(metadata_version==106||metadata_version==107) {
        if(normalized_variant=="106")return UnityModuleRgctxProfile::TraditionalHandle16;
        if(normalized_variant=="106.1")return UnityModuleRgctxProfile::CompactInline8;
    }
    return {};
}

inline std::uint32_t unity_module_rgctx_record_size(UnityModuleRgctxProfile profile) {
    return profile==UnityModuleRgctxProfile::TraditionalHandle16?16u:8u;
}

inline const char* unity_module_rgctx_profile_name(UnityModuleRgctxProfile profile) {
    switch(profile) {
        case UnityModuleRgctxProfile::LegacyIndex8:return "legacy-index-8";
        case UnityModuleRgctxProfile::TraditionalHandle16:return "modern-handle-16";
        case UnityModuleRgctxProfile::CompactInline8:return "compact-inline-8";
    }
    return "";
}

inline const char* unity_module_rgctx_kind_name(UnityModuleRgctxProfile profile,std::uint32_t kind) {
    if(profile==UnityModuleRgctxProfile::CompactInline8) {
        switch(kind) {
            case 1:return "TYPE";
            case 2:return "CLASS";
            case 3:return "METHOD";
            case 5:return "CONSTRAINED_CALL_TYPE";
            case 6:return "CONSTRAINED_CALL_METHOD";
            default:return ""; // ARRAY=4 exists in the enum but the 6000.6.0a6 runtime switch does not handle it.
        }
    }
    switch(kind) {
        case 1:return "TYPE";
        case 2:return "CLASS";
        case 3:return "METHOD";
        case 5:return "CONSTRAINED";
        default:return "";
    }
}
}
