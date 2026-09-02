#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace prts {
enum class UnityGenericClassLayoutProfile {
    Context32,
    Compact24,
};

inline std::optional<UnityGenericClassLayoutProfile> unity_generic_class_layout_profile(
    int metadata_version,std::string_view normalized_variant) {
    if(metadata_version<23||metadata_version>108)return {};
    if(metadata_version==108)return UnityGenericClassLayoutProfile::Compact24;
    if(metadata_version==106||metadata_version==107) {
        if(normalized_variant=="106")return UnityGenericClassLayoutProfile::Context32;
        if(normalized_variant=="106.1")return UnityGenericClassLayoutProfile::Compact24;
        return {};
    }
    return UnityGenericClassLayoutProfile::Context32;
}

inline std::uint32_t unity_generic_class_record_size(UnityGenericClassLayoutProfile profile) {
    return profile==UnityGenericClassLayoutProfile::Compact24?24u:32u;
}
inline std::uint32_t unity_generic_class_cached_class_offset(UnityGenericClassLayoutProfile profile) {
    return profile==UnityGenericClassLayoutProfile::Compact24?16u:24u;
}
inline bool unity_generic_class_has_method_inst(UnityGenericClassLayoutProfile profile) {
    return profile==UnityGenericClassLayoutProfile::Context32;
}
inline const char* unity_generic_class_layout_profile_name(UnityGenericClassLayoutProfile profile) {
    return profile==UnityGenericClassLayoutProfile::Compact24?"class-inst-24":"context-32";
}
}
