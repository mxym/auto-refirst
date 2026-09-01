#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

namespace prts {
enum class UnityMetadataUsageKindProfile {
    Traditional,
    Compact,
};
enum class UnityMetadataUsageIndexProfile {
    Direct,
    RuntimeToken,
};
struct UnityMetadataUsageDecoded {
    bool valid=false;
    std::uint32_t raw_kind=0,kind=0,source_index=0;
    bool low_bit_set=false;
};
struct UnityEncodedMethodDecoded {
    bool valid=false,invalid_usage=false;
    std::uint32_t raw_kind=0,kind=0,source_index=0;
    bool low_bit_set=false;
};
std::optional<UnityMetadataUsageKindProfile> unity_metadata_usage_kind_profile(
    int metadata_version,std::string_view normalized_variant);
std::uint32_t unity_metadata_usage_runtime_kind_compare_limit(UnityMetadataUsageKindProfile profile);
UnityMetadataUsageDecoded decode_unity_metadata_usage(
    std::uint32_t encoded, UnityMetadataUsageKindProfile kind_profile,
    UnityMetadataUsageIndexProfile index_profile);
UnityEncodedMethodDecoded decode_unity_encoded_method(
    std::uint32_t encoded,UnityMetadataUsageKindProfile kind_profile);
const char* unity_encoded_method_invalid_name(std::uint32_t source_index);
const char* unity_metadata_usage_kind_name(std::uint32_t kind);
}
