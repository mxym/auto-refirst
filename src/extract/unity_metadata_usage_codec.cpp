#include "unity_metadata_usage_codec.hpp"

namespace prts { namespace {
std::uint32_t logical_usage_kind(std::uint32_t raw,UnityMetadataUsageKindProfile profile) {
    if(profile==UnityMetadataUsageKindProfile::Compact&&raw>1)return raw+1;
    return raw;
}
}
std::optional<UnityMetadataUsageKindProfile> unity_metadata_usage_kind_profile(
    int metadata_version,std::string_view normalized_variant) {
    if(metadata_version==24||metadata_version==31)return UnityMetadataUsageKindProfile::Traditional;
    if(metadata_version==106||metadata_version==107) {
        if(normalized_variant=="106")return UnityMetadataUsageKindProfile::Traditional;
        if(normalized_variant=="106.1")return UnityMetadataUsageKindProfile::Compact;
        return {};
    }
    if(metadata_version==108)return UnityMetadataUsageKindProfile::Compact;
    return {};
}

std::uint32_t unity_metadata_usage_runtime_kind_compare_limit(UnityMetadataUsageKindProfile profile) {
    // The runtime shifts kind down by one before comparing against the largest valid enum value.
    return profile==UnityMetadataUsageKindProfile::Compact?5u:6u;
}

UnityMetadataUsageDecoded decode_unity_metadata_usage(
    std::uint32_t encoded, UnityMetadataUsageKindProfile kind_profile,
    UnityMetadataUsageIndexProfile index_profile) {
    UnityMetadataUsageDecoded out;
    out.raw_kind=(encoded>>29)&7u;
    out.kind=logical_usage_kind(out.raw_kind,kind_profile);
    out.low_bit_set=(encoded&1u)!=0;
    if(index_profile==UnityMetadataUsageIndexProfile::RuntimeToken) {
        if(!out.low_bit_set)return out;
        out.source_index=(encoded&0x1ffffffeu)>>1;
    } else {
        out.source_index=encoded&0x1fffffffu;
    }
    out.valid=out.kind>=1&&out.kind<=7;
    return out;
}

UnityEncodedMethodDecoded decode_unity_encoded_method(
    std::uint32_t encoded,UnityMetadataUsageKindProfile kind_profile) {
    UnityEncodedMethodDecoded out;
    out.raw_kind=(encoded>>29)&7u;
    out.kind=logical_usage_kind(out.raw_kind,kind_profile);
    out.source_index=(encoded&0x1ffffffeu)>>1;
    out.low_bit_set=(encoded&1u)!=0;
    if(out.kind==0) {
        out.invalid_usage=true;
        out.valid=out.source_index<=4; // Runtime recognizes InvalidMetadataUsageTokens 0..4.
    } else {
        out.valid=out.kind==3||out.kind==6;
    }
    return out;
}

const char* unity_encoded_method_invalid_name(std::uint32_t source_index) {
    switch(source_index) {
        case 0:return "NO_DATA";
        case 1:return "AMBIGUOUS_METHOD";
        case 2:return "AMBIGUOUS_STATIC_METHOD";
        case 3:return "ENTRY_POINT_NOT_FOUND";
        case 4:return "STATIC_ENTRY_POINT_NOT_FOUND";
        default:return "";
    }
}

const char* unity_metadata_usage_kind_name(std::uint32_t kind) {
    switch(kind) {
        case 1:return "TYPE_INFO";
        case 2:return "TYPE";
        case 3:return "METHOD_DEF";
        case 4:return "FIELD_INFO";
        case 5:return "STRING_LITERAL";
        case 6:return "METHOD_REF";
        case 7:return "FIELD_RVA";
        default:return "";
    }
}
}
