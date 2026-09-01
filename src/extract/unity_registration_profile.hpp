#pragma once
#include "prts/pe.hpp"
#include "unity_engine_version.hpp"
#include <cstdint>
#include <span>
#include <string>

namespace prts {
enum class UnityMetadataRegistrationTailEvidence {
    NotApplicable,
    NotFileBacked,
    ZeroPair,
    StrongExtended,
    Unresolved,
};
enum class UnityMetadataRegistrationEngineHint {
    None,
    Traditional106,
    Extended1061,
};
struct UnityMetadataRegistrationProfileDecision {
    std::string state="UNSUPPORTED",profile,normalized_variant,engine_hint,detail;
    std::uint32_t role_count=0;
    bool include_always_init=false;
};
struct UnityMetadataRegistrationTailProbe {
    UnityMetadataRegistrationTailEvidence evidence=UnityMetadataRegistrationTailEvidence::NotApplicable;
    std::uint64_t count=0,pointer_va=0;
    std::string detail;
};
UnityMetadataRegistrationEngineHint unity_metadata_registration_engine_hint(
    int declared_version,const UnityEngineVersionValue& engine_version);
UnityMetadataRegistrationProfileDecision decide_unity_metadata_registration_profile(
    int declared_version, UnityMetadataRegistrationTailEvidence tail_evidence,
    UnityMetadataRegistrationEngineHint engine_hint=UnityMetadataRegistrationEngineHint::None);
std::string unity_code_registration_layout_profile(int declared_version);
bool unity_validate_1061_always_init_encoded_slots(
    std::span<const std::uint32_t> encoded_slots, std::uint64_t type_count,
    std::uint64_t method_count, std::uint64_t string_count, std::uint64_t method_spec_count);
UnityMetadataRegistrationTailProbe probe_unity_metadata_registration_tail(
    std::span<const std::uint8_t> image, const PeInfo& pe, std::uint64_t tail_va,
    std::uint64_t type_count, std::uint64_t method_count,
    std::uint64_t string_count, std::uint64_t method_spec_count);
}
