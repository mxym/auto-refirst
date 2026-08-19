#pragma once
#include "prts/finding.hpp"
#include "prts/gdextension.hpp"
#include "prts/pe.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct GodotPckEntry {
    std::string path;
    std::uint64_t offset=0,size=0;
    std::array<std::uint8_t,16> md5{};
    std::uint32_t flags=0;
    bool encrypted=false,removal=false,delta=false;
};
// Stable identity supplied by the caller.  Path/stem proximity is never used as
// semantic evidence; sha256 is carried only as provenance for an already chosen
// concrete artifact.
struct GodotArtifactIdentity {
    std::filesystem::path path;
    std::string sha256;
};

struct GodotNativeKeySourceCoordinate {
    std::string anchor;
    std::uint64_t anchor_va=0;
    std::uint64_t load_va=0;
    std::uint64_t key_va=0;
};

// One distinct 256-bit value.  Multiple independently recovered coordinates for
// the same value are retained rather than silently deduplicated; this lets the
// semantic producer distinguish value uniqueness from source-coordinate
// uniqueness.
struct GodotNativeKeyCandidate {
    std::array<std::uint8_t,32> key{};
    GodotArtifactIdentity source;
    std::vector<GodotNativeKeySourceCoordinate> coordinates;
    std::vector<std::string> evidence;
    std::optional<double> confidence;
};

struct GodotNativeKeyCandidateSet {
    std::vector<GodotNativeKeyCandidate> candidates;
    std::size_t discovered_coordinate_count=0;
    std::size_t discovered_distinct_value_count=0;
    bool budget_exhausted=false;
};

// Key-free, exact-target inspection.  The external producer deliberately does
// not search siblings or infer a target from a filename: the caller supplies one
// exact PCK byte stream and identity.
struct GodotExternalPckInspection {
    bool valid=false;
    GodotArtifactIdentity target;
    std::uint64_t pck_offset=0;
    std::uint64_t directory_stream_offset=0;
    std::uint32_t format_version=0;
    std::uint32_t engine_major=0,engine_minor=0,engine_patch=0;
    std::uint32_t flags=0,file_count=0;
    bool encrypted_directory=false;
    bool relative_filebase=false;
    bool sparse_bundle=false;
    std::string target_coordinate;
    std::vector<std::string> evidence;
    std::string error;
};

struct GodotKeyInfo {
    // `confirmed` is intentionally only the internal "safe to use for pack decryption" gate.
    // Product evidence is split below; in particular DIRECTORY_KEY_VALIDATED is not
    // KEY_VALIDATED_FOR_SCRIPT.
    bool found=false,confirmed=false;
    bool directory_validated=false;
    bool encrypted_file_validated=false;
    bool script_validated=false;
    bool candidate_budget_exhausted=false;
    bool script_validation_truncated=false;
    std::size_t native_candidate_count=0;
    std::size_t candidate_validation_attempts=0;
    std::size_t encrypted_probe_count=0;
    std::size_t encrypted_script_count=0;
    std::size_t validated_script_count=0;
    std::array<std::uint8_t,32> key{};
    std::string anchor;
    std::string validated_script_path;
    std::uint64_t anchor_va=0,load_va=0,key_va=0;
    std::optional<double> confidence;
};
inline std::string godot_key_state(const GodotKeyInfo& key) {
    if (!key.found) return "ABSENT";
    if (key.script_validated) return "KEY_VALIDATED_FOR_SCRIPT";
    if (key.directory_validated) return "DIRECTORY_KEY_VALIDATED";
    if (key.encrypted_file_validated) return "ENCRYPTED_FILE_KEY_VALIDATED";
    return "KEY_CANDIDATE";
}

struct GodotGDExtensionScriptLinkInfo {
    std::string state = "EXACT_SCRIPT_REGISTRATION_LINK";
    std::string script_path;
    std::size_t script_entry_index = 0;
    std::string analysis_set_id;
    std::string base_class;
    std::string method_name;
    std::size_t extends_keyword_token_index = 0;
    std::size_t extends_identifier_token_index = 0;
    std::size_t super_token_index = 0;
    std::size_t method_identifier_token_index = 0;
    std::uint32_t effective_line = 0;
    bool effective_line_known = false;
    std::string descriptor_path;
    std::string library_path;
    std::string registration_state;
    std::uint32_t registration_call_rva = 0;
    std::size_t bridge_candidate_count = 0;
};

struct GodotPckInfo {
    bool valid=false,validated=false,modified_magic=false;
    std::uint64_t pck_offset=0,file_base=0,dir_offset=0;
    std::uint32_t format_version=0,engine_major=0,engine_minor=0,engine_patch=0,flags=0,file_count=0;
    bool encrypted_directory=false,relative_filebase=false,sparse_bundle=false;
    std::vector<GodotPckEntry> entries;
    GodotKeyInfo key;
    std::string gdextension_state = "NOT_PRESENT";
    std::size_t gdextension_descriptor_candidates = 0;
    std::size_t gdextension_descriptor_processed = 0;
    std::size_t gdextension_script_candidate_count = 0;
    std::uint64_t gdextension_script_candidate_bytes = 0;
    bool gdextension_analysis_limited = false;
    std::size_t gdextension_bundle_valid_count = 0;
    std::size_t gdextension_native_analyzed_count = 0;
    std::size_t gdextension_exact_registration_count = 0;
    std::size_t gdextension_bounded_bridge_count = 0;
    std::size_t gdextension_unresolved_count = 0;
    std::size_t gdextension_failed_count = 0;
    std::size_t gdextension_script_analysis_count = 0;
    std::size_t gdextension_super_call_count = 0;
    std::size_t gdextension_script_link_ambiguous_count = 0;
    std::vector<GDExtensionBundleInfo> gdextensions;
    std::vector<GodotGDExtensionScriptLinkInfo> gdextension_script_links;
    std::vector<std::string> evidence;
    std::string error;
};
struct GodotExternalPckCandidateValidation {
    bool target_valid=false;
    bool validated=false;
    std::size_t candidate_index=0;
    std::array<std::uint8_t,32> key{};
    bool directory_md5_validated=false;
    bool directory_structure_validated=false;
    std::size_t encrypted_file_probe_count=0;
    std::size_t encrypted_file_validated_count=0;
    std::size_t encrypted_script_count=0;
    std::size_t encrypted_script_validated_count=0;
    std::string validated_script_path;
    std::optional<std::size_t> validated_script_entry_index;
    std::string validated_script_target_coordinate;
    std::string target_coordinate;
    GodotPckInfo pack;
    std::vector<std::string> evidence;
    std::string error;
};

struct GodotExternalPckValidation {
    bool target_valid=false;
    bool resolved=false;
    bool value_unique=false;
    bool source_coordinate_ambiguous=false;
    bool candidate_budget_exhausted=false;
    std::size_t validation_attempts=0;
    std::size_t matching_candidate_count=0; // distinct key values
    std::size_t matching_source_coordinate_count=0;
    std::array<std::uint8_t,32> validated_key{};
    GodotArtifactIdentity source;
    GodotArtifactIdentity target;
    GodotNativeKeyCandidate validated_candidate;
    GodotPckInfo pack;
    bool directory_md5_validated=false;
    bool directory_structure_validated=false;
    std::size_t encrypted_file_probe_count=0;
    std::size_t encrypted_file_validated_count=0;
    std::size_t encrypted_script_count=0;
    std::size_t encrypted_script_validated_count=0;
    std::string validated_script_path;
    std::optional<std::size_t> validated_script_entry_index;
    std::string validated_script_target_coordinate;
    std::string source_coordinate;
    std::string target_coordinate;
    std::vector<std::size_t> matching_candidate_indices;
    std::vector<std::string> evidence;
    std::vector<std::string> ambiguity_reasons;
    std::string error;
};

struct GodotExternalPckMaterializedChild {
    std::size_t entry_index=0;
    std::string entry_path;
    std::filesystem::path output_path;
    std::string sha256;
    std::string target_coordinate;
    std::string validation_state;
    bool encrypted=false;
    bool script=false;
    std::string analysis_priority="HIGH";
};

struct GodotExternalPckMaterializeResult {
    bool success=false;
    bool budget_exhausted=false;
    std::filesystem::path output_dir;
    std::vector<GodotExternalPckMaterializedChild> children;
    std::uint64_t output_bytes=0;
    std::size_t omitted_count=0;
    std::uint64_t omitted_bytes=0;
    std::vector<std::string> warnings;
    std::string error;
};

struct GodotExtractResult {
    bool success=false,core_only=false,budget_exhausted=false;
    std::filesystem::path output_dir;
    std::vector<std::filesystem::path> files;
    std::uint64_t output_bytes=0,omitted_count=0,omitted_bytes=0;
    std::size_t script_analysis_count=0;
    std::size_t script_artifact_count=0;
    std::size_t script_analysis_failures=0;
    std::vector<std::string> warnings;
    std::string error;
};
GodotNativeKeyCandidateSet discover_godot_native_key_candidates(
    std::span<const std::uint8_t> source_data,
    const PeInfo& source_pe,
    GodotArtifactIdentity source_identity={});
GodotExternalPckInspection inspect_godot_external_pck(
    std::span<const std::uint8_t> target_data,
    GodotArtifactIdentity target_identity={});
GodotExternalPckCandidateValidation validate_godot_key_candidate_against_pck(
    std::span<const std::uint8_t> target_data,
    const GodotExternalPckInspection& inspection,
    const GodotNativeKeyCandidate& candidate,
    std::size_t candidate_index=0);
GodotExternalPckValidation reduce_godot_external_pck_validations(
    const GodotExternalPckInspection& inspection,
    const GodotNativeKeyCandidateSet& candidates,
    std::span<const GodotExternalPckCandidateValidation> validations);
GodotExternalPckValidation validate_godot_key_candidates_against_pck(
    std::span<const std::uint8_t> target_data,
    const GodotExternalPckInspection& inspection,
    const GodotNativeKeyCandidateSet& candidates);
GodotExternalPckMaterializeResult materialize_godot_external_pck_core(
    std::span<const std::uint8_t> target_data,
    const GodotExternalPckValidation& validation,
    const std::filesystem::path& output_dir,
    std::uint64_t max_output_bytes=64ull*1024*1024,
    std::uint32_t max_output_files=256);

GodotPckInfo detect_godot(std::span<const std::uint8_t> data,const PeInfo& pe);
void analyze_godot_gdextensions(std::span<const std::uint8_t> data,GodotPckInfo& info);
GodotExtractResult extract_godot(std::span<const std::uint8_t> data,const GodotPckInfo& info,const std::filesystem::path& output_dir,bool materialize_script_analysis=false,bool core_only=false,std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000);
Finding godot_finding(const GodotPckInfo& info);
Finding godot_gdextension_finding(const GodotPckInfo& info);
std::string godot_key_hex(const GodotKeyInfo& key);
}
