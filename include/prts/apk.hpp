#pragma once
#include "prts/finding.hpp"
#include "prts/godot.hpp"
#include "prts/implicit_exec.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct ApkManifestComponent {
    std::string kind;
    std::string name;
    std::string process;
    bool exported_known = false;
    bool exported = false;
    bool exported_reference = false;
    std::uint32_t exported_reference_id = 0;
};

struct ApkManifestInfo {
    bool candidate = false;
    bool valid = false;
    bool parse_complete = false;
    bool string_pool_utf8 = false;
    std::uint32_t string_count = 0;
    std::uint32_t resource_id_count = 0;
    std::uint32_t start_element_count = 0;
    std::string package_name;
    std::string version_name;
    std::string application_name;
    bool version_code_known = false;
    std::uint32_t version_code = 0;
    bool min_sdk_known = false;
    std::uint32_t min_sdk = 0;
    bool target_sdk_known = false;
    std::uint32_t target_sdk = 0;
    bool debuggable_known = false;
    bool debuggable = false;
    bool debuggable_reference = false;
    bool debuggable_reference_resolved = false;
    std::uint32_t debuggable_reference_id = 0;
    std::vector<std::string> permissions;
    std::vector<ApkManifestComponent> components;
    std::vector<std::string> anomalies;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct ApkResourceTableInfo {
    bool candidate = false;
    bool valid = false;
    bool parse_complete = false;
    std::uint32_t declared_package_count = 0;
    std::uint32_t parsed_package_count = 0;
    std::uint32_t type_spec_count = 0;
    std::uint32_t type_config_count = 0;
    std::uint32_t default_scalar_count = 0;
    std::uint32_t complex_entry_count = 0;
    std::uint32_t nondefault_config_count = 0;
    std::vector<std::string> package_names;
    std::vector<std::string> anomalies;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct ApkEntryInfo {
    std::uint32_t index = 0;
    std::string name;
    std::string normalized_name;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint32_t crc32 = 0;
    std::uint16_t method = 0;
    std::uint16_t flags = 0;
    std::uint64_t local_header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t central_directory_offset = 0;
    bool directory = false;
    bool encrypted = false;
    bool supported = false;
    bool safe_path = false;
    bool symlink = false;
    bool duplicate_path = false;
    bool manifest = false;
    bool manifest_binary_xml = false;
    bool dex = false;
    bool dex_magic = false;
    std::string dex_deep_state = "NOT_ATTEMPTED";
    std::string dex_deep_error;
    std::uint32_t dex_native_declaration_count = 0;
    std::uint32_t dex_load_library_count = 0;
    bool resources_arsc = false;
    bool resources_table = false;
    bool native_library = false;
    bool native_elf = false;
    bool godot_legacy_engine_config_candidate = false;
    bool godot_legacy_engine_config_valid = false;
    std::string godot_legacy_engine_config_error;
    bool unity_il2cpp_metadata_candidate = false;
    bool unity_il2cpp_metadata_valid = false;
    bool unity_il2cpp_metadata_parse_skipped_budget = false;
    std::int32_t unity_il2cpp_metadata_version = 0;
    std::string unity_il2cpp_metadata_layout;
    std::string unity_il2cpp_metadata_error;
    bool hermes_magic = false;
    bool hermes_integrity_valid = false;
    bool hermes_probe_skipped_budget = false;
    bool hermes_supported_epoch = false;
    bool hermes_valid = false;
    bool hermes_parse_complete = false;
    std::uint32_t hermes_version = 0;
    std::string hermes_sha256;
    std::string hermes_error;
    std::string native_deep_state = "NOT_ATTEMPTED";
    std::string native_deep_error;
    std::string native_dynamic_state;
    std::string native_dynamic_error;
    std::string native_unwind_state;
    std::string native_unwind_error;
    std::uint16_t native_machine = 0;
    bool native_elf64 = false;
    bool native_abi_consistent_known = false;
    bool native_abi_consistent = false;
    std::uint32_t native_import_count = 0;
    std::uint32_t native_export_count = 0;
    std::uint64_t native_relocation_count = 0;
    std::uint64_t native_fde_count = 0;
    bool native_jni_evidence_limited = false;
    std::string native_jni_evidence_error;
    bool jni_onload_export = false;
    std::uint32_t jni_onload_symbol_index = 0;
    std::uint64_t jni_onload_symbol_file_offset = 0;
    std::uint64_t jni_onload_va = 0;
    bool jni_onload_file_backed = false;
    std::uint64_t jni_onload_file_offset = 0;
    bool asset = false;
    bool resource = false;
    bool v1_signature_file = false;
    bool nested_archive = false;
    std::uint8_t analysis_priority = 0;
    std::string abi;
};

struct ApkJniRelation {
    std::uint32_t index = 0;
    std::string state;
    std::string evidence_level;
    std::string dex_entry;
    std::string native_entry;
    std::string abi;
    std::string library_name;
    std::string class_descriptor;
    std::string method_name;
    std::string method_descriptor;
    std::string jni_symbol;
    bool packaged = false;
    bool load_library_referenced = false;
    bool native_declared = false;
    bool exported = false;
    bool registration_confirmed = false;
    bool abi_consistent = false;
    bool fde_boundary_confirmed = false;
    std::uint32_t dex_method_index = 0;
    std::uint64_t dex_load_instruction_offset = 0;
    std::uint32_t elf_symbol_index = 0;
    std::uint64_t function_va = 0;
    std::uint64_t function_file_offset = 0;
    std::uint64_t function_end_va = 0;
    std::string detail;
};

struct ApkSigningBlockPair {
    std::uint32_t id = 0;
    std::uint64_t value_size = 0;
    std::uint64_t pair_offset = 0;
    std::string label;
};

struct ApkSigningBlockInfo {
    bool present = false;
    bool valid = false;
    bool cryptographic_verification_performed = false;
    bool has_v2 = false;
    bool has_v3 = false;
    bool has_v31 = false;
    bool has_v32 = false;
    bool has_source_stamp_v1 = false;
    bool has_source_stamp_v2 = false;
    bool has_verity_padding = false;
    bool has_unknown_pairs = false;
    std::uint64_t block_offset = 0;
    std::uint64_t block_size = 0;
    std::vector<ApkSigningBlockPair> pairs;
    std::vector<std::string> anomalies;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct ApkInfo {
    bool candidate = false;
    bool valid = false;
    bool zip_valid = false;
    bool zip64 = false;
    bool has_manifest = false;
    bool manifest_binary_xml = false;
    bool has_resources_arsc = false;
    bool resources_table_valid = false;
    bool has_v1_signature_files = false;
    bool has_duplicate_paths = false;
    bool manifest_path_ambiguous = false;
    bool resources_path_ambiguous = false;
    bool dex_path_ambiguous = false;
    bool anomaly_samples_truncated = false;
    std::uint32_t entry_count = 0;
    std::uint32_t unsafe_path_count = 0;
    std::uint32_t symlink_entry_count = 0;
    std::uint32_t encrypted_entry_count = 0;
    std::uint32_t unsupported_entry_count = 0;
    std::uint32_t duplicate_path_entry_count = 0;
    std::uint32_t invalid_dex_entry_count = 0;
    std::uint32_t invalid_native_entry_count = 0;
    std::uint32_t dex_count = 0;
    std::uint32_t validated_dex_count = 0;
    std::uint32_t native_library_count = 0;
    std::uint32_t validated_native_elf_count = 0;
    std::uint32_t deep_native_elf_count = 0;
    std::uint32_t native_dynamic_resolved_count = 0;
    std::uint32_t native_unwind_resolved_count = 0;
    std::uint32_t native_jni_onload_count = 0;
    std::uint32_t native_abi_mismatch_count = 0;
    std::uint32_t native_deep_skipped_budget_count = 0;
    std::uint32_t dex_deep_resolved_count = 0;
    std::uint32_t dex_deep_partial_count = 0;
    std::uint32_t jni_packaged_count = 0;
    std::uint32_t jni_referenced_count = 0;
    std::uint32_t jni_declared_count = 0;
    std::uint32_t jni_exported_count = 0;
    std::uint32_t jni_registration_confirmed_count = 0;
    bool jni_relations_limited = false;
    std::string jni_relations_state = "NOT_PRESENT";
    std::string jni_relations_error;
    std::uint32_t godot_legacy_engine_config_candidate_count = 0;
    std::uint32_t godot_legacy_engine_config_valid_count = 0;
    GodotLegacyEngineConfigInfo godot_legacy_config;
    std::uint32_t unity_il2cpp_metadata_candidate_count = 0;
    std::uint32_t unity_il2cpp_metadata_valid_count = 0;
    std::uint32_t unity_il2cpp_metadata_parse_count = 0;
    bool unity_il2cpp_metadata_parse_budget_exhausted = false;
    std::uint64_t unity_il2cpp_metadata_parse_bytes = 0;
    std::uint32_t hermes_probe_entry_count = 0;
    std::uint32_t hermes_magic_count = 0;
    std::uint32_t hermes_integrity_valid_count = 0;
    std::uint32_t hermes_supported_epoch_count = 0;
    std::uint32_t hermes_parse_complete_count = 0;
    std::uint32_t hermes_integrity_failure_count = 0;
    std::uint32_t hermes_probe_skipped_budget_count = 0;
    bool hermes_probe_budget_exhausted = false;
    std::uint64_t hermes_probe_validated_bytes = 0;
    std::uint64_t native_import_count = 0;
    std::uint64_t native_export_count = 0;
    std::uint64_t native_relocation_count = 0;
    std::uint64_t native_fde_count = 0;
    std::uint32_t asset_count = 0;
    std::uint32_t resource_count = 0;
    std::uint32_t nested_archive_count = 0;
    std::uint64_t total_compressed = 0;
    std::uint64_t total_uncompressed = 0;
    std::uint64_t extractable_bytes = 0;
    std::uint64_t extractable_files = 0;
    std::uint64_t analysis_candidate_bytes = 0;
    std::uint64_t analysis_candidate_files = 0;
    std::uint64_t central_directory_offset = 0;
    std::vector<std::string> dex_entries;
    std::vector<std::string> native_abis;
    std::vector<std::string> interesting_entries;
    std::vector<std::string> anomalies;
    std::vector<ApkEntryInfo> entries;
    std::vector<ApkJniRelation> jni_relations;
    ApkManifestInfo manifest;
    ApkResourceTableInfo resource_table;
    ApkSigningBlockInfo signing_block;
    ImplicitExecutionInfo implicit_exec;
    std::string error;
};

struct ApkExtractResult {
    bool success = false;
    bool budget_exhausted = false;
    bool analysis_only = false;
    std::filesystem::path output_dir;
    std::uint64_t file_count = 0;
    std::uint64_t output_bytes = 0;
    std::vector<std::filesystem::path> files;
    std::vector<std::string> warnings;
    std::string error;
};

ApkInfo detect_apk(std::span<const std::uint8_t> data);
Finding apk_finding(const ApkInfo& info);
ApkExtractResult extract_apk(std::span<const std::uint8_t> data,
                             const ApkInfo& info,
                             const std::filesystem::path& output_dir,
                             std::uint64_t max_output_bytes,
                             std::uint64_t max_files,
                             bool analysis_only = false);

}  // namespace prts
