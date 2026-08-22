#pragma once

#include "prts/pe.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts {

struct GDExtensionLibraryDecl {
    std::string feature_key;
    std::string path;
    std::size_t line = 0;
};

struct GDExtensionDescriptorInfo {
    bool candidate = false;
    bool valid = false;
    std::string state = "FAILED";
    std::string entry_symbol;
    std::string compatibility_minimum;
    bool reloadable = false;
    bool reloadable_present = false;
    std::vector<GDExtensionLibraryDecl> libraries;
    std::string error;
    std::size_t error_line = 0;
};

struct GDExtensionApiSlotInfo {
    std::string api_name;
    std::uint32_t resolver_function_rva = 0;
    std::uint32_t resolve_call_rva = 0;
    std::uint64_t storage_va = 0;
    std::uint32_t storage_rva = 0;
    bool storage_writable = false;
    bool storage_file_backed = false;
    std::uint64_t storage_file_offset = 0;
};

struct GDExtensionBridgeTargetInfo {
    std::uint64_t va = 0;
    std::uint32_t rva = 0;
    std::string source;
};

struct GDExtensionMethodRegistrationInfo {
    std::string evidence_state = "UNRESOLVED_REGISTRATION";
    std::uint32_t registration_function_rva = 0;
    std::uint32_t registration_call_rva = 0;
    std::string class_name;
    std::string method_name;
    std::uint32_t method_flags = 0;
    bool method_flags_known = false;
    bool has_return_value = false;
    bool has_return_value_known = false;
    std::uint32_t return_value_metadata = 0;
    bool return_value_metadata_known = false;
    std::uint32_t return_variant_type = 0;
    bool return_variant_type_known = false;
    std::string return_variant_type_name;
    std::uint32_t argument_count = 0;
    bool argument_count_known = false;
    bool argument_types_complete = false;
    bool argument_metadata_complete = false;
    std::vector<std::uint32_t> argument_variant_types;
    std::vector<std::string> argument_variant_type_names;
    std::vector<std::uint32_t> argument_metadata;
    std::uint32_t default_argument_count = 0;
    bool default_argument_count_known = false;
    std::uint64_t method_userdata_va = 0;
    bool method_userdata_known = false;
    std::uint64_t call_func_va = 0;
    bool call_func_known = false;
    std::uint64_t ptrcall_func_va = 0;
    bool ptrcall_func_known = false;
    std::vector<GDExtensionBridgeTargetInfo> bridge_candidates;
    std::string detail;
};

struct GDExtensionClassRegistrationInfo {
    std::string evidence_state = "UNRESOLVED_REGISTRATION";
    std::uint32_t registration_function_rva = 0;
    std::uint32_t registration_call_rva = 0;
    std::string class_name;
    std::string parent_class_name;
};

struct GDExtensionNativeInfo {
    bool candidate = false;
    bool valid = false;
    std::string state = "UNRESOLVED_REGISTRATION";
    std::string architecture;
    std::string entry_symbol;
    std::uint32_t entry_rva = 0;
    bool entry_export_validated = false;
    bool get_proc_relationship_validated = false;
    std::uint32_t resolver_function_rva = 0;
    std::size_t reachable_function_count = 0;
    std::vector<GDExtensionApiSlotInfo> api_slots;
    std::vector<GDExtensionClassRegistrationInfo> classes;
    std::vector<GDExtensionMethodRegistrationInfo> methods;
    std::string error;
};

struct GDExtensionPckChildView {
    std::string path;
    std::span<const std::uint8_t> data;
    std::size_t entry_index = 0;
    bool validated = false;
};

struct GDExtensionLibraryMatchInfo {
    std::string feature_key;
    std::string declared_path;
    std::string normalized_declared_path;
    std::string matched_child_path;
    std::size_t matched_entry_index = 0;
    bool exact_path_match = false;
    bool child_validated = false;
    bool native_analyzed = false;
    std::string native_format;
    std::string state = "MISSING_DECLARED_LIBRARY";
    GDExtensionNativeInfo native;
    std::string error;
};

struct GDExtensionBundleInfo {
    bool valid = false;
    std::string state = "UNRESOLVED_REGISTRATION";
    std::string descriptor_path;
    std::size_t descriptor_entry_index = 0;
    bool descriptor_child_validated = false;
    GDExtensionDescriptorInfo descriptor;
    std::size_t exact_library_match_count = 0;
    std::size_t analyzed_native_count = 0;
    std::vector<GDExtensionLibraryMatchInfo> libraries;
    std::string error;
};

std::optional<std::string> normalize_gdextension_resource_path(std::string_view input);
bool gdextension_pe64_x64_feature_compatible(std::string_view feature_key);
GDExtensionDescriptorInfo parse_gdextension_descriptor(std::span<const std::uint8_t> data);
GDExtensionNativeInfo analyze_gdextension_pe(std::span<const std::uint8_t> data,
                                             const PeInfo& pe,
                                             const GDExtensionDescriptorInfo& descriptor);
GDExtensionBundleInfo analyze_gdextension_pck_bundle(const GDExtensionPckChildView& descriptor_child,
                                                        std::span<const GDExtensionPckChildView> children);

} // namespace prts
