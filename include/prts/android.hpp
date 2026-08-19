#pragma once
#include "prts/finding.hpp"
#include "prts/implicit_exec.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct DexMapItem {
    std::uint16_t type = 0;
    std::uint32_t size = 0;
    std::uint32_t offset = 0;
    std::string name;
};

struct DexProtoInfo {
    std::uint32_t index = 0;
    std::uint32_t shorty_idx = 0;
    std::uint32_t return_type_idx = 0;
    std::uint32_t parameters_off = 0;
    std::string shorty;
    std::string return_type;
    std::string signature;
    std::vector<std::string> parameter_types;
};

struct DexFieldInfo {
    std::uint32_t index = 0;
    std::uint16_t class_idx = 0;
    std::uint16_t type_idx = 0;
    std::uint32_t name_idx = 0;
    std::uint32_t access_flags = 0;
    bool defined = false;
    std::string owner;
    std::string name;
    std::string type;
    std::string signature;
};

struct DexMethodInfo {
    std::uint32_t index = 0;
    std::uint16_t class_idx = 0;
    std::uint16_t proto_idx = 0;
    std::uint32_t name_idx = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t code_off = 0;
    bool defined = false;
    std::string owner;
    std::string name;
    std::string signature;
};

struct DexMethodHandleInfo {
    std::uint32_t index = 0;
    std::uint16_t handle_type = 0;
    std::uint16_t field_or_method_id = 0;
    bool references_field = false;
    std::string target;
};

struct DexCallSiteInfo {
    std::uint32_t index = 0;
    std::uint32_t call_site_off = 0;
    std::uint32_t call_site_size = 0;
    std::uint32_t bootstrap_method_handle_idx = 0;
    std::uint32_t method_name_idx = 0;
    std::uint32_t method_type_idx = 0;
    std::uint32_t extra_argument_count = 0;
    std::string method_name;
    std::string method_type;
    std::string bootstrap_target;
};

struct DexCodeInfo {
    std::uint32_t method_idx = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t code_off = 0;
    std::uint16_t registers_size = 0;
    std::uint16_t ins_size = 0;
    std::uint16_t outs_size = 0;
    std::uint16_t tries_size = 0;
    std::uint32_t debug_info_off = 0;
    std::uint32_t insns_size = 0;
    std::uint32_t code_size_bytes = 0;
    std::uint32_t debug_line_start = 0;
    std::uint32_t debug_position_count = 0;
    std::vector<std::string> parameter_names;
};

struct DexClassInfo {
    std::uint32_t class_idx = 0;
    std::uint32_t access_flags = 0;
    std::uint32_t superclass_idx = 0xffffffffu;
    std::uint32_t interfaces_off = 0;
    std::uint32_t source_file_idx = 0xffffffffu;
    std::uint32_t class_data_off = 0;
    std::uint32_t static_values_off = 0;
    std::uint32_t static_field_count = 0;
    std::uint32_t instance_field_count = 0;
    std::uint32_t direct_method_count = 0;
    std::uint32_t virtual_method_count = 0;
    std::string name;
    std::string superclass;
    std::string source_file;
    std::vector<std::string> interfaces;
};

struct DexInfo {
    bool candidate = false;
    bool valid = false;
    bool reverse_endian = false;
    bool container_v41 = false;
    bool checksum_checked = false;
    bool checksum_matches = false;
    bool signature_checked = false;
    bool signature_matches = false;
    bool map_complete = false;
    bool descriptor_parse_complete = true;

    std::string version;
    std::uint32_t checksum = 0;
    std::uint32_t computed_checksum = 0;
    std::uint32_t file_size = 0;
    std::uint32_t header_size = 0;
    std::uint32_t link_size = 0;
    std::uint32_t link_off = 0;
    std::uint32_t map_off = 0;
    std::uint32_t string_ids_size = 0;
    std::uint32_t string_ids_off = 0;
    std::uint32_t type_ids_size = 0;
    std::uint32_t type_ids_off = 0;
    std::uint32_t proto_ids_size = 0;
    std::uint32_t proto_ids_off = 0;
    std::uint32_t field_ids_size = 0;
    std::uint32_t field_ids_off = 0;
    std::uint32_t method_ids_size = 0;
    std::uint32_t method_ids_off = 0;
    std::uint32_t class_defs_size = 0;
    std::uint32_t class_defs_off = 0;
    std::uint32_t data_size = 0;
    std::uint32_t data_off = 0;
    std::uint32_t container_size = 0;
    std::uint32_t header_offset = 0;

    std::uint32_t defined_field_count = 0;
    std::uint32_t defined_method_count = 0;
    std::uint32_t code_item_count = 0;
    std::uint32_t debug_info_count = 0;

    std::vector<DexMapItem> map_items;
    std::vector<std::string> strings;
    std::vector<std::string> types;
    std::vector<DexProtoInfo> protos;
    std::vector<DexFieldInfo> fields;
    std::vector<DexMethodInfo> methods;
    std::vector<DexMethodHandleInfo> method_handles;
    std::vector<DexCallSiteInfo> call_sites;
    std::vector<DexClassInfo> classes;
    std::vector<DexCodeInfo> code_items;
    std::vector<std::string> string_hints;
    std::vector<std::string> anomalies;
    ImplicitExecutionInfo implicit_exec;

    std::string error;
    std::uint64_t error_offset = 0;
};

struct DexExtractResult {
    bool success = false;
    std::filesystem::path methods_csv;
    std::filesystem::path classes_csv;
    std::filesystem::path fields_csv;
    std::filesystem::path callsites_csv;
    std::uint64_t method_count = 0;
    std::uint64_t class_count = 0;
    std::uint64_t field_count = 0;
    std::uint64_t callsite_count = 0;
    std::string error;
};

DexInfo parse_dex(std::span<const std::uint8_t> data);
Finding dex_finding(const DexInfo& info);
DexExtractResult extract_dex_maps(const DexInfo& info, const std::filesystem::path& methods_csv);

}  // namespace prts
