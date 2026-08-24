#pragma once

#include "prts/finding.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct HermesOpcodeInfo {
    std::uint16_t opcode = 0;
    std::string name;
    std::uint32_t count = 0;
};

struct HermesFunctionInfo {
    std::uint32_t index = 0;
    std::uint64_t header_offset = 0;
    std::uint64_t bytecode_offset = 0;
    std::uint64_t bytecode_size = 0;
    std::uint64_t info_offset = 0;
    std::uint32_t function_name_id = 0;
    std::string function_name;
    std::uint32_t param_count = 0;
    std::uint32_t frame_size = 0;
    std::uint32_t environment_size = 0;
    std::uint32_t instruction_count = 0;
    bool overflow_header = false;
    bool strict_mode = false;
    bool has_exception_handler = false;
    bool has_debug_info = false;
    std::vector<HermesOpcodeInfo> opcodes;
};

struct HermesStringInfo {
    std::uint32_t index = 0;
    std::uint64_t storage_offset = 0;
    std::uint32_t length = 0;
    bool utf16 = false;
    bool identifier = false;
    std::string value;
};

struct HermesDebugInfo {
    bool present = false;
    bool valid = false;
    std::uint64_t offset = 0;
    std::uint32_t filename_count = 0;
    std::uint32_t filename_storage_size = 0;
    std::uint32_t file_region_count = 0;
    std::uint32_t debug_data_size = 0;
    std::uint32_t lexical_data_offset = 0;
    std::uint32_t scope_desc_data_offset = 0;
    std::uint32_t textified_callee_offset = 0;
    std::uint32_t string_table_offset = 0;
    std::uint64_t end_offset = 0;
};

struct HermesInfo {
    bool candidate = false;
    bool supported_epoch = false;
    bool valid = false;
    bool parse_complete = false;
    bool footer_hash_checked = false;
    bool footer_hash_matches = false;
    bool budget_limited = false;
    bool maps_truncated = false;
    std::uint32_t version = 0;
    std::string epoch;
    std::string source_hash;
    std::string file_hash;
    std::uint64_t file_size = 0;
    std::uint32_t declared_file_length = 0;
    std::uint32_t global_code_index = 0;
    std::uint32_t function_count = 0;
    std::uint32_t string_kind_count = 0;
    std::uint32_t identifier_count = 0;
    std::uint32_t string_count = 0;
    std::uint32_t overflow_string_count = 0;
    std::uint32_t string_storage_size = 0;
    std::uint32_t bigint_count = 0;
    std::uint32_t regexp_count = 0;
    std::uint32_t cjs_module_count = 0;
    std::uint32_t function_source_count = 0;
    std::uint32_t deduplicated_function_bodies = 0;
    std::uint64_t function_table_offset = 0;
    std::uint64_t string_kind_table_offset = 0;
    std::uint64_t identifier_hash_table_offset = 0;
    std::uint64_t string_table_offset = 0;
    std::uint64_t overflow_string_table_offset = 0;
    std::uint64_t string_storage_offset = 0;
    std::uint64_t function_bytecode_begin = 0;
    std::uint64_t function_bytecode_end = 0;
    std::uint64_t error_offset = 0;
    HermesDebugInfo debug;
    std::vector<HermesFunctionInfo> functions;
    std::vector<HermesStringInfo> strings;
    std::vector<HermesOpcodeInfo> opcodes;
    std::vector<std::string> anomalies;
    std::string error;
};

struct HermesExtractResult {
    bool success = false;
    std::filesystem::path functions_csv;
    std::filesystem::path strings_csv;
    std::filesystem::path opcodes_csv;
    std::uint64_t function_count = 0;
    std::uint64_t string_count = 0;
    std::uint64_t opcode_count = 0;
    std::string error;
};

HermesInfo parse_hermes_bytecode(std::span<const std::uint8_t> data);
Finding hermes_finding(const HermesInfo& info);
HermesExtractResult extract_hermes_maps(const HermesInfo& info,
                                        const std::filesystem::path& functions_csv);

}  // namespace prts
