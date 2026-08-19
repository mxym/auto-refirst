#pragma once
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct CPythonFrozenCodeRange {
    std::uint64_t blob_offset=0;
    std::uint64_t file_offset=0;
    std::uint32_t rva=0;
    std::uint64_t size=0;
    std::string name;
    std::string filename;
    std::string qualname;
    std::int32_t first_line=0;
};

struct CPythonFrozenModule {
    std::string table;
    std::string name;
    std::string state; // RAW_MARSHAL / DEEP_FROZEN_STATIC_CODE_OBJECT / UNAVAILABLE / MALFORMED
    std::string marshal_state; // CONFIRMED / UNAVAILABLE_DEEP_FROZEN_OBJECT_GRAPH / UNAVAILABLE_NO_RAW_CODE / PARSE_FAILED
    std::string error;
    bool is_package=false;
    std::uint32_t record_rva=0;
    std::uint32_t name_rva=0;
    std::uint32_t raw_code_rva=0;
    std::uint64_t raw_code_file_offset=0;
    std::uint32_t raw_code_size=0;
    std::uint32_t getter_rva=0;
    std::uint32_t code_object_rva=0;
    std::uint32_t adaptive_code_rva=0;
    std::uint64_t adaptive_code_file_offset=0;
    std::uint32_t adaptive_code_size=0;
    std::string raw_sha256;
    std::string semantic_sha256;
    std::string reference_version;
    std::string reference_state; // NOT_CHECKED / REFERENCE_MATCH / REFERENCE_DIFF / NO_REFERENCE / UNAVAILABLE_*
    std::string reference_match_mode; // EXACT / SEMANTIC / DIFFERENT
    std::string reference_raw_sha256;
    std::string reference_semantic_sha256;
    std::uint64_t marshal_object_count=0;
    std::uint64_t marshal_code_object_count=0;
    std::vector<CPythonFrozenCodeRange> code_ranges;
};

struct CPythonFrozenTable {
    std::string export_name;
    std::string state; // CONFIRMED / PARTIAL / REJECTED
    std::string error;
    std::uint32_t export_rva=0;
    std::uint32_t table_rva=0;
    std::uint32_t record_size=0;
    std::vector<CPythonFrozenModule> modules;
};

struct CPythonFrozenInfo {
    bool valid=false;
    std::string state; // CONFIRMED / PARTIAL / REJECTED / NO_FROZEN_EXPORTS / NO_CPYTHON_RUNTIME (bundle orchestration)
    std::string error;
    int python_minor=0;
    std::uint32_t raw_module_count=0;
    std::uint32_t deep_frozen_module_count=0;
    std::uint32_t unavailable_module_count=0;
    std::string reference_version;
    std::uint32_t reference_match_count=0;
    std::uint32_t reference_diff_count=0;
    std::uint32_t reference_no_reference_count=0;
    std::uint32_t reference_unavailable_count=0;
    std::vector<CPythonFrozenTable> tables;
};

CPythonFrozenInfo analyze_cpython_frozen(std::span<const std::uint8_t> data,
                                         const PeInfo& pe,
                                         int python_version);

}
