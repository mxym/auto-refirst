#pragma once
#include "prts/elf.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct ControlRecordField {
    std::uint32_t offset = 0;
    std::uint32_t width = 0;
    std::string role;
    std::string evidence_state;
};

struct ControlRecordTable {
    std::uint32_t index = 0;
    std::string format = "ELF";
    std::string architecture = "x86_64";
    std::string evidence_state;
    std::string priority = "INFORMATIONAL";
    std::string priority_reason;

    std::uint64_t table_va = 0;
    std::uint64_t table_file_offset = 0;
    std::uint32_t record_stride = 0;
    std::uint32_t record_count = 0;
    std::uint64_t table_size = 0;
    std::string stride_evidence_state;
    std::string count_evidence_state;

    std::uint64_t consumer_va = 0;
    std::uint64_t consumer_file_offset = 0;
    std::string consumer_profile;
    std::uint32_t indirect_dispatch_count = 0;

    bool mutable_storage = false;
    std::string mutability_basis;
    std::vector<ControlRecordField> fields;
    std::string coordinate_provenance = "current_input_file + ELF virtual address";
    std::string detail;
};

struct ControlRecordInfo {
    std::string state = "NOT_PRESENT";
    std::string error;
    std::uint64_t bounded_function_count = 0;
    std::uint64_t candidate_consumer_count = 0;
    std::uint64_t confirmed_table_count = 0;
    std::uint64_t rejected_consumer_count = 0;
    bool analysis_limited = false;
    std::vector<ControlRecordTable> tables;
};

struct ControlRecordExtractResult {
    bool success = false;
    std::filesystem::path csv;
    std::uint64_t row_count = 0;
    std::string error;
};

ControlRecordInfo detect_control_records(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf);

ControlRecordExtractResult extract_control_records(
    const ControlRecordInfo& info,
    const std::filesystem::path& csv);

} // namespace prts
