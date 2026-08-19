#pragma once
#include "prts/elf.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct ContinuationControlField {
    std::string role;
    std::uint32_t frame_offset = 0;
    std::uint32_t width = 0;
    std::uint64_t target_va = 0;
    std::uint64_t target_file_offset = 0;
    bool target_file_backed = false;
    std::string evidence_state;
};

struct ContinuationSuspendSite {
    std::uint64_t instruction_va = 0;
    std::uint64_t instruction_file_offset = 0;
    std::uint32_t state_frame_offset = 0;
    std::uint32_t state_width = 0;
    bool state_value_exact = false;
    std::uint64_t state_value = 0;
    std::string evidence_state;
};

struct ContinuationEntry {
    std::uint32_t index = 0;
    std::string format = "ELF";
    std::string architecture = "x86_64";
    std::string coroutine_identity;
    std::string compiler_profile;
    std::string evidence_state;
    std::string priority = "INFORMATIONAL";
    std::string priority_reason;

    std::uint64_t creator_va = 0;
    std::uint64_t creator_file_offset = 0;
    std::uint64_t frame_allocation_site_va = 0;
    std::uint64_t frame_allocation_site_file_offset = 0;
    bool frame_size_exact = false;
    std::uint64_t frame_size = 0;
    std::string frame_storage;
    bool frame_control_pointers_writable = false;

    std::uint64_t resume_target_va = 0;
    std::uint64_t resume_target_file_offset = 0;
    std::uint64_t destroy_target_va = 0;
    std::uint64_t destroy_target_file_offset = 0;
    std::uint64_t cleanup_target_va = 0;
    std::uint64_t final_target_va = 0;
    std::uint64_t continuation_target_va = 0;

    std::uint32_t state_frame_offset = 0;
    std::uint32_t state_width = 0;
    bool final_clears_resume_pointer = false;
    bool destroy_consumes_common_frame = false;

    std::string promise_relation = "UNRESOLVED";
    std::string coordinate_provenance = "current_input_file + ELF virtual address";
    std::vector<ContinuationControlField> control_fields;
    std::vector<ContinuationSuspendSite> suspend_sites;
    std::string detail;
};

struct ContinuationInfo {
    std::string state = "NOT_PRESENT";
    std::string error;
    std::uint64_t candidate_creator_count = 0;
    std::uint64_t confirmed_count = 0;
    std::uint64_t rejected_shape_count = 0;
    bool analysis_limited = false;
    std::vector<ContinuationEntry> entries;
};

struct ContinuationExtractResult {
    bool success = false;
    std::filesystem::path csv;
    std::uint64_t row_count = 0;
    std::string error;
};

ContinuationInfo detect_cpp20_continuations(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf);

ContinuationExtractResult extract_continuations(
    const ContinuationInfo& info,
    const std::filesystem::path& csv);

} // namespace prts
