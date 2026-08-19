#pragma once
#include "prts/cpython_frozen.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
namespace prts {
struct CPythonFrozenPriorityCandidate {
    std::string table;
    std::string module;
    std::string reference_version;
    std::uint64_t file_offset=0;
    std::uint32_t rva=0;
    std::uint32_t size=0;
    std::string current_raw_sha256;
    std::string reference_raw_sha256;
    std::string current_semantic_sha256;
    std::string reference_semantic_sha256;
};
struct CPythonFrozenPriorityInfo {
    std::string preferred_target; // FROZEN_REFERENCE_DIFF / PYINSTALLER_USER_PAYLOAD / NONE
    std::uint32_t mismatch_count=0;
    bool candidates_truncated=false;
    std::vector<CPythonFrozenPriorityCandidate> candidates;
};
CPythonFrozenPriorityInfo build_cpython_frozen_priority(const CPythonFrozenInfo& frozen,
                                                        bool pyinstaller_user_payload_present,
                                                        std::size_t max_candidates=16);
}
