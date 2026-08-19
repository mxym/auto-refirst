#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts {

struct NestedExecutableLimits {
    // These are extractor-local safety ceilings. Callers may tighten them further
    // with the existing artifact graph / extraction budgets.
    std::uint64_t max_child_bytes=64ull*1024*1024;
};

struct NestedExecutableInfo {
    bool valid=false;
    std::string format;
    std::string architecture;
    std::string endianness;
    std::uint16_t machine=0;
    bool is_64=false;
    std::uint64_t parent_offset=0;
    std::uint64_t exact_size=0;
    std::string child_sha256;
    std::string validation_state="UNRESOLVED";
    std::string error;
};

// A report-level candidate that may already own the exact bytes through a
// stronger structured-container provenance plane. `validated_structured_member`
// is deliberately supplied by orchestration: equal bytes alone are not enough
// to suppress AP materialization.
struct NestedExecutableArtifactCandidate {
    std::filesystem::path path;
    std::string source;
    std::string relation;
    std::string priority;
    std::string state;
    std::string sha256;
    std::uint64_t size=0;
    bool validated_structured_member=false;
};

struct NestedExecutableReuseDecision {
    bool reuse=false;
    std::size_t preferred_index=0;
    bool priority_upgrade_required=false;
    std::vector<std::size_t> matching_indexes;
};

// Choose an already materialized higher-level structured member for the exact
// child. The selector re-opens the path, refuses symlinks/non-regular files, and
// re-hashes current bytes. Deterministic precedence is HIGH route first, then
// source/relation/path lexical order. Low-quality equal-SHA artifacts are ignored.
NestedExecutableReuseDecision select_nested_executable_reuse(
    const NestedExecutableInfo& info,
    std::span<const NestedExecutableArtifactCandidate> candidates);

// Validate exactly one candidate already located by the bounded static scanner.
// The returned extent contains only bytes owned by self-describing PE/ELF
// structures; arbitrary trailing parent bytes are never inferred as overlay.
NestedExecutableInfo validate_nested_executable(
    std::span<const std::uint8_t> parent,
    std::uint64_t parent_offset,
    std::string_view expected_format,
    NestedExecutableLimits limits={});

// Persist only the already validated exact span. This never executes the child.
bool materialize_nested_executable(
    std::span<const std::uint8_t> parent,
    const NestedExecutableInfo& info,
    const std::filesystem::path& output,
    std::string& error);

} // namespace prts
