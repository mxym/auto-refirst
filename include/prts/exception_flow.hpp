#pragma once

#include "prts/finding.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct PeInfo;
struct ElfInfo;

// Independent exceptional-execution evidence plane.  This deliberately does
// not extend ImplicitExecutionInfo: exception/signal control transfer has a
// different trigger/registration/resume contract and a much stricter refusal
// boundary than ordinary loader callbacks.
struct ExceptionalExecutionFact {
    std::uint32_t index=0;
    std::string platform;
    std::string mechanism;
    std::string trigger_kind;
    std::optional<RangeRef> trigger_location;
    std::optional<RangeRef> registration_site;
    std::optional<RangeRef> handler;
    std::optional<RangeRef> landing_pad;
    std::optional<RangeRef> protected_range;
    std::string protected_function;
    std::string resume_semantics;
    std::string context_mutation_evidence;
    // : evidence is explicitly tiered and plane-scoped.  Static
    // registration/trigger/context facts must never be presented as runtime
    // confirmation merely because they describe the same mechanism.
    std::string evidence_level; // X0..X5 for exceptional execution
    std::string proof_plane="STATIC_PROVEN";
    std::string handler_outcome;
    std::string ambiguity;
    std::string evidence_state;
    std::string provenance;
    std::string priority="INFORMATIONAL";
    std::string priority_reason;
    std::string refusal_reason;
    std::string detail;
};

struct ExceptionalExecutionInfo {
    std::string state="NOT_PRESENT";
    std::string error;
    bool analysis_limited=false;
    std::uint32_t informational_count=0;
    std::uint32_t review_count=0;
    std::uint32_t high_priority_count=0;
    std::vector<ExceptionalExecutionFact> facts;
};

struct ExceptionalExecutionExtractResult {
    bool success=false;
    std::filesystem::path csv;
    std::uint64_t fact_count=0;
    std::string error;
};

// Platform analyzers are intentionally explicit entry points rather than
// automatic parser side effects.  The caller supplies artifact_identity so
// every recovered address carries the Direction-E typed provenance contract.
ExceptionalExecutionInfo analyze_pe_exception_flow(
    std::span<const std::uint8_t> data,
    const PeInfo& pe,
    const std::string& artifact_identity={});
ExceptionalExecutionInfo analyze_elf_exception_flow(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf,
    const std::string& artifact_identity={});


// : cheap, bounded composition of existing exact metadata/control facts
// into alternate execution-surface guidance. This is static evidence only; it
// never claims runtime dispatch/confirmation and never evaluates a DWARF VM.
std::vector<Finding> compose_exception_execution_surfaces(
    std::span<const std::uint8_t> data,
    const PeInfo& pe,
    const ElfInfo& elf,
    const std::string& artifact_identity = {});

ExceptionalExecutionExtractResult extract_exceptional_execution(
    const ExceptionalExecutionInfo& info,
    const std::filesystem::path& csv);
}
