#pragma once
#include <array>
#include <cstdint>
#include <filesystem>
#include <string_view>
#include <string>
#include <vector>

namespace prts {
inline constexpr std::array<std::string_view,10> kRuntimeModalityTaxonomy={
    "STATIC_SUFFICIENT",
    "REQUIRES_NATIVE_EXECUTION",
    "REQUIRES_FIRST_EXECUTION_MATERIALIZATION",
    "REQUIRES_SELF_MODIFYING_STATE",
    "REQUIRES_MEMORY_DUMP_CORRELATION",
    "REQUIRES_NETWORK_SIDECAR_CORRELATION",
    "REQUIRES_SUPPLIED_RUNTIME_ENVIRONMENT",
    "REQUIRES_PERF_TIMING_ORACLE",
    "REQUIRES_EXTERNAL_DEVICE_OR_FIRMWARE",
    "UNRESOLVED_RUNTIME_MODALITY"
};
struct AnalysisReport;
struct DirectoryPlan;
struct DirectoryReportIndex;

// AU is a guidance plane: these are hard static-analysis budgets, not runtime
// permissions.  A budget hit fails closed and never promotes a modality.
struct RuntimeModalityBudgets {
    static constexpr std::uint64_t max_executable_bytes_inspected=64ull*1024*1024;
    static constexpr std::uint32_t max_candidate_functions=4096;
    static constexpr std::uint32_t max_candidate_windows=64;
    static constexpr std::uint32_t max_instructions_per_window=32768;
    static constexpr std::uint32_t max_retained_compact_records=16384;
    static constexpr std::uint32_t max_local_provenance_hops=4096;
    static constexpr std::uint64_t max_candidate_function_bytes=16ull*1024*1024;
    static constexpr std::uint64_t max_function_window_bytes=256ull*1024;
};
static_assert(RuntimeModalityBudgets::max_retained_compact_records<=RuntimeModalityBudgets::max_instructions_per_window);
static_assert(RuntimeModalityBudgets::max_local_provenance_hops<=RuntimeModalityBudgets::max_instructions_per_window);

struct RuntimeModalityRequirement {
    std::string modality;
    std::string state="REQUIRED";
    double confidence=0.0;
    std::string evidence_gate;
    std::string reason;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
    std::vector<std::filesystem::path> artifacts;
};

struct RuntimeModalityGuidance {
    std::string policy="STATIC_GUIDANCE_ONLY";
    bool static_evidence_only=true;
    bool runtime_execution_authorized=false;
    std::vector<RuntimeModalityRequirement> requirements;
    std::vector<std::string> priority_guidance;
};

RuntimeModalityGuidance build_runtime_modality_guidance(const AnalysisReport& report);
RuntimeModalityGuidance build_directory_runtime_modality_guidance(const DirectoryPlan& plan,const std::vector<DirectoryReportIndex>& reports);
}
