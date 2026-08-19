#pragma once
#include "prts/runtime_modality.hpp"
#include "prts/finding.hpp"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
namespace prts {
struct AnalysisReport;
struct AnalysisGuidance {
    std::string visible_hypothesis="declared entry remains the default hypothesis";
    bool declared_entry_default=true;
    std::string decoy_risk="NOT_INDICATED"; // NOT_INDICATED / REVIEW / HIGH
    std::uint32_t runtime_pre_entry_count=0;
    std::uint32_t runtime_first_exec_count=0;
    std::uint32_t high_implicit_count=0;
    std::uint32_t frozen_reference_diff_count=0;
    std::vector<std::string> contradictory_evidence;
    std::vector<std::string> alternate_execution_paths;
    std::vector<std::string> unresolved_alternatives{"absence of alternate evidence is not proof that hidden execution is impossible"};
    std::vector<std::string> priority_reasons;
    RuntimeModalityGuidance runtime_modality;
};
std::optional<Finding> build_pyinstaller_cpython_path(const AnalysisReport& report);
AnalysisGuidance build_analysis_guidance(const AnalysisReport& report);
}
