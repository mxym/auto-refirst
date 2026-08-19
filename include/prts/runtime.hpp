#pragma once
#include "prts/report.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
namespace prts {
struct RuntimeOptions {
    bool deep_materialization_analysis=false;
    bool allow_validated_install=false;
    std::uint32_t timeout_ms=15000;
    std::filesystem::path artifact_dir;
};
bool run_target(const std::filesystem::path& target,const PeInfo& pe,const RuntimeOptions& options,AnalysisReport& report,std::string& error);
}
