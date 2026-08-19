#pragma once
#include "prts/report.hpp"
#include <filesystem>
#include <string>
namespace prts {
std::filesystem::path choose_backup_path(const std::filesystem::path& target);
bool replace_with_unpacked(const std::filesystem::path& target,
                           const std::filesystem::path& unpacked,
                           ReplacementReport& report,
                           std::string& error);
}
