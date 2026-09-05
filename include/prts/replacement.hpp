#pragma once
#include <filesystem>
#include <string>
namespace prts {
std::filesystem::path choose_backup_path(const std::filesystem::path& target);
}
