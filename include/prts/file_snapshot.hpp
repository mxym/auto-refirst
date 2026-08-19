#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
namespace prts {
struct FileSnapshot {
 std::filesystem::path path; bool exists=false; std::uintmax_t size=0;
 std::optional<std::filesystem::file_time_type> write_time; std::string sha256;
};
FileSnapshot snapshot_file(const std::filesystem::path& p);
}
