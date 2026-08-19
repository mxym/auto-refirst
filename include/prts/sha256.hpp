#pragma once
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
std::string sha256_bytes(std::span<const std::uint8_t> data);
std::string sha256_parts(const std::vector<std::span<const std::uint8_t>>& parts);
std::string sha256_file(const std::filesystem::path& p);
}
