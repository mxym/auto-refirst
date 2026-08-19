#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>
namespace prts {
std::array<std::uint8_t,20> sha1_bytes(std::span<const std::uint8_t> data);
std::array<std::uint8_t,20> sha1_parts(const std::vector<std::span<const std::uint8_t>>& parts);
std::array<std::uint8_t,20> hmac_sha1(std::span<const std::uint8_t> key,std::span<const std::uint8_t> data);
void pbkdf2_hmac_sha1(std::string_view password,std::string_view salt,std::uint32_t iterations,std::span<std::uint8_t> out);
}
