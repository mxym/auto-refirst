#include "prts/v8_code_cache.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

void put_u32(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    data[offset] = static_cast<std::uint8_t>(value);
    data[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    data[offset + 2] = static_cast<std::uint8_t>(value >> 16);
    data[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

std::vector<std::uint8_t> modern_cache() {
    constexpr std::size_t header = 32;
    std::vector<std::uint8_t> data(header + 64, 0xa5);
    put_u32(data, 0, 0xc0de0688u);
    put_u32(data, 4, 0xdc338cfau);
    put_u32(data, 8, 17u | (1u << 29));
    put_u32(data, 12, 0x5fb11f89u);
    put_u32(data, 16, 0x5cfb0532u);
    put_u32(data, 20, 64u);
    put_u32(data, 24, 0u);
    return data;
}

std::vector<std::uint8_t> legacy_cache() {
    constexpr std::size_t header = 24;
    std::vector<std::uint8_t> data(header + 48, 0x5a);
    put_u32(data, 0, 0xc0de05ccu);
    put_u32(data, 4, 0x00e4c20bu);
    put_u32(data, 8, 9u | (1u << 31));
    put_u32(data, 12, 0x5f1581a7u);
    put_u32(data, 16, 48u);
    put_u32(data, 20, 0u);
    return data;
}

bool modern_roundtrip() {
    const auto data = modern_cache();
    const auto info = prts::parse_v8_code_cache(data);
    if (!info.candidate || !info.valid || info.layout != "modern_7_word_header") return false;
    if (info.header_size != 32 || info.payload_offset != 32 || info.payload_size != 64) return false;
    if (info.source_length != 17 || !info.source_hash_has_wrapped_arguments || info.source_hash_is_module) return false;
    const auto finding = prts::v8_code_cache_finding(info);
    return finding.state == "LIKELY" && finding.ranges.size() == 1 &&
           finding.ranges[0].offset == 32 && finding.ranges[0].size == 64;
}

bool legacy_roundtrip() {
    const auto data = legacy_cache();
    const auto info = prts::parse_v8_code_cache(data);
    return info.candidate && info.valid && info.layout == "legacy_6_word_header" &&
           info.header_size == 24 && info.source_length == 9 && info.source_hash_is_module;
}

bool malformed_geometry_is_rejected() {
    auto data = modern_cache();
    put_u32(data, 20, 63u);
    const auto info = prts::parse_v8_code_cache(data);
    const auto finding = prts::v8_code_cache_finding(info);
    return info.candidate && !info.valid && !info.error.empty() && finding.state == "FAILED";
}

bool bounded_prefix_preserves_geometry() {
    const auto data = modern_cache();
    const auto info = prts::parse_v8_code_cache(
        std::span<const std::uint8_t>(data.data(), 32), data.size());
    return info.candidate && info.valid && info.payload_offset == 32 &&
           info.payload_size == 64;
}

}  // namespace

int main() {
    if (!modern_roundtrip() || !legacy_roundtrip() ||
        !malformed_geometry_is_rejected() || !bounded_prefix_preserves_geometry())
        return 1;
    std::cout << "PASS\n";
    return 0;
}
