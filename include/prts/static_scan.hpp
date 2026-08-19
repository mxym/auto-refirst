#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include "prts/elf.hpp"
#include <cstdint>
#include <span>
#include <vector>
namespace prts {
StaticScanReport scan_static(std::span<const std::uint8_t> data);
std::vector<Finding> detect_common(std::span<const std::uint8_t> data,
                                   const PeInfo& pe,
                                   const ElfInfo& elf,
                                   const StaticScanReport& scan);
}
