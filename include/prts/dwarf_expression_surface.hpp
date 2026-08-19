#pragma once

#include "prts/finding.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct ElfInfo;

struct DwarfVendorProgramFact {
    std::string carrier;              // DWARF_EXPRESSION or DWARF_LINE_PROGRAM
    std::string section;
    std::string consumer_relation;
    std::string semantic_state;       // authenticated semantics are never guessed
    std::uint64_t unit_offset=0;      // section-relative CU/line-unit coordinate
    std::uint64_t die_offset=0;       // .debug_info-relative when carrier is expression
    std::uint64_t file_offset=0;
    std::uint64_t size=0;
    std::uint64_t vendor_record_count=0;
    std::uint64_t vendor_byte_count=0;
    std::string vendor_opcodes;
    std::string exact_bytes_hex;
    bool executable_address_relation=false;
};

struct DwarfVendorSurfaceInfo {
    std::string state="NOT_PRESENT";
    std::string error;
    bool analysis_limited=false;
    std::uint64_t standard_expression_count=0;
    std::uint64_t malformed_expression_count=0;
    std::vector<DwarfVendorProgramFact> candidates;
};

// Bounded structural DWARF inspection. It does not execute DWARF expressions,
// line programs, or vendor opcodes. Unknown vendor semantics remain explicit.
DwarfVendorSurfaceInfo analyze_dwarf_vendor_surface(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf,
    const std::string& artifact_identity={});

// Product-facing guidance gate. Exactly one consumer-related candidate is
// required. The result is REVIEW only; this producer has no HIGH path.
std::vector<Finding> compose_dwarf_vendor_surfaces(
    std::span<const std::uint8_t> data,
    const ElfInfo& elf,
    const std::string& artifact_identity={});
}
