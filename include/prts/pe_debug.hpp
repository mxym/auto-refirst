#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace prts {

// Inspect validated PE debug-directory payloads for embedded bytes that are
// actionable to the next reversing step. Ordinary RSDS/NB10 records with only
// a normal PDB path remain silent; the detector never treats a PDB name as a
// payload indicator.
std::vector<Finding> detect_pe_debug_payload(std::span<const std::uint8_t> data,
                                             const PeInfo& pe);

} // namespace prts
