#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct PackedPeInfo {
    bool candidate=false;
    int structural_score=0, evidence_categories=0;
    bool ep_high_entropy_exec=false, ep_writable_exec=false, sparse_imports=false, resolver_imports=false;
    bool raw_empty_exec=false, exec_virtual_gap=false, high_entropy_payload=false, large_overlay=false, tls_pre_entry=false;
    std::uint32_t ep_section_index=0xffffffffu, import_modules=0, import_functions=0, resolver_api_count=0;
    std::uint32_t raw_empty_exec_count=0, exec_virtual_gap_count=0, high_entropy_section_count=0;
    std::uint64_t overlay_size=0;
    double overlay_ratio=0.0;
    std::vector<std::string> family_marker_hints;
    std::vector<std::string> evidence, negative_evidence;
};

PackedPeInfo detect_packed_pe(const PeInfo& pe, std::uint64_t file_size);
Finding packed_pe_finding(const PackedPeInfo& info, const PeInfo& pe);
std::vector<Finding> detect_pe_protector_structures(std::span<const std::uint8_t> data, const PeInfo& pe, const PackedPeInfo* packed_info=nullptr);
} // namespace prts
