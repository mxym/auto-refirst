#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include "prts/elf.hpp"
#include <cstdint>
#include <span>
namespace prts {
struct UpxInfo {
    bool candidate=false;
    bool standard_marker=false;
    bool standard_sections=false;
    bool layout_match=false;
    bool resolver_imports=false;
    bool ep_in_packed_section=false;
    bool empty_exec_before_packed=false;
    bool elf_entry_in_packed_segment=false;
    bool elf_materialization_gap=false;
    bool elf_compact_load_geometry=false;
    bool elf_shared_file_mapping=false;
    bool elf_sectionless=false;
    bool elf_static_stub=false;
    std::uint32_t elf_load_segments=0;
    std::uint64_t elf_materialization_bytes=0;
    int structural_score=0;
    bool semantic_cfg_valid=false;
    std::string reference_state;
    std::string reference_label;
    double reference_similarity=0.0;
    std::uint32_t reference_matched_blocks=0,reference_blocks=0,target_blocks=0;
    std::vector<RangeRef> reference_changed_ranges;
    std::string state;
    std::optional<double> confidence;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
};
UpxInfo detect_upx(std::span<const std::uint8_t> data,const PeInfo& pe,const ElfInfo& elf);
Finding upx_finding(const UpxInfo& info);
}
