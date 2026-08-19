#pragma once
#include "prts/pe.hpp"
#include "prts/finding.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct SemanticBlock {
    std::uint64_t address=0;
    std::uint32_t rva=0;
    std::uint32_t size=0;
    std::uint32_t instruction_count=0;
    std::uint64_t hash=0;
    std::vector<std::uint64_t> instruction_hashes;
};
struct SemanticCfg {
    bool valid=false;
    std::uint32_t entry_rva=0;
    std::vector<SemanticBlock> blocks;
    std::string error;
};
struct SemanticDiff {
    double block_similarity=0.0;
    std::uint32_t matched_blocks=0,reference_blocks=0,target_blocks=0;
    std::vector<RangeRef> changed_ranges;
};
struct DirectControlRef {
    std::uint32_t source_rva=0,target_rva=0,size=0;
    std::string kind;
};
SemanticCfg build_x86_cfg(std::span<const std::uint8_t> data,const PeInfo&pe,std::uint32_t entry_rva,std::uint32_t max_span=0x6000,std::uint32_t max_blocks=512);
SemanticDiff compare_semantic_cfg(const SemanticCfg&target,const std::vector<std::uint64_t>&reference_block_hashes);
std::uint64_t semantic_cfg_digest(const SemanticCfg&cfg);
std::vector<DirectControlRef> find_direct_control_refs(std::span<const std::uint8_t>data,const PeInfo&pe,const std::vector<RangeRef>&target_ranges,std::size_t max_refs=256);
}
