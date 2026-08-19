#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include "prts/cpython_opcode.hpp"
#include "prts/cpython_probe.hpp"
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct CPythonSectionDiff {
    std::string name;
    std::uint64_t target_virtual=0, reference_virtual=0;
    std::uint64_t target_raw=0, reference_raw=0;
    std::int64_t virtual_delta=0, raw_delta=0;
};
struct CPythonFunctionDiff {
    std::string name,state;
    std::uint32_t target_rva=0;
    double reference_coverage=0.0;
    std::uint32_t matched_blocks=0,reference_blocks=0,target_blocks=0;
    std::vector<RangeRef> changed_ranges;
};
struct CPythonRegionDiff {
    std::string kind,section;
    std::uint32_t rva=0;
    std::uint64_t size=0;
    std::string detail;
};
struct CPythonNativeXref {
    std::uint32_t source_rva=0,target_rva=0,size=0;
    std::string kind;
};
struct CPythonOpcodeNormalizationMap {
    std::array<std::int16_t,256> target_to_official{};
    std::string source; // dispatch | compiler_probe
    std::uint32_t mapped_opcodes=0;
};
struct CPythonInfo {
    bool valid=false;
    std::string source;
    std::uint32_t version_hex=0;
    std::string version;
    std::uint32_t api_export_hits=0;
    std::uint32_t named_export_count=0;
    std::string sha256;
    std::uint64_t file_size=0;
    bool exact_reference_available=false;
    std::string reference_status; // REFERENCE_MATCH / DIFFERS_FROM_OFFICIAL_REFERENCE / NO_EXACT_REFERENCE
    std::string reference_version;
    std::string reference_sha256;
    std::uint64_t reference_size=0;
    std::vector<CPythonSectionDiff> section_diffs;
    std::vector<std::string> added_exports;
    std::vector<std::string> missing_exports;
    std::string semantic_reference_status; // REFERENCE_MATCH / COMPARABLE / BUILD_INCOMPARABLE / NO_SEMANTIC_REFERENCE
    double semantic_probe_median=0.0;
    std::uint32_t semantic_probe_count=0;
    std::vector<CPythonFunctionDiff> function_diffs;
    std::string text_reference_status; // MATCH / DIFF / SKIPPED_INCOMPARABLE / NO_REFERENCE
    double text_chunk_match_ratio=0.0;
    std::uint32_t text_chunks_matched=0,text_chunks_reference=0,text_chunks_target=0;
    std::vector<CPythonRegionDiff> region_diffs;
    std::vector<CPythonNativeXref> new_region_xrefs;
    CPythonDispatchInfo dispatch;
    CPythonCompilerProbeInfo compiler_probe;
    std::vector<std::string> evidence;
};
CPythonInfo detect_cpython(std::span<const std::uint8_t> data,const PeInfo& pe,const std::string& source={});
Finding cpython_finding(const CPythonInfo& info);
std::optional<std::array<std::uint8_t,4>> cpython_official_pyc_magic(std::uint32_t version_hex);
std::optional<CPythonOpcodeNormalizationMap> cpython_validated_opcode_map(const CPythonInfo& info);
}
