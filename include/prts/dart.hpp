#pragma once

#include "prts/elf.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct DartSnapshotInfo {
    bool candidate = false;
    bool valid = false;
    std::uint64_t file_offset = 0;
    std::uint64_t available_size = 0;
    std::int64_t stored_length = 0;
    std::uint64_t length = 0;
    std::int64_t kind = 0;
    std::string kind_name;
    std::string snapshot_hash;
    std::string features;
    std::vector<std::string> feature_tokens;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct DartAotSymbol {
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t segment_flags = 0;
    std::uint8_t binding = 0;
    std::uint8_t type = 0;
    bool file_backed = false;
};

struct DartStringHint {
    std::uint64_t file_offset = 0;
    std::string text;
};

struct DartKernelString {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t byte_size = 0;
    bool wtf8_surrogate_escaped = false;
    std::string text;
};

struct DartKernelSource {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t source_code_offset = 0;
    std::uint32_t source_code_size = 0;
    std::uint32_t line_count = 0;
    std::uint32_t coverage_reference_count = 0;
    bool uri_wtf8_surrogate_escaped = false;
    bool import_uri_wtf8_surrogate_escaped = false;
    std::string uri;
    std::string import_uri;
    std::vector<std::uint32_t> line_starts;
};

struct DartKernelCanonicalName {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint32_t parent_reference = 0;
    std::uint32_t string_reference = 0;
    bool path_truncated = false;
    std::string name;
    std::string path;
};

struct DartKernelConstant {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t end_offset = 0;
    std::uint8_t tag = 0;
    bool simple_value_decoded = false;
    std::string tag_name;
    std::string value;
};

struct DartKernelSerializedRange {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t end_offset = 0;
};

struct DartKernelProcedure {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t end_offset = 0;
    std::uint64_t prefix_end_offset = 0;
    std::uint32_t canonical_reference = 0;
    std::uint32_t file_uri_reference = 0;
    std::int64_t source_start_offset = -1;
    std::int64_t source_name_offset = -1;
    std::int64_t source_end_offset = -1;
    std::uint8_t kind = 0;
    std::uint8_t stub_kind = 0;
    std::uint32_t flags = 0;
    std::string canonical_path;
    std::string name;
    std::string file_uri;
};

struct DartKernelLibrary {
    std::uint32_t index = 0;
    std::uint64_t file_offset = 0;
    std::uint64_t end_offset = 0;
    std::uint64_t index_offset = 0;
    std::uint64_t prefix_end_offset = 0;
    std::uint8_t flags = 0;
    std::uint32_t language_major = 0;
    std::uint32_t language_minor = 0;
    std::uint32_t canonical_reference = 0;
    std::uint32_t name_reference = 0;
    std::uint32_t file_uri_reference = 0;
    std::uint32_t problem_count = 0;
    std::uint32_t class_count = 0;
    std::uint32_t procedure_count = 0;
    std::string import_uri;
    std::string name;
    std::string file_uri;
    std::vector<DartKernelSerializedRange> class_ranges;
    std::vector<DartKernelSerializedRange> procedure_ranges;
    std::vector<DartKernelProcedure> procedures;
};

struct DartKernelInfo {
    bool candidate = false;
    bool valid = false;
    bool deep_metadata_supported = false;
    bool deep_metadata_complete = false;
    std::uint32_t format_version = 0;
    std::string sdk_hash;
    std::uint32_t string_count = 0;
    std::uint32_t constant_count = 0;
    std::uint32_t source_count = 0;
    std::uint32_t canonical_name_count = 0;
    std::uint32_t library_count = 0;
    std::uint32_t component_index_words = 0;
    std::uint64_t component_file_size = 0;
    std::uint64_t component_index_offset = 0;
    std::uint64_t source_table_offset = 0;
    std::uint64_t constant_table_offset = 0;
    std::uint64_t constant_table_index_offset = 0;
    std::uint64_t canonical_name_table_offset = 0;
    std::uint64_t metadata_payloads_offset = 0;
    std::uint64_t metadata_mappings_offset = 0;
    std::uint64_t string_table_offset = 0;
    std::uint32_t main_method_reference = 0;
    std::vector<std::uint64_t> library_offsets;
    std::vector<DartKernelString> strings;
    std::vector<DartKernelConstant> constants;
    std::vector<DartKernelSource> sources;
    std::vector<DartKernelCanonicalName> canonical_names;
    std::vector<DartKernelLibrary> libraries;
    std::vector<DartStringHint> string_hints;
    std::string deep_metadata_error;
    std::uint64_t deep_metadata_error_offset = 0;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct DartAotInfo {
    bool candidate = false;
    bool valid = false;
    bool standalone = false;
    bool flutter_symbols = false;
    bool section_table_independent = false;
    bool symbol_parse_complete = false;
    bool architecture_feature_matches = true;
    std::string variant;
    std::string architecture;
    std::string build_id_hex;
    std::uint32_t dynamic_symbol_count = 0;
    std::vector<DartAotSymbol> symbols;
    std::vector<DartSnapshotInfo> snapshots;
    std::vector<DartStringHint> string_hints;
    std::vector<std::string> anomalies;
    std::string error;
    std::uint64_t error_offset = 0;
};

struct DartInfo {
    bool candidate = false;
    bool valid = false;
    DartSnapshotInfo raw_snapshot;
    DartKernelInfo kernel;
    DartAotInfo aot;
    std::string error;
    std::uint64_t error_offset = 0;
};

DartSnapshotInfo parse_dart_snapshot(std::span<const std::uint8_t> data,
                                     std::uint64_t file_offset = 0,
                                     std::uint64_t available_size = 0);
DartKernelInfo parse_dart_kernel(std::span<const std::uint8_t> data);
DartInfo detect_dart(std::span<const std::uint8_t> data, const ElfInfo& elf);

}  // namespace prts
