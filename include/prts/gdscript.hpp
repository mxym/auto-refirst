#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct GDScriptLayoutCandidate {
    std::uint32_t token_record_size = 0;
    std::uint32_t line_record_size = 0;
    bool size_fit = false;
    bool identifier_valid = false;
    bool constant_valid = false;
    bool line_references_valid = false;
    bool known_token_semantics_valid = false;
    bool structurally_valid = false;
    std::size_t custom_token_count = 0;
    double token_domain_ratio = 0.0;
    double token_reference_ratio = 0.0;
    double line_token_reference_ratio = 0.0;
    double line_monotonic_ratio = 0.0;
    double reserved_zero_ratio = 0.0;
};

struct GDScriptLayoutInfo {
    std::string state = "FAILED";
    std::string variant = "unknown-variant";
    bool official_compatible = false;
    std::uint32_t tokenizer_version = 0;
    std::uint32_t identifier_count = 0;
    std::uint32_t constant_count = 0;
    std::uint32_t token_line_count = 0;
    std::uint32_t token_count = 0;
    std::uint32_t token_record_size = 0;
    std::uint32_t line_record_size = 0;
    std::size_t size_fit_candidates = 0;
    std::size_t structurally_valid_candidates = 0;
    std::vector<GDScriptLayoutCandidate> candidates;
    std::string error;
};

struct GDScriptIdentifierInfo {
    std::size_t index = 0;
    std::size_t payload_offset = 0;
    std::size_t token_reference_count = 0;
    std::size_t annotation_reference_count = 0;
    std::size_t func_identifier_pair_count = 0;
    std::size_t var_identifier_pair_count = 0;
    std::size_t const_identifier_pair_count = 0;
    std::size_t signal_identifier_pair_count = 0;
    std::size_t class_name_identifier_pair_count = 0;
    std::size_t class_identifier_pair_count = 0;
    std::size_t enum_identifier_pair_count = 0;
    std::size_t extends_identifier_pair_count = 0;
    std::size_t first_token_index = 0;
    std::size_t last_token_index = 0;
    bool referenced = false;
    std::string text;
};

struct GDScriptConstantInfo {
    std::size_t index = 0;
    std::size_t payload_offset = 0;
    std::size_t encoded_size = 0;
    std::size_t token_reference_count = 0;
    std::size_t literal_reference_count = 0;
    std::size_t error_reference_count = 0;
    std::size_t first_token_index = 0;
    std::size_t last_token_index = 0;
    std::uint32_t type_id = 0;
    bool summary_available = false;
    bool summary_complete = false;
    bool referenced = false;
    std::string type;
    std::string summary;
};

struct GDScriptLineInfo {
    std::size_t index = 0;
    std::uint32_t token_index = 0;
    std::uint32_t line = 0;
    std::uint32_t column = 0;
    std::uint32_t unknown = 0;
    bool has_column = false;
    bool has_unknown = false;
};

struct GDScriptNativeSuperCallInfo {
    std::string base_class;
    std::string method_name;
    std::size_t extends_keyword_token_index = 0;
    std::size_t extends_identifier_token_index = 0;
    std::size_t super_token_index = 0;
    std::size_t method_identifier_token_index = 0;
    std::uint32_t effective_line = 0;
    bool effective_line_known = false;
};

struct GDScriptTokenInfo {
    std::size_t index = 0;
    std::size_t payload_offset = 0;
    std::uint32_t type_id = 0;
    std::uint32_t data = 0;
    std::uint32_t line = 0;
    std::uint32_t mapped_line = 0;
    std::uint32_t mapped_column = 0;
    std::uint32_t effective_line = 0;
    std::uint32_t record_size = 0;
    bool custom = false;
    bool position_map_present = false;
    bool mapped_column_known = false;
    bool effective_line_known = false;
    bool semantic_text_available = false;
    bool semantic_text_complete = false;
    bool keyword_identifier_pair_present = false;
    std::size_t keyword_identifier_pair_token_index = 0;
    std::string type;
    std::string keyword_identifier_pair_keyword;
    std::string effective_line_source;
    std::string semantic_text_source;
    std::string semantic_text;
    std::string reference_kind;
    std::string reference;
};

struct GDScriptAnalysisInfo {
    bool valid = false;
    std::string state = "FAILED";
    std::string variant = "unknown-variant";
    std::string offset_space = "decompressed_gdscript_payload";
    std::string compression;
    std::string official_version_scope;
    std::string official_version_basis;
    std::string input_sha256;
    std::string payload_sha256;
    std::string analysis_set_id;
    std::size_t input_bytes = 0;
    std::uint32_t tokenizer_version = 0;
    bool payload_reserved_word_present = false;
    std::uint32_t payload_reserved_word = 0;
    std::uint32_t decompressed_size = 0;
    std::size_t payload_bytes = 0;
    std::uint32_t token_record_size = 0;
    std::uint32_t line_record_size = 0;
    std::size_t typed_array_count = 0;
    std::size_t typed_dictionary_count = 0;
    std::size_t class_name_container_count = 0;
    std::size_t script_container_count = 0;
    std::size_t position_mapped_token_count = 0;
    std::size_t mapped_column_token_count = 0;
    std::size_t semantic_text_token_count = 0;
    std::size_t effective_line_token_count = 0;
    std::size_t unknown_line_token_count = 0;
    std::size_t semantic_text_complete_token_count = 0;
    std::size_t semantic_text_incomplete_token_count = 0;
    std::vector<GDScriptIdentifierInfo> identifiers;
    std::vector<GDScriptConstantInfo> constants;
    std::vector<GDScriptLineInfo> lines;
    std::vector<GDScriptTokenInfo> tokens;
    std::vector<GDScriptNativeSuperCallInfo> native_super_calls;
    std::string error;
};

struct GDScriptMaterializeResult {
    bool success = false;
    std::filesystem::path info_json;
    std::filesystem::path identifiers_csv;
    std::filesystem::path constants_csv;
    std::filesystem::path lines_csv;
    std::filesystem::path tokens_csv;
    std::string error;
};

struct GDScriptBufferInfo {
    bool header_valid = false;
    bool compression_valid = false;
    bool structurally_valid = false;
    bool official_compatible = false;
    std::uint32_t tokenizer_version = 0;
    std::uint32_t decompressed_size = 0;
    std::uint32_t identifier_count = 0;
    std::uint32_t constant_count = 0;
    std::uint32_t token_line_count = 0;
    std::uint32_t token_count = 0;
    std::size_t payload_bytes = 0;
    std::string compression;
    std::string failure_stage;
    std::string error;
};

GDScriptBufferInfo validate_gdscript_buffer(
    std::span<const std::uint8_t> data,
    std::size_t max_decompressed_size = 32u * 1024u * 1024u);

GDScriptBufferInfo validate_gdscript_buffer_versioned(
    std::span<const std::uint8_t> data,
    std::size_t max_decompressed_size = 32u * 1024u * 1024u);

GDScriptLayoutInfo infer_gdscript_layout(
    std::span<const std::uint8_t> data,
    std::size_t max_decompressed_size = 32u * 1024u * 1024u);

GDScriptAnalysisInfo analyze_gdscript_buffer(
    std::span<const std::uint8_t> data,
    std::size_t max_decompressed_size = 32u * 1024u * 1024u);

GDScriptMaterializeResult materialize_gdscript_analysis(
    const GDScriptAnalysisInfo& info,
    const std::filesystem::path& output_base);

} // namespace prts
