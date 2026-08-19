#pragma once
#include "prts/finding.hpp"
#include "prts/python_marshal.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct CPythonPycMagicInfo {
    bool known=false;
    std::uint16_t magic_number=0;
    std::array<std::uint8_t,4> bytes{};
    int python_minor=0;
    std::string version_family;
    std::string provenance_tag;
    std::string provenance_path;
};

struct PythonBytecodeInfo {
    bool candidate=false;
    bool valid=false;
    bool filename_hint=false;
    std::uint64_t file_size=0;
    CPythonPycMagicInfo magic;
    std::uint32_t flags=0;
    std::string header_kind;
    std::uint32_t timestamp=0;
    std::uint32_t source_size=0;
    std::array<std::uint8_t,8> source_hash{};
    bool hash_checked=false;
    std::uint64_t marshal_offset=16;
    PythonMarshalSemantic marshal;
    PythonMarshalRootCode root;
    std::array<std::uint64_t,256> opcode_counts{};
    std::uint64_t code_units=0;
    bool opcode_inventory_complete=false;
    std::string error;
    std::uint64_t error_offset=0;
};

struct PythonBytecodeExtractResult {
    bool success=false;
    std::filesystem::path code_objects_csv;
    std::filesystem::path root_symbols_csv;
    std::filesystem::path opcode_inventory_csv;
    std::uint64_t rows=0;
    std::string error;
};

struct CPythonMarshalLoaderInfo {
    bool candidate=false;
    bool loader_confirmed=false;
    bool payload_relation_confirmed=false;
    bool exec_closure=false;
    bool source_integrity_dependency=false;
    std::string loader_api;
    std::string payload_source_kind;
    std::string payload_binding;
    std::string payload_expression;
    std::string transform_callable;
    std::string source_key_binding;
    std::string runtime_version_hint;
    std::string runtime_relation_state;
    std::uint64_t loader_offset=0;
    std::uint64_t loader_size=0;
    std::uint64_t payload_source_offset=0;
    std::uint64_t payload_source_size=0;
};

struct CPythonRuntimePayloadRelationInput {
    bool runtime_present=false;
    bool runtime_authenticated=false;
    std::string runtime_version_family;
    bool payload_present=false;
    bool payload_loader_confirmed=false;
    std::string payload_version_family;
    bool explicit_runtime_payload_binding=false;
    bool unknown_custom_semantics=false;
};

struct CPythonRuntimePayloadRelation {
    bool closed=false;
    std::string state;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
};

CPythonPycMagicInfo identify_cpython_pyc_magic(std::span<const std::uint8_t> data);
PythonBytecodeInfo detect_python_bytecode(std::span<const std::uint8_t> data,bool filename_hint=false);
Finding python_bytecode_finding(const PythonBytecodeInfo& info);
PythonBytecodeExtractResult extract_python_bytecode_maps(const PythonBytecodeInfo& info,
                                                         const std::filesystem::path& code_objects_csv);

CPythonMarshalLoaderInfo inspect_cpython_marshal_loader_source(std::span<const std::uint8_t> data);
Finding cpython_marshal_loader_finding(const CPythonMarshalLoaderInfo& info);
CPythonRuntimePayloadRelation assess_cpython_runtime_payload_relation(const CPythonRuntimePayloadRelationInput& input);

} // namespace prts
