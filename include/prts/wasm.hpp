#pragma once
#include "prts/finding.hpp"
#include "prts/implicit_exec.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct WasmFuncType {
    std::uint32_t index=0;
    std::vector<std::string> params;
    std::vector<std::string> results;
    std::string signature;
};
struct WasmImport {
    std::string module,name,kind;
    std::uint32_t index=0,type_index=0;
};
struct WasmExport {
    std::string name,kind;
    std::uint32_t index=0;
};
struct WasmFunction {
    std::uint32_t index=0,type_index=0;
    bool imported=false,user_like=false;
    std::string name,signature,import_module,import_name;
    std::vector<std::string> exports;
    std::uint64_t code_offset=0,code_size=0;
};
struct WasmCustomSection {
    std::string name;
    std::uint64_t offset=0,size=0;
};
struct WasmDataSegment {
    std::uint32_t index=0,memory_index=0;
    bool passive=false,offset_known=false;
    std::int64_t offset=0;
    std::uint64_t data_offset=0,size=0;
};
struct WasmInfo {
    bool candidate=false,valid=false,type_parse_complete=true,name_parse_complete=true,data_parse_complete=true;
    std::uint32_t version=0;
    std::uint32_t section_count=0,imported_function_count=0,defined_function_count=0,named_function_count=0;
    bool has_data_count=false,has_start=false,start_imported=false,start_exported=false;
    std::uint32_t data_count=0,start_function_index=0,start_type_index=0;
    std::uint64_t start_section_offset=0,start_index_offset=0,start_index_size=0,start_code_offset=0,start_code_size=0;
    std::string start_name,start_signature;
    std::vector<std::string> start_exports;
    std::vector<WasmFuncType> types;
    std::vector<WasmImport> imports;
    std::vector<WasmExport> exports;
    std::vector<WasmFunction> functions;
    std::vector<WasmCustomSection> custom_sections;
    std::vector<WasmDataSegment> data_segments;
    std::vector<std::string> string_hints;
    std::vector<std::string> dwarf_sections;
    std::vector<std::string> anomalies;
    ImplicitExecutionInfo implicit_exec;
    std::string error;
    std::uint64_t error_offset=0;
};
struct WasmExtractResult {
    bool success=false;
    std::filesystem::path functions_csv,strings_txt;
    std::uint64_t function_count=0,string_count=0;
    std::string error;
};
WasmInfo parse_wasm(std::span<const std::uint8_t> data);
Finding wasm_finding(const WasmInfo& info);
WasmExtractResult extract_wasm(const WasmInfo& info,const std::filesystem::path&functions_csv);
}
