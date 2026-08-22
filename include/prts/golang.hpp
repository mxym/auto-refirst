#pragma once
#include "prts/elf.hpp"
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct GoFunction {
    std::uint64_t start_va=0,end_va=0;
    std::uint64_t start_rva=0,end_rva=0;
    std::string name;
    std::string package;
    bool user_like=false;
};
struct GoStructField {
    std::string name,type_name,tag;
    std::uint64_t type_va=0,offset=0;
    bool embedded=false;
};
struct GoTypeInfo {
    std::uint64_t va=0,size=0;
    std::string name,kind;
    std::uint8_t tflag=0;
    bool user_like=false;
    std::vector<GoStructField> fields;
};
struct GoInfo {
    bool valid=false;
    std::string version;
    std::string module_path;
    std::vector<std::string> modules;
    std::vector<std::string> build_settings;
    std::string pclntab_layout;
    std::uint64_t pclntab_offset=0,pclntab_va=0,pclntab_text_base=0;
    std::string pclntab_text_base_source;
    std::uint64_t moduledata_va=0,types_va=0,etypes_va=0,typelinks_va=0,itablinks_va=0;
    std::uint64_t typelinks_count=0,itablinks_count=0;
    std::string moduledata_layout;
    std::uint32_t pointer_size=0,quantum=0;
    bool little_endian=true;
    std::vector<GoFunction> functions;
    std::vector<GoTypeInfo> types;
    std::string type_error;
    std::string error;
};
struct GoExtractResult {
    bool success=false;
    std::filesystem::path symbols_csv;
    std::filesystem::path types_csv;
    std::uint64_t symbol_count=0,type_count=0;
    std::string error;
};
GoInfo detect_golang(std::span<const std::uint8_t> data,const PeInfo&pe,const ElfInfo&elf);
Finding golang_finding(const GoInfo&info);
GoExtractResult extract_go_symbols(const GoInfo&info,const std::filesystem::path&out);
}
