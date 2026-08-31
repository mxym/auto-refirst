#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include "prts/elf.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct NuitkaEntry { std::string name; std::uint64_t size=0; std::uint64_t data_offset=0; std::uint8_t flags=0; };
struct NuitkaConstantBlock { std::string name; std::uint64_t header_offset=0,data_offset=0,size=0; };
struct NuitkaCodeObjectInfo { std::string name,qualname,args,free_vars; std::uint64_t flags=0; std::uint32_t line=0,arg_count=0,kw_only=0,pos_only=0; };
struct NuitkaDecodedBlock { std::string name; bool success=false; std::uint32_t declared_count=0; std::uint64_t consumed=0,error_offset=0; std::string error; std::vector<std::string> values; std::vector<std::string> string_values; std::vector<NuitkaCodeObjectInfo> code_objects; };
struct NuitkaCompiledVersionInfo {
    bool valid=false;
    std::uint32_t major=0,minor=0,micro=0,descriptor_field_count=0;
    std::uint64_t descriptor_va=0,init_call_va=0,int_constructor_va=0;
    std::string releaselevel,profile,error;
};
struct NuitkaInfo {
    bool valid=false;
    bool onefile=false;
    bool compressed=false;
    bool windows_names=false;
    bool decompression_limited=false;
    std::uint64_t payload_offset=0,payload_size=0,decompressed_size=0,zstd_decompressed_bound=0,decompression_limit=0;
    std::vector<NuitkaEntry> entries;
    std::uint64_t constant_blob_offset=0,constant_blob_size=0;
    std::vector<NuitkaConstantBlock> constant_blocks;
    std::vector<NuitkaDecodedBlock> decoded_blocks;
    NuitkaCompiledVersionInfo compiled_version;
    std::string variant;
    std::string error;
};
struct NuitkaExtractResult { bool success=false,core_only=false,budget_exhausted=false; std::filesystem::path output_dir; std::uint64_t file_count=0,output_bytes=0,omitted_count=0,omitted_bytes=0; std::vector<std::filesystem::path> files; std::string error; };
NuitkaCompiledVersionInfo detect_nuitka_compiled_version(std::span<const std::uint8_t>data,const ElfInfo&elf);
NuitkaInfo detect_nuitka(std::span<const std::uint8_t>data,const PeInfo&pe,const ElfInfo&elf,std::uint64_t max_decompressed_size=512ull*1024*1024);
Finding nuitka_finding(const NuitkaInfo&info);
NuitkaExtractResult extract_nuitka(std::span<const std::uint8_t>data,const NuitkaInfo&info,const std::filesystem::path&out,bool core_only=false,std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000);
}
