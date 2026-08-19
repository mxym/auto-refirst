#pragma once
#include "prts/implicit_exec.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct PeTlsCallback { std::uint64_t slot_va=0,slot_file_offset=0,target_va=0,target_file_offset=0; bool target_file_backed=false; };
struct PeTlsInfo { bool present=false; std::uint64_t directory_rva=0,directory_file_offset=0; std::uint64_t callbacks_va=0,callbacks_file_offset=0; std::vector<std::uint64_t> callback_vas; std::vector<PeTlsCallback> callbacks; };
struct PeRuntimeFunction { std::uint32_t begin_rva=0,end_rva=0,unwind_rva=0; };
struct PeExceptionInfo { bool present=false; std::uint32_t rva=0,size=0; std::uint32_t runtime_function_count=0; std::vector<PeRuntimeFunction> runtime_functions; std::vector<std::uint32_t> handler_rvas; };
struct PeInitInfo { bool has_crt_section=false; bool references_initterm=false; bool references_initterm_e=false; std::vector<std::string> crt_sections; };
struct PeSection { std::string name; std::uint32_t rva=0,vsize=0,raw_offset=0,raw_size=0,used_size=0,characteristics=0; double entropy=0.0; };
struct PeImportFunction { std::string name; std::uint16_t ordinal=0; bool by_ordinal=false; std::uint16_t hint=0; };
struct PeImportModule { std::string name; std::uint32_t descriptor_rva=0,iat_rva=0; std::vector<PeImportFunction> functions; };
struct PeExport { std::string name; std::string forwarder; std::uint32_t rva=0; std::uint16_t ordinal=0; };
struct PeDirectoryInfo { bool present=false; std::uint32_t rva=0,size=0; };
struct PeLoadConfigInfo { bool present=false; std::uint32_t rva=0,size=0; std::uint32_t guard_flags=0; std::uint64_t security_cookie=0; std::uint64_t seh_table=0; std::uint64_t seh_count=0; };
struct PeInfo {
    bool valid=false; bool pe64=false,dll=false;
    std::uint16_t machine=0,subsystem=0,coff_characteristics=0;
    std::uint32_t entry_rva=0,image_size=0,headers_size=0;
    std::uint64_t image_base=0;
    std::uint64_t overlay_offset=0,overlay_size=0;
    std::vector<PeSection> sections;
    std::vector<PeImportModule> imports;
    std::vector<PeExport> exports;
    PeTlsInfo tls;
    PeExceptionInfo exception;
    PeInitInfo init;
    PeDirectoryInfo resources;
    PeDirectoryInfo relocations;
    PeDirectoryInfo debug;
    PeDirectoryInfo clr;
    PeLoadConfigInfo load_config;
    ImplicitExecutionInfo implicit_exec;
    std::string error;
};
PeInfo parse_pe(std::span<const std::uint8_t> data);
PeInfo parse_pe(const std::filesystem::path& p);
std::string pe_machine_name(std::uint16_t machine);
std::string pe_subsystem_name(std::uint16_t subsystem);
}
