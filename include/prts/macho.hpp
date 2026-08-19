#pragma once
#include "prts/implicit_exec.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct MachOSection {
    std::string segment,name;
    std::uint64_t address=0,offset=0,size=0,used_size=0;
    std::uint32_t flags=0;
    double entropy=0.0;
};
struct MachOSymbol {
    std::string name;
    std::uint64_t value=0,file_offset=0;
    std::uint16_t desc=0;
    std::uint8_t type=0,section=0;
    bool external=false,private_external=false,defined=false;
};
struct MachOFunctionStart {
    std::uint64_t address=0,file_offset=0;
    std::string symbol;
};
struct MachOInitializerSlot {
    std::string kind;
    std::uint64_t slot_address=0,slot_file_offset=0,target_address=0,target_file_offset=0;
    bool target_file_backed=false;
};
struct MachOSlice {
    bool valid=false,macho64=false,little_endian=true;
    std::int32_t cpu_type=0,cpu_subtype=0;
    std::uint32_t filetype=0,flags=0;
    std::uint64_t slice_offset=0,slice_size=0;
    std::uint64_t entry_file_offset=0,entry_va=0;
    std::uint64_t routine_init_address=0,routine_command_file_offset=0,routine_target_file_offset=0;
    bool routine_target_file_backed=false;
    std::vector<MachOSection> sections;
    std::vector<MachOSymbol> symbols;
    std::vector<MachOFunctionStart> function_starts;
    std::vector<std::string> dylibs;
    std::vector<std::uint64_t> init_functions,term_functions,thread_init_functions;
    std::vector<MachOInitializerSlot> initializer_slots;
    ImplicitExecutionInfo implicit_exec;
    std::string uuid;
    std::uint32_t platform=0,min_os=0,sdk=0;
    bool encrypted=false;
    std::uint32_t cryptid=0;
    std::uint64_t crypt_offset=0,crypt_size=0;
    bool code_signature=false;
    std::uint64_t code_signature_offset=0,code_signature_size=0;
    std::string error;
};
struct MachOInfo {
    bool valid=false,fat=false,fat64=false;
    std::vector<MachOSlice> slices;
    std::string error;
};
MachOInfo parse_macho(std::span<const std::uint8_t> data);
MachOInfo parse_macho(const std::filesystem::path& p);
std::string macho_cpu_name(std::int32_t cpu);
std::string macho_filetype_name(std::uint32_t filetype);
std::string macho_platform_name(std::uint32_t platform);
std::string macho_version_string(std::uint32_t version);
}
