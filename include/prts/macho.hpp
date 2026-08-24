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
struct MachOLoadCommand {
    std::string name;
    std::uint32_t command=0,size=0;
    std::uint64_t offset=0;
    bool known=false;
};
struct MachOSwiftSection {
    std::string segment,name,state;
    std::uint64_t offset=0,size=0;
    bool encrypted_overlap=false;
};
struct MachOSwiftField {
    std::string name,mangled_type_name;
    std::string mangled_type_sha256;
    std::uint64_t record_offset=0;
    std::uint32_t flags=0,mangled_type_byte_length=0,mangled_type_symbolic_references=0;
    bool mangled_type_present=false,mangled_type_plain_text=false;
};
struct MachOSwiftType {
    std::string module_name,type_name,mangled_type_name,kind;
    std::string mangled_type_sha256;
    std::uint64_t type_descriptor_offset=0,field_descriptor_offset=0;
    std::uint32_t mangled_type_byte_length=0,mangled_type_symbolic_references=0;
    bool mangled_type_present=false,mangled_type_plain_text=false;
    std::vector<MachOSwiftField> fields;
};
struct MachOSwiftInfo {
    std::string state="NOT_PRESENT",evidence_level="NONE",coverage_state="COMPLETE";
    std::string source_or_semantic_recovery="UNSUPPORTED",error;
    bool present=false,structured=false,analysis_limited=false;
    std::uint32_t type_records_used=0,field_descriptors_used=0,field_records_used=0;
    std::uint32_t complete_type_closures=0,type_records_skipped=0,type_records_partial=0;
    std::uint32_t type_records_unsupported=0,field_descriptors_skipped=0,field_descriptors_partial=0;
    std::uint32_t field_records_skipped=0,field_records_partial=0;
    std::uint32_t mangled_type_names_absent=0,mangled_type_names_symbolic=0;
    std::uint32_t relative_pointers_used=0,strings_used=0;
    std::uint64_t string_bytes_used=0;
    std::vector<MachOSwiftSection> sections;
    std::vector<MachOSwiftType> types;
    std::vector<std::string> reasons;
};
struct MachOSlice {
    bool valid=false,macho64=false,little_endian=true;
    std::int32_t cpu_type=0,cpu_subtype=0;
    std::uint32_t cpu_subtype_base=0,ptrauth_abi_version=0;
    bool arm64e=false,ptrauth_versioned=false,ptrauth_kernel=false;
    std::string architecture;
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
    std::string code_signature_state="NOT_PRESENT";
    std::uint64_t code_signature_offset=0,code_signature_size=0;
    bool bitcode_present=false;
    std::string bitcode_state="NOT_PRESENT";
    std::uint32_t load_command_count=0,unknown_load_command_count=0;
    bool load_commands_truncated=false,unknown_load_commands_truncated=false;
    std::string load_command_coverage_state="COMPLETE",coverage_state="COMPLETE";
    std::vector<MachOLoadCommand> load_commands,unknown_load_commands;
    std::vector<std::string> coverage_reasons;
    MachOSwiftInfo swift;
    std::string error;
};
struct MachOInfo {
    bool valid=false,fat=false,fat64=false;
    std::string slice_policy="REPORT_ALL_DECLARED_SLICES_NO_SELECTION";
    std::int32_t selected_slice=-1;
    std::vector<MachOSlice> slices;
    std::string error;
};
MachOInfo parse_macho(std::span<const std::uint8_t> data);
MachOInfo parse_macho(const std::filesystem::path& p);
std::string macho_cpu_name(std::int32_t cpu);
std::string macho_architecture_name(std::int32_t cpu,std::int32_t subtype);
std::string macho_load_command_name(std::uint32_t command);
std::string macho_filetype_name(std::uint32_t filetype);
std::string macho_platform_name(std::uint32_t platform);
std::string macho_version_string(std::uint32_t version);
}
