#pragma once
#include "prts/implicit_exec.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <span>
#include <vector>
namespace prts {
struct ElfInitArray { std::string kind; std::uint64_t address=0,offset=0,size=0; std::vector<std::uint64_t> entries; };
struct ElfInitInfo { std::vector<ElfInitArray> arrays; bool has_init=false,has_fini=false,has_ctors=false,has_dtors=false; std::uint64_t dt_init=0,dt_fini=0,dt_preinit_array=0,dt_preinit_arraysz=0,dt_init_array=0,dt_init_arraysz=0,dt_fini_array=0,dt_fini_arraysz=0; };
struct ElfSection {
    std::string name;
    std::uint64_t address=0, offset=0, size=0, flags=0, type=0, used_size=0;
    double entropy=0.0;
};
struct ElfSegment {
    std::uint32_t type=0, flags=0;
    std::uint64_t offset=0, address=0, file_size=0, memory_size=0, align=0, used_size=0;
    double entropy=0.0;
};
struct ElfDynamicSymbol {
    std::uint32_t index=0,name_offset=0;
    std::uint8_t info=0,other=0,binding=0,type=0,visibility=0;
    std::uint16_t section_index=0,version_index=0;
    std::uint64_t value=0,size=0,entry_file_offset=0,value_file_offset=0;
    bool value_file_backed=false, imported=false, exported=false, version_hidden=false;
    std::string name;
};
struct ElfRelocation {
    std::string source,type_name;
    std::uint64_t entry_file_offset=0,target_va=0,target_file_offset=0;
    std::uint32_t type=0,symbol_index=0;
    std::int64_t addend=0;
    bool has_addend=false,plt=false,target_file_backed=false,symbol_imported=false,symbol_exported=false;
};
struct ElfDynamicInfo {
    std::string state="NOT_PRESENT",error,symbol_count_source;
    std::uint64_t table_file_offset=0,table_size=0;
    std::uint64_t strtab_va=0,strtab_file_offset=0,strtab_size=0;
    std::uint64_t symtab_va=0,symtab_file_offset=0,syment=0;
    std::uint64_t hash_va=0,gnu_hash_va=0,pltgot_va=0;
    std::uint64_t rela_va=0,rela_size=0,rela_ent=0,rel_va=0,rel_size=0,rel_ent=0;
    std::uint64_t jmprel_va=0,pltrel_size=0,pltrel_kind=0;
    std::uint64_t relr_va=0,relr_size=0,relr_ent=0;
    std::uint64_t estimated_memory_bytes=0,memory_budget_bytes=0;
    std::vector<ElfDynamicSymbol> symbols;
    std::vector<ElfRelocation> relocations;
};
struct ElfExtractResult {
    bool success=false;
    std::filesystem::path symbols_csv,relocations_csv;
    std::uint64_t symbol_count=0,relocation_count=0;
    std::string error;
};
struct ElfVersionRecord {
    std::uint16_t index=0,flags=0;
    std::uint64_t file_offset=0,va=0;
    bool base=false;
    std::string source,name,provider;
    std::vector<std::string> parents;
};
struct ElfAbiInfo {
    std::string state="NOT_PRESENT",error;
    std::string soname,rpath,runpath,build_id,build_id_source;
    std::uint64_t soname_file_offset=0,rpath_file_offset=0,runpath_file_offset=0;
    std::uint64_t build_id_file_offset=0;
    std::uint32_t build_id_size=0;
    std::uint64_t versym_va=0,versym_file_offset=0,verdef_va=0,verdef_file_offset=0,verneed_va=0,verneed_file_offset=0;
    std::uint32_t verdef_count=0,verneed_count=0;
    std::vector<ElfVersionRecord> versions;
};
struct ElfUnwindCie {
    std::uint32_t index=0;
    std::uint64_t file_offset=0,va=0,record_size=0;
    std::uint8_t version=0,address_size=0,segment_selector_size=0;
    std::uint64_t code_alignment=0,return_address_register=0;
    std::int64_t data_alignment=0;
    std::string augmentation;
    std::uint8_t fde_encoding=0xff,lsda_encoding=0xff,personality_encoding=0xff;
    std::uint64_t personality_reference_va=0,personality_reference_file_offset=0;
    std::uint64_t cfi_file_offset=0,cfi_size=0; // raw CFI instruction program; syntax is not interpreted here
    bool personality_indirect=false,personality_reference_file_backed=false,personality_imported=false,signal_frame=false;
    std::string personality_symbol;
};
struct ElfUnwindFde {
    std::uint32_t index=0,cie_index=0;
    std::uint64_t file_offset=0,va=0,record_size=0,cie_file_offset=0,cie_va=0;
    std::uint64_t function_start_va=0,function_end_va=0,function_size=0,function_file_offset=0;
    std::uint64_t lsda_reference_va=0,lsda_file_offset=0;
    std::uint64_t cfi_file_offset=0,cfi_size=0; // raw FDE CFI instruction program; bounded syntax consumers may inspect it
    bool function_file_backed=false,lsda_file_backed=false,lsda_indirect=false,header_matched=false;
};
struct ElfUnwindInfo {
    std::string state="NOT_PRESENT",error,source;
    std::uint64_t eh_frame_hdr_va=0,eh_frame_hdr_file_offset=0,eh_frame_hdr_size=0;
    std::uint64_t eh_frame_va=0,eh_frame_file_offset=0,eh_frame_size=0;
    std::uint8_t header_version=0,eh_frame_ptr_encoding=0xff,fde_count_encoding=0xff,table_encoding=0xff;
    std::uint64_t header_fde_count=0;
    std::uint64_t estimated_memory_bytes=0,memory_budget_bytes=0;
    std::vector<ElfUnwindCie> cies;
    std::vector<ElfUnwindFde> fdes;
};
struct ElfUnwindExtractResult {
    bool success=false;
    std::filesystem::path cies_csv,fdes_csv;
    std::uint64_t cie_count=0,fde_count=0;
    std::string error;
};
struct ElfInfo {
    bool valid=false, elf64=false, little_endian=true;
    std::uint16_t type=0, machine=0;
    std::uint64_t entry=0, overlay_offset=0, overlay_size=0;
    std::uint16_t program_header_count=0, section_header_count=0;
    bool section_table_present=false;
    std::string interpreter;
    std::vector<std::string> needed;
    std::vector<ElfSection> sections;
    std::vector<ElfSegment> segments;
    ElfInitInfo init;
    ElfDynamicInfo dynamic;
    ElfAbiInfo abi;
    ImplicitExecutionInfo implicit_exec;
    ElfUnwindInfo unwind;
    std::string error;
};
ElfInfo parse_elf(std::span<const std::uint8_t> data);
ElfInfo parse_elf(const std::filesystem::path& p);
ElfExtractResult extract_elf_dynamic(const ElfInfo& info,const std::filesystem::path& symbols_csv);
ElfUnwindExtractResult extract_elf_unwind(const ElfInfo& info,const std::filesystem::path& fdes_csv);
std::string elf_machine_name(std::uint16_t machine);
std::string elf_type_name(std::uint16_t type);
}
