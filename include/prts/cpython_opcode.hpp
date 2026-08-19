#pragma once
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct CPythonDispatchEntry {
    std::uint16_t opcode=0;
    std::uint32_t handler_rva=0;
    std::uint64_t entry_block_hash=0; // normalized <=4-block CFG digest
    std::uint32_t entry_instruction_count=0; // number of blocks included in digest
};
struct CPythonOpcodeMapping {
    std::uint16_t target_opcode=0;
    std::uint32_t target_handler_rva=0;
    std::uint32_t expected_handler_rva=0;
    std::string state; // SLOT_MATCH / PERMUTED / HANDLER_MODIFIED_CANDIDATE / SEMANTIC_* / AMBIGUOUS / UNMAPPED
    std::vector<std::uint16_t> reference_opcodes;
    std::vector<std::string> reference_names;
};
struct CPythonDispatchInfo {
    bool attempted=false;
    bool table_found=false;
    std::string state; // TABLE_RECOVERED / TABLE_NOT_FOUND / UNSUPPORTED
    std::uint32_t evaluator_rva=0;
    std::uint32_t table_load_rva=0;
    std::uint32_t table_rva=0;
    std::uint16_t table_first_opcode=0;
    std::uint16_t table_entry_count=0;
    std::uint32_t executable_entries=0;
    std::uint32_t unique_handler_count=0;
    std::vector<CPythonDispatchEntry> entries;
    std::string reference_status; // REFERENCE_MATCH / OPCODE_PERMUTATION / HANDLER_MODIFIED / ...
    std::string reference_version;
    std::uint32_t slot_matches=0,permuted_slots=0,handler_modified=0,semantic_mapped=0,ambiguous=0,unmapped=0;
    std::vector<CPythonOpcodeMapping> mappings;
    std::string error;
};
CPythonDispatchInfo recover_cpython_dispatch(std::span<const std::uint8_t> data,const PeInfo& pe,bool fingerprint_handlers=true);
CPythonDispatchInfo analyze_cpython_dispatch(std::span<const std::uint8_t> data,const PeInfo& pe,std::uint32_t version_hex,bool native_comparable,bool exact_reference_match=false);
}
