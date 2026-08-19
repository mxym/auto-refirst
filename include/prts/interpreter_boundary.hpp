#pragma once
#include "prts/elf.hpp"
#include "prts/finding.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct InterpreterBoundaryInfo {
    bool analyzed=false;
    std::string state="UNRESOLVED";
    std::string boundary_kind;
    std::string host_role;
    std::string target_role;
    std::string semantic_requirement;
    std::string runtime_family;
    bool external_program_argument_required=false;
    bool program_buffer_chain_confirmed=false;
    bool exact_program_target_bound=false;
    std::string exact_program_target_state="UNRESOLVED";
    std::uint64_t main_va=0;
    std::uint64_t loader_va=0;
    std::uint64_t dispatch_va=0;
    std::uint32_t evidence_count=0;
    std::uint32_t functions_examined=0;
    std::uint32_t decoded_instructions=0;
    bool budget_exhausted=false;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
};

// AW is guidance only.  This analyzer never executes the input, emulates a VM,
// infers opcode meanings, or binds a runtime argv value to a sibling artifact.
InterpreterBoundaryInfo analyze_interpreter_boundary(std::span<const std::uint8_t> data,
                                                      const ElfInfo& elf,
                                                      const std::filesystem::path& input);
Finding interpreter_boundary_finding(const InterpreterBoundaryInfo& info);

}
