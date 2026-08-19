#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace prts {
struct CPythonInfo;
struct PyInstArchiveInfo;
struct CPythonCompilerProbeCode {
    std::string path;
    std::vector<std::uint8_t> code;
};
struct CPythonCompilerOpcodeMapping {
    std::uint16_t target_opcode=0;
    std::uint16_t reference_opcode=0;
    std::uint64_t observations=0;
};
struct CPythonCompilerProbeInfo {
    bool attempted=false;
    bool launched=false;
    bool success=false;
    std::string state; // REFERENCE_MATCH / OPCODE_PERMUTATION_RECOVERED / COMPILER_DIFFERENT / NO_REFERENCE / FAILED
    std::string reference_version;
    std::uint32_t code_objects=0;
    std::uint64_t code_units=0;
    std::uint64_t oparg_matches=0;
    std::uint32_t observed_opcodes=0;
    std::uint32_t changed_opcodes=0;
    std::vector<CPythonCompilerOpcodeMapping> mappings;
    std::string error;
};
CPythonCompilerProbeInfo compare_cpython_compiler_probe(std::uint32_t version_hex,const std::vector<CPythonCompilerProbeCode>& target);
bool run_cpython_compiler_probe_for_input(const std::filesystem::path& input,const PyInstArchiveInfo* pyinstaller,CPythonInfo& cpython,std::uint32_t timeout_ms,std::string& error);
int cpython_probe_child_main();
}
