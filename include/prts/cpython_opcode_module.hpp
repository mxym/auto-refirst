#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct CPythonOpcodeDefinition {
    std::string name;
    std::uint16_t opcode=0;
};

// Parsed from a caller-supplied stock Lib/opcode.py.  The parser deliberately
// does not assign provenance/trust to the bytes; Q's trust contract keeps
// authentication of the exact reference as a separate decision.
struct CPythonOpcodeSourceReference {
    bool valid=false;
    std::string sha256;
    std::vector<CPythonOpcodeDefinition> definitions;
    std::string error;
};

struct CPythonOpcodeModuleMapping {
    std::uint16_t target_opcode=0;
    std::uint16_t reference_opcode=0;
    std::string name;
    std::string evidence;
};

// A bounded structural delta recovered from a CPython 3.8 opcode.py marshal
// code object.  complete_named_opcode_map means every named opcode in the
// supplied exact source reference has a unique target value.  Reserved/blank
// opcode slots are intentionally outside this scope.
struct CPythonOpcodeModuleDelta {
    bool attempted=false;
    bool valid=false;
    bool changed=false;
    bool complete_named_opcode_map=false;
    int python_minor=0;
    std::string state;
    std::string reference_sha256;
    std::uint32_t initial_constant_pairs=0;
    std::uint32_t bootstrap_helper_calls=0;
    std::uint32_t recovered_call_pairs=0;
    std::uint32_t validated_one_hop_helper_aliases=0;
    std::uint32_t validated_one_hop_integer_bindings=0;
    std::uint32_t validated_helper_calls=0;
    std::uint32_t changed_opcodes=0;
    std::array<std::int16_t,256> target_to_reference{};
    std::vector<CPythonOpcodeModuleMapping> mappings;
    std::string error;
};

CPythonOpcodeSourceReference parse_cpython_opcode_source_reference(std::span<const std::uint8_t> source);
CPythonOpcodeModuleDelta recover_cpython38_opcode_module_delta(
    std::span<const std::uint8_t> marshal_payload,
    const CPythonOpcodeSourceReference& reference);

}
