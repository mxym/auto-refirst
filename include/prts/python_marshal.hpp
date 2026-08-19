#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct CPythonDispatchInfo;
struct PythonMarshalCodeRange {
    std::uint64_t offset=0,size=0;
    std::string name;
    std::string filename;
    std::string qualname;
    std::int32_t first_line=0;
};
struct PythonMarshalSemantic {
    bool valid=false;
    int python_minor=0;
    std::string sha256;
    std::uint64_t error_offset=0;
    std::string error;
    std::uint64_t object_count=0;
    std::uint64_t code_object_count=0;
    std::vector<PythonMarshalCodeRange> code_ranges;
};
enum class PythonMarshalScalarKind : std::uint8_t { Other, Integer, String };
struct PythonMarshalScalar {
    PythonMarshalScalarKind kind=PythonMarshalScalarKind::Other;
    std::int64_t integer=0;
    std::string text;
};
struct PythonMarshalRootCode {
    bool valid=false;
    int python_minor=0;
    std::uint64_t code_offset=0;
    std::vector<std::uint8_t> code;
    std::vector<PythonMarshalScalar> constants;
    std::vector<std::string> names;
    std::uint64_t error_offset=0;
    std::string error;
};
struct PythonMarshalOpcodeRewrite {
    bool valid=false;
    bool changed=false;
    int python_minor=0;
    std::uint64_t code_object_count=0;
    std::uint64_t code_units=0;
    std::uint64_t rewritten_code_units=0;
    std::vector<std::uint16_t> unmapped_opcodes;
    std::vector<std::uint8_t> bytes;
    std::string error;
};
PythonMarshalSemantic semantic_hash_python_marshal(std::span<const std::uint8_t> data,int python_version);
PythonMarshalRootCode inspect_python_marshal_root_code(std::span<const std::uint8_t> data,int python_version);
PythonMarshalOpcodeRewrite remap_python_marshal_opcodes(std::span<const std::uint8_t> data,int python_version,const std::array<std::int16_t,256>& target_to_output);
PythonMarshalOpcodeRewrite normalize_python_marshal_opcodes(std::span<const std::uint8_t> data,int python_version,const CPythonDispatchInfo& dispatch);
}
