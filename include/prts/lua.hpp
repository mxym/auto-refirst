#pragma once
#include "prts/finding.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct LuaInstruction {
    std::uint32_t pc=0, raw=0, opcode=0, a=0,b=0,c=0,bx=0;
    std::string name;
};
struct LuaProto {
    std::string path;
    std::string source;
    std::uint32_t line_defined=0,last_line_defined=0;
    std::uint8_t num_params=0,vararg_or_flags=0,max_stack=0;
    std::vector<LuaInstruction> instructions;
    std::vector<std::string> constants;
    std::vector<std::string> local_names;
    std::vector<std::string> upvalue_names;
};
struct LuaInfo {
    bool valid=false,header_valid=false,modified_header=false;
    std::string version;
    std::uint8_t version_byte=0,format=0;
    bool little_endian=true;
    std::uint8_t int_size=0,size_t_size=0,instruction_size=0,integer_size=0,number_size=0;
    std::uint64_t parsed_bytes=0;
    std::vector<LuaProto> protos;
    std::string error;
    std::uint64_t error_offset=0;
};
struct LuaExtractResult { bool success=false; std::filesystem::path disasm_path; std::string error; };
LuaInfo parse_luac(std::span<const std::uint8_t>data);
Finding lua_finding(const LuaInfo&info);
LuaExtractResult extract_lua_disasm(const LuaInfo&info,const std::filesystem::path&out);
}
