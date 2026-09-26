#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace prts {
enum class PreflightFormat { Unknown, PE, ELF, MachO, JvmClass, MachOOrJvm, Hermes, Lua, PythonBytecode, Wasm, Dex, Zip, IoStore, GodotPck, Script };
inline constexpr std::size_t kPreflightPrefixBytes=64*1024;

// A cheap admission hint, never a complete format/semantic validation or an
// authorization decision. Names and extensions are deliberately not inputs.
struct PreflightHeader {
    PreflightFormat format=PreflightFormat::Unknown;
    std::string_view type_hint;
    std::string_view role;
    std::string_view confidence="low";
    std::string_view reason;
    int priority_boost=0;
    bool native_executable_hint=false;
};
PreflightHeader probe_preflight_header(std::span<const std::uint8_t> prefix,std::uint64_t file_size);
}
