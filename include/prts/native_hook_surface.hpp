#pragma once

#include "prts/finding.hpp"
#include "prts/pe.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace prts {

// Static evidence that code in the current image writes an import-address-table
// slot or an executable image range while also exposing a loader/patch bridge.
// This is a bounded triage route: it does not infer the value written to the
// slot, the runtime call path, or whether the hook is ever installed.
struct NativeHookSurfaceInfo {
    bool candidate = false;
    bool entry_window = false;
    std::uint32_t function_count = 0;
    std::uint32_t iat_write_count = 0;
    std::uint32_t executable_write_count = 0;
    std::uint32_t bridge_call_count = 0;
    std::vector<std::string> iat_targets;
    std::vector<std::string> bridge_apis;
    std::vector<std::uint32_t> write_rvas;
    std::vector<std::uint32_t> bridge_call_rvas;
    std::string state;
    std::string variant;
};

NativeHookSurfaceInfo analyze_native_hook_surface(std::span<const std::uint8_t> data,
                                                  const PeInfo& pe);
std::optional<Finding> native_hook_surface_finding(const NativeHookSurfaceInfo& info);

} // namespace prts
