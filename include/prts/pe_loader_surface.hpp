#pragma once

#include "prts/finding.hpp"
#include "prts/pe.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

// A bounded static route for PE images whose loader-facing shape differs from
// an ordinary link-time import surface.  The result is deliberately a route
// hint: these signals can also occur in plugin hosts, unpackers and updaters.
struct PeLoaderSurfaceInfo {
    bool candidate = false;
    std::string state = "ABSENT";
    std::string variant;
    std::uint32_t evidence_categories = 0;
    std::uint32_t import_modules = 0;
    std::uint32_t import_functions = 0;
    std::uint32_t resolver_api_count = 0;
    std::uint32_t resolver_module_count = 0;
    std::uint32_t tls_callback_count = 0;
    bool relocation_directory = false;
    bool low_import_surface = false;
    bool entrypoint_nonstandard_section = false;
    bool entrypoint_writable_executable = false;
    bool relocation_geometry_valid = false;
    std::uint32_t entry_rva = 0;
    std::uint32_t relocation_rva = 0;
    std::uint32_t relocation_size = 0;
    std::uint32_t relocation_block_count = 0;
    std::uint32_t relocation_entry_count = 0;
    std::uint32_t tls_directory_rva = 0;
    std::string entry_section;
    std::vector<std::string> resolver_apis;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
    std::vector<RangeRef> ranges;
};

PeLoaderSurfaceInfo analyze_pe_loader_surface(std::span<const std::uint8_t> data, const PeInfo& pe);
Finding pe_loader_surface_finding(const PeLoaderSurfaceInfo& info);

} // namespace prts
