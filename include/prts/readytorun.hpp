#pragma once

#include "prts/finding.hpp"
#include "prts/pe.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct ReadyToRunSection {
    std::uint32_t type = 0;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    std::uint64_t file_offset = 0;
    std::string type_name;
};

// ReadyToRun is a native-code sidecar inside a CLI image. This parser only
// validates the header, the sorted section directory, and file-backed ranges;
// it does not decode fixups, native methods, or execute the image.
struct ReadyToRunInfo {
    bool candidate = false;
    bool valid = false;
    std::string state = "NOT_PRESENT";
    std::string source;
    std::string error;
    std::uint64_t header_offset = 0;
    std::uint32_t header_rva = 0;
    std::uint32_t managed_native_rva = 0;
    std::uint32_t managed_native_size = 0;
    std::uint16_t major_version = 0;
    std::uint16_t minor_version = 0;
    std::uint32_t flags = 0;
    std::uint32_t unknown_flags = 0;
    std::uint32_t section_count = 0;
    std::uint64_t header_size = 0;
    bool composite = false;
    bool component = false;
    bool partial = false;
    bool embedded_msil = false;
    bool platform_native_image = false;
    bool stripped_il_bodies = false;
    bool stripped_inlining_info = false;
    bool stripped_debug_info = false;
    std::uint32_t import_section_count = 0;
    std::uint32_t runtime_function_section_count = 0;
    std::uint32_t method_entrypoint_section_count = 0;
    std::uint32_t exception_section_count = 0;
    std::vector<ReadyToRunSection> sections;
};

ReadyToRunInfo detect_ready_to_run(std::span<const std::uint8_t> data,
                                   const PeInfo& pe);
Finding ready_to_run_finding(const ReadyToRunInfo& info);

}  // namespace prts
