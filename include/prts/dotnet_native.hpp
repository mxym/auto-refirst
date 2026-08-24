#pragma once
#include "prts/elf.hpp"
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct DotNetBundleEntry {
    std::uint32_t index=0;
    std::uint64_t offset=0,size=0,compressed_size=0,stored_size=0;
    std::uint8_t type=0;
    bool compressed=false;
    std::string type_name,relative_path;
};

struct DotNetBundleInfo {
    bool candidate=false,valid=false;
    std::string state="NOT_PRESENT",error;
    std::uint64_t locator_offset=0,header_offset=0,manifest_end=0,trailing_bytes=0;
    std::uint32_t major_version=0,minor_version=0,file_count=0;
    std::string bundle_id;
    std::uint64_t deps_json_offset=0,deps_json_size=0;
    std::uint64_t runtimeconfig_json_offset=0,runtimeconfig_json_size=0;
    std::uint64_t flags=0,stored_bytes=0,uncompressed_bytes=0,compressed_file_count=0;
    std::string integrity_state="NOT_AVAILABLE_IN_FORMAT";
    std::vector<DotNetBundleEntry> entries;
};

struct NativeAotSectionRow {
    std::uint32_t id=0,flags=0;
    std::uint64_t start_va=0,end_va=0;
};

struct NativeAotInfo {
    bool candidate=false,valid=false;
    std::string state="NOT_PRESENT",platform,error;
    std::uint64_t modules_offset=0,modules_size=0,header_offset=0,header_va=0;
    std::uint16_t major_version=0,minor_version=0,section_count=0;
    std::uint8_t entry_size=0,entry_type=0;
    std::uint64_t raw_rtr_magic_count=0,valid_rtr_header_count=0,native_section_id_count=0;
    bool has_managed_code_section=false,has_dotnet_eh_table=false,has_hydrated_section=false;
    std::vector<NativeAotSectionRow> sections;
};

DotNetBundleInfo detect_dotnet_bundle(std::span<const std::uint8_t> data,const PeInfo& pe,const ElfInfo& elf);
Finding dotnet_bundle_finding(const DotNetBundleInfo& info);
NativeAotInfo detect_native_aot(std::span<const std::uint8_t> data,const PeInfo& pe,const ElfInfo& elf);
Finding native_aot_finding(const NativeAotInfo& info);
} // namespace prts
