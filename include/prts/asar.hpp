#pragma once
#include "prts/finding.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
enum class AsarEntryKind { File, Directory, Link };
struct AsarEntry {
    std::string path;
    AsarEntryKind kind=AsarEntryKind::File;
    std::uint64_t offset=0,size=0;
    bool unpacked=false,executable=false;
    std::string link;
    std::string integrity_algorithm,integrity_sha256;
    std::uint64_t integrity_block_size=0,integrity_block_count=0;
};
struct AsarInfo {
    bool valid=false;
    std::filesystem::path archive_path;
    std::uint64_t header_size=0,data_offset=0,packed_bytes=0,trailing_bytes=0;
    std::uint64_t file_count=0,directory_count=0,link_count=0,packed_file_count=0,unpacked_file_count=0,integrity_count=0;
    std::vector<AsarEntry> entries;
    std::vector<std::string> interesting_paths;
    bool package_json_valid=false;
    std::string package_name,package_version,package_main,package_main_resolved;
    std::string error;
};
struct AsarExtractResult {
    bool success=false,core_only=false,budget_exhausted=false;
    std::filesystem::path output_dir;
    std::uint64_t packed_files=0,unpacked_files=0,directories=0,links_skipped=0,output_bytes=0,omitted_count=0,omitted_bytes=0;
    std::uint64_t integrity_verified=0,integrity_mismatches=0;
    std::vector<std::filesystem::path> files;
    std::vector<std::string> warnings;
    std::string error;
};
AsarInfo detect_asar(std::span<const std::uint8_t> data,const std::filesystem::path& archive_path={});
Finding asar_finding(const AsarInfo& info);
AsarExtractResult extract_asar(std::span<const std::uint8_t> data,const AsarInfo& info,const std::filesystem::path& output_dir,bool core_only=false,std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000);
}
