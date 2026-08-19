#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct AutoItRecord {
    std::string kind; // script_token / script_text / resource
    std::string subtype,source_path,output_name,decoded_sha256;
    std::uint64_t record_offset=0,stored_data_offset=0,compressed_size=0,output_size=0;
    bool compressed=false,crc_valid=false,compressed_magic_standard=true;
};
struct AutoItInfo {
    bool valid=false;
    std::string version="EA06",container;
    bool standard_marker=false;
    std::uint64_t container_offset=0,container_size=0,stream_offset=0,stream_end=0;
    std::string resource_type,resource_name;
    std::uint64_t pseudo_records=0;
    std::vector<AutoItRecord> records;
    bool script_found=false,script_tokenized=false,token_valid=false;
    std::uint32_t token_lines=0;
    std::uint64_t token_bytes=0,token_error_offset=0;
    std::uint32_t token_unknown_opcode=0;
    std::string token_error,script_source,error;
};
struct AutoItExtractResult {
    bool success=false,scripts_only=false;
    std::filesystem::path output_dir;
    std::vector<std::filesystem::path> files;
    std::uint64_t records_verified=0,resources_written=0,scripts_written=0;
    std::vector<std::string> warnings;
    std::string error;
};
AutoItInfo detect_autoit(std::span<const std::uint8_t> data,const PeInfo& pe,const std::filesystem::path& input,bool static_hint);
Finding autoit_finding(const AutoItInfo& info);
AutoItExtractResult extract_autoit(std::span<const std::uint8_t> data,const AutoItInfo& info,const std::filesystem::path& output_dir,bool scripts_only=false);
}
