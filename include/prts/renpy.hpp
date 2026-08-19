#pragma once
#include "prts/finding.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct RenpySlot { std::uint32_t id=0,start=0,length=0; };
struct RenpyRpycInfo {
 bool valid=false,legacy=false,modified_header=false;
 std::string variant,extractor;
 std::vector<RenpySlot> slots;
 std::vector<std::string> layers;
 std::vector<std::string> globals;
 std::vector<std::string> string_hints;
 std::uint32_t pickle_protocol=0;
 std::vector<std::uint8_t> pickle_payload;
 std::string error;
};
struct RenpyExtractResult { bool success=false; std::filesystem::path pickle_path; std::string error; };
struct RenpyRpaEntry { std::string name; std::uint64_t offset=0,length=0; std::vector<std::uint8_t> prefix; };
struct RenpyRpaInfo { bool valid=false; std::string version; std::uint64_t index_offset=0; std::uint32_t key=0; std::vector<RenpyRpaEntry> entries; std::string error; };
struct RenpyRpaExtractResult { bool success=false,core_only=false,budget_exhausted=false; std::filesystem::path output_dir; std::uint64_t file_count=0,output_bytes=0,omitted_count=0,omitted_bytes=0; std::vector<std::filesystem::path> files; std::string error; };
RenpyRpycInfo detect_rpyc(std::span<const std::uint8_t>data,const std::filesystem::path&path={});
Finding renpy_rpyc_finding(const RenpyRpycInfo&info);
RenpyExtractResult extract_rpyc(const RenpyRpycInfo&info,const std::filesystem::path&out);
RenpyRpaInfo detect_rpa(std::span<const std::uint8_t>data,const std::filesystem::path&path={});
Finding renpy_rpa_finding(const RenpyRpaInfo&info);
RenpyRpaExtractResult extract_rpa(std::span<const std::uint8_t>data,const RenpyRpaInfo&info,const std::filesystem::path&out,bool core_only=false,std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000);
}
