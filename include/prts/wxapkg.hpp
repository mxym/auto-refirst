#pragma once
#include "prts/finding.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct WxapkgEntry { std::string name; std::uint32_t offset=0,size=0; };
struct WxapkgInfo {
 bool valid=false,encrypted=false,decrypted=false;
 std::string wxid;
 std::uint32_t index_length=0,body_length=0;
 std::vector<WxapkgEntry> entries;
 std::vector<std::uint8_t> plaintext;
 std::string error;
};
struct WxapkgExtractResult { bool success=false,core_only=false,budget_exhausted=false; std::filesystem::path output_dir; std::uint64_t file_count=0,output_bytes=0,omitted_count=0,omitted_bytes=0; std::vector<std::filesystem::path> files; std::string error; };
WxapkgInfo detect_wxapkg(std::span<const std::uint8_t>data,const std::filesystem::path&path={},std::string wxid={});
Finding wxapkg_finding(const WxapkgInfo&info);
WxapkgExtractResult extract_wxapkg(std::span<const std::uint8_t>original,const WxapkgInfo&info,const std::filesystem::path&out,bool core_only=false,std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000);
}
