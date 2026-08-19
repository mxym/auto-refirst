#pragma once
#include "prts/finding.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
namespace prts {
struct CPythonInfo;
struct PyInstEntry {
    std::uint32_t offset=0, compressed_size=0, uncompressed_size=0;
    std::uint8_t compression_flag=0;
    char typecode=0;
    std::string name;
};
struct PyInstBootstrapModuleMatch {
    std::string name,state,sha256,semantic_sha256,normalized_semantic_sha256,reference_label,semantic_error,normalize_error,normalization_source;
    std::uint64_t size=0,semantic_error_offset=0,normalized_code_units=0;
};
struct PyInstArchiveInfo {
    bool valid=false;
    bool standard_magic=false;
    bool heuristic_cookie=false;
    std::uint64_t cookie_offset=0, archive_start=0, archive_end=0;
    std::uint32_t archive_length=0,toc_offset=0,toc_length=0,python_version=0;
    std::string python_library;
    std::vector<PyInstEntry> entries;
    std::vector<std::string> evidence;
    std::string error;
    std::string bootstrap_reference_status;
    std::string bootstrap_reference_label;
    std::string bootstrap_match_mode;
    std::vector<PyInstBootstrapModuleMatch> bootstrap_modules;

};
enum class PyInstExtractMode { AutoCore, Full };
struct PyInstMaterializedFile {
    std::filesystem::path path;
    std::string role,source_name,priority;
    bool normalized=false,recursive_candidate=false;
};
struct PyInstExtractResult {
    bool success=false;
    PyInstExtractMode mode=PyInstExtractMode::Full;
    std::filesystem::path output_dir,carchive_inventory,pyz_inventory;
    std::vector<std::filesystem::path> files;
    std::vector<PyInstMaterializedFile> materialized;
    std::vector<std::string> warnings;
    std::uint64_t normalized_files=0;
    std::uint64_t target_preserved_files=0;
    std::uint64_t normalized_code_units=0;
    std::uint64_t output_bytes=0;
    std::uint64_t omitted_count=0,omitted_bytes=0,policy_omitted_count=0,policy_omitted_bytes=0;
    std::uint64_t pyz_entry_count=0,pyz_selected_count=0;
    std::uint64_t user_files=0,bootstrap_files=0,runtime_files=0,bulk_files=0;
    bool budget_exhausted=false;
    std::string error;
};
PyInstArchiveInfo detect_pyinstaller(std::span<const std::uint8_t> data);
PyInstExtractResult extract_pyinstaller(std::span<const std::uint8_t> data,
                                       const PyInstArchiveInfo& info,
                                       const std::filesystem::path& output_dir,
                                       const CPythonInfo* cpython=nullptr,
                                       std::uint64_t max_output_bytes=std::numeric_limits<std::uint64_t>::max(),
                                       std::uint32_t max_output_files=std::numeric_limits<std::uint32_t>::max(),
                                       PyInstExtractMode mode=PyInstExtractMode::Full);
std::optional<std::vector<std::uint8_t>> pyinstaller_entry_bytes(std::span<const std::uint8_t> data,const PyInstArchiveInfo& info,const PyInstEntry& entry);
struct PyInstPyzMemberData {
    bool valid=false;
    std::string name,error;
    int type=0;
    std::uint32_t toc_entry_count=0,match_count=0;
    std::array<std::uint8_t,4> pyc_magic{};
    std::vector<std::uint8_t> marshal_payload;
};
// Decode one uniquely named PYZ member from already-validated/decompressed PYZ bytes.
// match_count != 1 is deliberately unresolved; duplicate-name first-match is forbidden.
PyInstPyzMemberData pyinstaller_pyz_member_bytes(std::span<const std::uint8_t> pyz,std::string_view name,
                                                  std::size_t max_output_bytes=16ull*1024*1024);
std::string pyinstaller_entry_role(const PyInstArchiveInfo& info,const PyInstEntry& entry);
Finding pyinstaller_finding(const PyInstArchiveInfo& info);

void analyze_pyinstaller_bootstrap(std::span<const std::uint8_t> data,PyInstArchiveInfo& info,const CPythonInfo* cpython=nullptr);
Finding pyinstaller_bootstrap_finding(const PyInstArchiveInfo& info);
}
