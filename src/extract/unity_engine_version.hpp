#pragma once
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace prts {
struct UnityEngineVersionValue {
    std::uint32_t major=0,minor=0,patch=0,channel_number=0;
    char channel='a';
};
struct UnityEngineVersionProbe {
    std::string state="UNRESOLVED",source,version,detail;
    std::uint32_t format_version=0;
    std::uint64_t declared_file_size=0;
};
struct UnityEngineVersionEvidence {
    std::string state="ABSENT",version,source,detail;
    std::filesystem::path root,globalgamemanagers_path,data_unity3d_path;
    UnityEngineVersionProbe globalgamemanagers,data_unity3d;
};
bool parse_unity_engine_version_value(std::string_view text,UnityEngineVersionValue& value);
bool parse_unity_engine_version_string(std::string_view text,std::string& canonical);
UnityEngineVersionProbe probe_unity_globalgamemanagers(std::span<const std::uint8_t> prefix,std::uint64_t actual_file_size);
UnityEngineVersionProbe probe_unityfs(std::span<const std::uint8_t> prefix,std::uint64_t actual_file_size);
UnityEngineVersionEvidence aggregate_unity_engine_versions(const std::vector<UnityEngineVersionProbe>& probes);
UnityEngineVersionEvidence inspect_unity_engine_version_near(const std::filesystem::path& anchor);
}
