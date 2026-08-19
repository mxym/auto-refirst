#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct FlutterAssetVariant {
    std::string asset;
    std::optional<double> device_pixel_ratio;
    std::vector<std::string> unknown_metadata_keys;
};

struct FlutterAssetEntry {
    std::string key;
    std::vector<FlutterAssetVariant> variants;
};

struct FlutterAssetManifestInfo {
    bool candidate = false;
    bool valid = false;
    bool nonempty = false;
    bool legacy_string_variants = false;
    bool modern_metadata_variants = false;
    std::uint32_t entry_count = 0;
    std::uint32_t variant_count = 0;
    std::uint32_t unknown_metadata_key_count = 0;
    std::uint64_t decoded_node_count = 0;
    std::uint64_t decoded_string_bytes = 0;
    std::vector<FlutterAssetEntry> entries;
    std::vector<std::string> anomalies;
    std::string error;
    std::uint64_t error_offset = 0;
};

FlutterAssetManifestInfo parse_flutter_asset_manifest(std::span<const std::uint8_t> data);

}  // namespace prts
