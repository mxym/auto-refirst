#include "prts/v8_code_cache.hpp"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>

namespace prts {
namespace {

constexpr std::uint32_t kMagicPrefix = 0xC0DE0000u;
constexpr std::uint32_t kMagicMask = 0xFFFF0000u;
constexpr std::uint32_t kSourceLengthMask = (std::uint32_t{1} << 29) - 1;
constexpr std::uint32_t kWrappedArgumentsBit = std::uint32_t{1} << 29;
constexpr std::uint32_t kModuleBit = std::uint32_t{1} << 30;
constexpr std::uint32_t kLegacyModuleBit = std::uint32_t{1} << 31;
constexpr std::uint64_t kLegacyHeaderSize = 24;
constexpr std::uint64_t kModernHeaderSize = 32;

bool has_bytes(std::span<const std::uint8_t> data, std::size_t offset,
               std::size_t count) {
    return offset <= data.size() && count <= data.size() - offset;
}

std::uint32_t u32(std::span<const std::uint8_t> data, std::size_t offset) {
    if (!has_bytes(data, offset, sizeof(std::uint32_t))) return 0;
    return std::uint32_t(data[offset]) |
           (std::uint32_t(data[offset + 1]) << 8) |
           (std::uint32_t(data[offset + 2]) << 16) |
           (std::uint32_t(data[offset + 3]) << 24);
}

std::string hex32(std::uint32_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
    return out.str();
}

void decode_source_hash(V8CodeCacheInfo& info, bool modern) {
    if (modern) {
        info.source_length = info.source_hash & kSourceLengthMask;
        info.source_hash_has_wrapped_arguments =
            (info.source_hash & kWrappedArgumentsBit) != 0;
        info.source_hash_is_module = (info.source_hash & kModuleBit) != 0;
    } else {
        info.source_length = info.source_hash & ~kLegacyModuleBit;
        info.source_hash_is_module = (info.source_hash & kLegacyModuleBit) != 0;
    }
}

}  // namespace

V8CodeCacheInfo parse_v8_code_cache(std::span<const std::uint8_t> data,
                                    std::uint64_t file_size) {
    V8CodeCacheInfo out;
    const auto logical_size = file_size == 0 ? std::uint64_t(data.size()) : file_size;
    if (logical_size < sizeof(std::uint32_t) || data.size() < sizeof(std::uint32_t)) {
        return out;
    }

    out.magic = u32(data, 0);
    if ((out.magic & kMagicMask) != kMagicPrefix) return out;
    out.candidate = true;
    out.magic_low16 = static_cast<std::uint16_t>(out.magic & 0xffffu);

    if (logical_size > std::numeric_limits<std::uint32_t>::max()) {
        out.error = "V8 code-cache file exceeds the bounded 32-bit serialized length field";
        out.error_offset = 0;
        return out;
    }
    if (data.size() < kLegacyHeaderSize) {
        out.error = "V8 code-cache header is truncated";
        out.error_offset = data.size();
        return out;
    }

    out.version_hash = u32(data, 4);
    out.source_hash = u32(data, 8);
    out.flag_hash = u32(data, 12);
    const auto legacy_payload = u32(data, 16);
    const auto legacy_checksum = u32(data, 20);
    const bool legacy_geometry = logical_size >= kLegacyHeaderSize &&
                                 std::uint64_t(legacy_payload) + kLegacyHeaderSize == logical_size;

    bool modern_geometry = false;
    std::uint32_t modern_snapshot = 0;
    std::uint32_t modern_payload = 0;
    std::uint32_t modern_checksum = 0;
    if (data.size() >= kModernHeaderSize) {
        modern_snapshot = u32(data, 16);
        modern_payload = u32(data, 20);
        modern_checksum = u32(data, 24);
        modern_geometry = logical_size >= kModernHeaderSize &&
                          std::uint64_t(modern_payload) + kModernHeaderSize == logical_size;
    }

    if (legacy_geometry == modern_geometry) {
        out.error = legacy_geometry
                        ? "V8 code-cache header matches both legacy and modern payload layouts"
                        : "V8 serializer magic is present but payload length does not close over the file";
        out.error_offset = 16;
        return out;
    }

    const bool modern = modern_geometry;
    out.layout = modern ? "modern_7_word_header" : "legacy_6_word_header";
    out.header_size = modern ? kModernHeaderSize : kLegacyHeaderSize;
    out.payload_offset = out.header_size;
    out.payload_length = modern ? modern_payload : legacy_payload;
    out.payload_size = out.payload_length;
    out.read_only_snapshot_checksum = modern ? modern_snapshot : 0;
    out.checksum = modern ? modern_checksum : legacy_checksum;
    decode_source_hash(out, modern);

    if (out.version_hash == 0 || out.flag_hash == 0) {
        out.error = "V8 code-cache header has an empty version or flag hash";
        out.error_offset = out.version_hash == 0 ? 4 : 12;
        return out;
    }
    if (out.payload_length == 0) {
        out.error = "V8 code-cache payload is empty";
        out.error_offset = modern ? 20 : 16;
        return out;
    }
    if (out.source_length > logical_size) {
        out.error = "V8 code-cache source-hash length exceeds the logical file size";
        out.error_offset = 8;
        return out;
    }
    out.valid = true;
    return out;
}

Finding v8_code_cache_finding(const V8CodeCacheInfo& info) {
    Finding f;
    f.kind = "bytecode";
    f.family = "V8 JavaScript code cache";
    f.variant = info.layout.empty() ? "serializer-header-candidate" : info.layout;
    f.fields["offset_space"] = "current_input_file";
    f.fields["magic"] = hex32(info.magic);
    f.fields["magic_low16"] = std::to_string(info.magic_low16);
    f.fields["version_hash"] = hex32(info.version_hash);
    f.fields["source_hash"] = hex32(info.source_hash);
    f.fields["source_length"] = std::to_string(info.source_length);
    f.fields["source_hash_wrapped_arguments"] =
        info.source_hash_has_wrapped_arguments ? "true" : "false";
    f.fields["source_hash_is_module"] = info.source_hash_is_module ? "true" : "false";
    f.fields["flag_hash"] = hex32(info.flag_hash);
    f.fields["header_size"] = std::to_string(info.header_size);
    f.fields["payload_offset"] = std::to_string(info.payload_offset);
    f.fields["payload_size"] = std::to_string(info.payload_size);
    f.fields["payload_length_field"] = std::to_string(info.payload_length);
    f.fields["checksum"] = hex32(info.checksum);
    if (info.header_size == kModernHeaderSize)
        f.fields["read_only_snapshot_checksum"] = hex32(info.read_only_snapshot_checksum);

    if (!info.valid) {
        f.state = "FAILED";
        f.confidence = .35;
        f.evidence.push_back("V8 serializer magic is present at file offset 0");
        if (!info.error.empty()) {
            std::ostringstream detail;
            detail << info.error << " at 0x" << std::hex << info.error_offset;
            f.negative_evidence.push_back(detail.str());
        }
        f.suggested_actions = {"inspect the producer/runtime version before using a V8-aware cache tool"};
        return f;
    }

    f.state = "LIKELY";
    f.confidence = .82;
    f.evidence = {
        "V8 serializer magic and bounded version/source/flag fields validated",
        "aligned payload length closes exactly over the current input file",
    };
    f.negative_evidence = {
        "source compatibility and runtime acceptance cannot be checked without the paired JavaScript source and V8 consumer",
        "serialized cache payload remains opaque; no bytecode deserialization or execution was attempted",
    };
    f.ranges.push_back(file_offset_range(info.header_size, info.payload_size,
                                         "V8 serialized code-cache payload"));
    f.suggested_actions = {
        "pair the cache with its JavaScript source and matching Node/V8 build",
        "use a V8-aware inspector or consumer-side cachedDataRejected check before deeper analysis",
    };
    return f;
}

}  // namespace prts
