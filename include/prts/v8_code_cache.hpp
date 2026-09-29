#pragma once

#include "prts/finding.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace prts {

// V8 code-cache data is a serialized compiler artifact. The preprocessor only
// validates the bounded header geometry; it never deserializes or executes the
// payload, and it cannot establish source/runtime compatibility without the
// paired JavaScript source and consumer.
struct V8CodeCacheInfo {
    bool candidate = false;
    bool valid = false;
    std::uint32_t magic = 0;
    std::uint32_t version_hash = 0;
    std::uint32_t source_hash = 0;
    std::uint32_t flag_hash = 0;
    std::uint32_t read_only_snapshot_checksum = 0;
    std::uint32_t payload_length = 0;
    std::uint32_t checksum = 0;
    std::uint32_t source_length = 0;
    bool source_hash_has_wrapped_arguments = false;
    bool source_hash_is_module = false;
    std::uint16_t magic_low16 = 0;
    std::uint64_t header_size = 0;
    std::uint64_t payload_offset = 0;
    std::uint64_t payload_size = 0;
    std::string layout;
    std::string error;
    std::uint64_t error_offset = 0;
};

// |file_size| is optional. When supplied, |data| may be only a bounded prefix
// (as used by directory preflight); header geometry is checked against the
// logical file size without reading the payload.
V8CodeCacheInfo parse_v8_code_cache(std::span<const std::uint8_t> data,
                                    std::uint64_t file_size = 0);
Finding v8_code_cache_finding(const V8CodeCacheInfo& info);

}  // namespace prts
