#pragma once

#include "prts/finding.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct UnrealPakInfo {
    bool candidate = false;
    bool valid = false;
    bool supported_version = false;
    bool encrypted_index = false;
    bool frozen_index = false;
    bool index_hash_checked = false;
    bool index_hash_matches = false;
    bool index_header_valid = false;
    bool secondary_index_hashes_checked = false;
    bool secondary_index_hashes_match = false;
    bool budget_exhausted = false;
    std::string state = "ABSENT";
    std::string footer_profile;
    std::uint32_t version = 0;
    std::uint64_t footer_offset = 0;
    std::uint64_t footer_size = 0;
    std::uint64_t index_offset = 0;
    std::uint64_t index_size = 0;
    std::uint64_t entry_count = 0;
    std::uint32_t secondary_index_count = 0;
    std::uint32_t encoded_entry_bytes = 0;
    std::uint32_t non_encoded_entry_count = 0;
    std::string mount_point;
    std::vector<std::string> compression_methods;
    std::string error;
};

struct UnrealIoStorePartitionInfo {
    std::uint32_t index = 0;
    std::filesystem::path path;
    std::uint64_t required_bytes = 0;
    std::uint64_t file_size = 0;
    std::string state = "NOT_EVALUATED";
    std::string error;
};

struct UnrealIoStoreInfo {
    bool candidate = false;
    bool toc_valid = false;
    bool valid = false;
    bool supported_version = false;
    bool encrypted = false;
    bool signed_container = false;
    bool indexed = false;
    bool signature_table_structurally_present = false;
    bool compressed = false;
    bool pair_checked = false;
    bool pair_valid = false;
    bool budget_exhausted = false;
    bool duplicate_chunk_ids = false;
    bool sibling_inventory_truncated = false;
    std::string state = "ABSENT";
    std::uint8_t version = 0;
    std::uint8_t container_flags = 0;
    std::uint32_t header_size = 0;
    std::uint32_t entry_count = 0;
    std::uint32_t compressed_block_count = 0;
    std::uint32_t compressed_block_entry_size = 0;
    std::uint32_t compression_method_name_count = 0;
    std::uint32_t compression_method_name_length = 0;
    std::uint32_t compression_block_size = 0;
    std::uint32_t directory_index_size = 0;
    std::uint32_t partition_count = 0;
    std::uint32_t perfect_hash_seed_count = 0;
    std::uint32_t chunks_without_perfect_hash_count = 0;
    std::uint64_t partition_size = 0;
    std::uint64_t toc_layout_bytes = 0;
    std::vector<std::string> compression_methods;
    std::vector<UnrealIoStorePartitionInfo> partitions;
    std::string error;
};

struct UnrealInfo {
    bool candidate = false;
    bool valid = false;
    std::string kind;
    std::string state = "ABSENT";
    UnrealPakInfo pak;
    UnrealIoStoreInfo iostore;
    std::string error;
};

// Static recognition only. This parser inventories Pak/IoStore container
// structure and exact .utoc -> .ucas partition geometry. It does not decrypt,
// decompress, enumerate asset semantics, or materialize content.
UnrealInfo detect_unreal_container(std::span<const std::uint8_t> data,
                                   const std::filesystem::path& input);
Finding unreal_container_finding(const UnrealInfo& info);

} // namespace prts
