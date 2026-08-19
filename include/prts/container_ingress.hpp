#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {

struct IngressLayerStatus {
    std::string layer;
    std::string state = "NOT_EVALUATED";
    std::vector<std::string> evidence;
    std::string failure_reason;
    std::string budget_kind;
    std::uint64_t budget_used = 0;
    std::uint64_t budget_limit = 0;
};

struct ContainerIngressLimits {
    std::uint64_t max_input_bytes = 512ull * 1024 * 1024;
    std::uint64_t max_members = 4096;
    std::uint64_t max_path_bytes = 4096;
    std::uint64_t max_member_uncompressed_bytes = 128ull * 1024 * 1024;
    std::uint64_t max_total_declared_uncompressed_bytes = 2ull * 1024 * 1024 * 1024;
    std::uint64_t max_total_materialized_bytes = 256ull * 1024 * 1024;
    std::uint64_t max_probe_bytes = 4ull * 1024 * 1024;
    std::uint64_t max_child_candidates = 128;
    std::uint64_t max_recursive_depth = 4;
    double max_expansion_ratio = 1000.0;
};

struct ContainerMemberIdentity {
    std::uint64_t index = 0;
    std::string name;
    std::string normalized_path;
    std::string state;
    std::string failure_reason;
    std::string offset_space = "parent_input_file";
    std::string coordinate;
    std::string compressed_sha256;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint64_t local_header_offset = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t central_directory_offset = 0;
    std::uint32_t crc32 = 0;
    std::uint16_t method = 0;
    std::uint16_t flags = 0;
    bool directory = false;
    bool symlink = false;
    bool special_file = false;
    bool encrypted = false;
    bool supported_method = false;
    bool safe_path = false;
    bool portable_path = false;
    bool duplicate_path = false;
    bool case_collision = false;
    bool data_descriptor = false;
    bool safe_to_materialize = false;
};

struct ContainerIngressInfo {
    std::string kind = "unknown";
    std::string state = "ABSENT";
    std::string source_identity;
    std::string parent_sha256;
    std::string failure_reason;
    bool recognized = false;
    bool structurally_valid = false;
    bool zip64 = false;
    bool credential_required = false;
    bool policy_gated = false;
    std::uint64_t parent_size = 0;
    std::uint64_t archive_base_offset = 0;
    std::uint64_t central_directory_offset = 0;
    std::uint64_t member_count = 0;
    std::uint64_t regular_file_count = 0;
    std::uint64_t encrypted_file_count = 0;
    std::uint64_t safe_materialization_count = 0;
    std::uint64_t total_compressed_bytes = 0;
    std::uint64_t total_declared_uncompressed_bytes = 0;
    ContainerIngressLimits limits;
    std::vector<std::string> anomalies;
    std::vector<IngressLayerStatus> layers;
    std::vector<ContainerMemberIdentity> members;
};

struct ContainerMaterializationResult {
    std::string state = "REFUSED";
    std::string failure_reason;
    std::filesystem::path output_path;
    std::string parent_sha256;
    std::string member_name;
    std::string compressed_sha256;
    std::string uncompressed_sha256;
    std::string offset_space = "parent_input_file";
    std::string coordinate;
    std::uint64_t member_index = 0;
    std::uint64_t compressed_size = 0;
    std::uint64_t uncompressed_size = 0;
    std::uint64_t bytes_written = 0;
    std::uint64_t data_offset = 0;
    bool success = false;
};

// Cheap recognition only. This intentionally requires an EOCD whose comment reaches EOF;
// a local-header signature alone is not enough to claim a ZIP container.
bool has_strict_zip_eocd(std::span<const std::uint8_t> data);

// Owns only ingress L0/L1. A successful result does not imply bundle semantics,
// executable role, child-analysis eligibility, or semantic decisiveness (L2-L5).
ContainerIngressInfo inspect_zip_container(
    std::span<const std::uint8_t> data,
    std::string source_identity = {},
    const ContainerIngressLimits& limits = {});

// Materializes exactly one already-inspected regular member. The output path is derived
// from the validated normalized member path under output_root; caller-supplied member
// names are never used. Decompression is streamed, bounded, and CRC/size verified.
ContainerMaterializationResult materialize_zip_member(
    std::span<const std::uint8_t> data,
    const ContainerIngressInfo& info,
    std::uint64_t member_index,
    const std::filesystem::path& output_root,
    std::uint64_t current_depth = 0,
    std::uint64_t remaining_output_bytes = ~std::uint64_t{0});

}  // namespace prts
