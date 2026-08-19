#include "prts/container_ingress.hpp"
#include "prts/sha256.hpp"

#define MINIZ_NO_ZLIB_APIS
#include "miniz.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <cstring>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace prts {
namespace {

constexpr std::uint32_t kLocalHeaderSig = 0x04034b50u;
constexpr std::uint32_t kCentralHeaderSig = 0x02014b50u;
constexpr std::uint32_t kEocdSig = 0x06054b50u;
constexpr std::uint32_t kDataDescriptorSig = 0x08074b50u;
constexpr std::uint16_t kZipFlagEncrypted = 0x0001u;
constexpr std::uint16_t kZipFlagDataDescriptor = 0x0008u;
constexpr std::uint16_t kZipFlagStrongEncryption = 0x0040u;
constexpr std::size_t kMaxAnomalySamples = 128;
constexpr std::size_t kIoChunk = 1u << 20;

std::uint16_t le16(std::span<const std::uint8_t> b, std::uint64_t off) {
    if (off > b.size() || 2 > b.size() - static_cast<std::size_t>(off)) return 0;
    return std::uint16_t(b[static_cast<std::size_t>(off)]) |
           (std::uint16_t(b[static_cast<std::size_t>(off + 1)]) << 8);
}

std::uint32_t le32(std::span<const std::uint8_t> b, std::uint64_t off) {
    if (off > b.size() || 4 > b.size() - static_cast<std::size_t>(off)) return 0;
    const auto p = static_cast<std::size_t>(off);
    return std::uint32_t(b[p]) | (std::uint32_t(b[p + 1]) << 8) |
           (std::uint32_t(b[p + 2]) << 16) | (std::uint32_t(b[p + 3]) << 24);
}

std::uint64_t le64(std::span<const std::uint8_t> b, std::uint64_t off) {
    return std::uint64_t(le32(b, off)) | (std::uint64_t(le32(b, off + 4)) << 32);
}

bool add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (a > std::numeric_limits<std::uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool span_in_bounds(std::span<const std::uint8_t> b, std::uint64_t off, std::uint64_t len) {
    return off <= b.size() && len <= b.size() - static_cast<std::size_t>(off);
}

std::string miniz_error(mz_zip_archive& zip) {
    const auto err = mz_zip_get_last_error(&zip);
    const auto* text = mz_zip_get_error_string(err);
    return text ? text : "unknown miniz error";
}

struct ZipCloser {
    mz_zip_archive* zip = nullptr;
    ~ZipCloser() { if (zip && zip->m_pState) mz_zip_reader_end(zip); }
};

void push_anomaly(ContainerIngressInfo& out, std::string s) {
    if (out.anomalies.size() < kMaxAnomalySamples) out.anomalies.push_back(std::move(s));
}

IngressLayerStatus layer(std::string name, std::string budget_kind, std::uint64_t limit) {
    IngressLayerStatus s;
    s.layer = std::move(name);
    s.budget_kind = std::move(budget_kind);
    s.budget_limit = limit;
    return s;
}

std::vector<IngressLayerStatus> initial_layers(const ContainerIngressLimits& limits, std::uint64_t input_bytes) {
    std::vector<IngressLayerStatus> x;
    x.reserve(6);
    x.push_back(layer("L0_TRANSPORT_CONTAINER", "input_bytes", limits.max_input_bytes));
    x.back().budget_used = input_bytes;
    x.push_back(layer("L1_MEMBER_IDENTITY", "member_count", limits.max_members));
    x.push_back(layer("L2_INNER_FORMAT_MEDIA", "probe_bytes", limits.max_probe_bytes));
    x.push_back(layer("L3_EXECUTABLE_DATA_ROLE", "candidate_count", limits.max_child_candidates));
    x.push_back(layer("L4_CHILD_ANALYSIS_ELIGIBILITY", "materialized_bytes", limits.max_total_materialized_bytes));
    x.push_back(layer("L5_SEMANTIC_ROUTING_PROVENANCE", "recursive_depth", limits.max_recursive_depth));
    return x;
}

std::string lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (const unsigned char c : s) out.push_back(static_cast<char>(std::tolower(c)));
    return out;
}

bool windows_reserved_component(std::string_view component) {
    auto low = lower_ascii(component);
    const auto dot = low.find('.');
    const auto base = low.substr(0, dot);
    if (base == "con" || base == "prn" || base == "aux" || base == "nul" ||
        base == "conin$" || base == "conout$") return true;
    if (base.size() == 4 && (base.starts_with("com") || base.starts_with("lpt")) &&
        base[3] >= '1' && base[3] <= '9') return true;
    return false;
}

bool safe_relative_name(std::string_view raw, bool directory, std::uint64_t max_bytes,
                        std::string& normalized, bool& portable_ascii) {
    normalized.clear();
    portable_ascii = true;
    if (raw.empty() || raw.size() > max_bytes || raw.front() == '/' || raw.front() == '\\') return false;
    std::string tmp;
    tmp.reserve(raw.size());
    for (const unsigned char c : raw) {
        if (c < 0x20 || c == 0x7f || c == ':') return false;
        if (c >= 0x80) portable_ascii = false;
        tmp.push_back(c == '\\' ? '/' : static_cast<char>(c));
    }
    while (directory && !tmp.empty() && tmp.back() == '/') tmp.pop_back();
    if (tmp.empty()) return directory;
    std::size_t start = 0;
    while (start <= tmp.size()) {
        const auto slash = tmp.find('/', start);
        const auto end = slash == std::string::npos ? tmp.size() : slash;
        const auto part = std::string_view(tmp).substr(start, end - start);
        if (part.empty() || part == "." || part == ".." || part.back() == '.' || part.back() == ' ' ||
            windows_reserved_component(part)) return false;
        if (!normalized.empty()) normalized += '/';
        normalized.append(part);
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return !normalized.empty();
}

bool descriptor_matches(std::span<const std::uint8_t> data, std::uint64_t off,
                        std::uint32_t crc, std::uint64_t comp, std::uint64_t uncomp) {
    for (const bool signature : {false, true}) {
        std::uint64_t p = off;
        if (signature) {
            if (!span_in_bounds(data, p, 4) || le32(data, p) != kDataDescriptorSig) continue;
            p += 4;
        }
        if (!span_in_bounds(data, p, 12)) continue;
        if (le32(data, p) != crc) continue;
        if (std::uint64_t(le32(data, p + 4)) == comp && std::uint64_t(le32(data, p + 8)) == uncomp) return true;
        if (!span_in_bounds(data, p, 20)) continue;
        if (le64(data, p + 4) == comp && le64(data, p + 12) == uncomp) return true;
    }
    return false;
}

void fail_structure(ContainerIngressInfo& out, std::string reason) {
    out.state = "MALFORMED";
    out.structurally_valid = false;
    out.failure_reason = std::move(reason);
    out.layers[0].state = "FAILED";
    out.layers[0].failure_reason = out.failure_reason;
    out.layers[1].state = "NOT_EVALUATED";
}

void finalize_member_state(ContainerMemberIdentity& e, const ContainerIngressLimits& limits) {
    e.safe_to_materialize = false;
    e.failure_reason.clear();
    if (!e.safe_path) { e.state = "UNSAFE_PATH"; e.failure_reason = "member path is not a portable safe relative path"; return; }
    if (!e.portable_path) { e.state = "PORTABILITY_UNVERIFIED"; e.failure_reason = "non-ASCII path requires a Unicode normalization/casefold policy"; return; }
    if (e.symlink) { e.state = "LINK_REFUSED"; e.failure_reason = "ZIP symlink materialization is forbidden"; return; }
    if (e.special_file) { e.state = "SPECIAL_FILE_REFUSED"; e.failure_reason = "non-regular ZIP filesystem object is forbidden"; return; }
    if (e.directory) { e.state = "DIRECTORY"; return; }
    if (e.duplicate_path) { e.state = "DUPLICATE_PATH_REFUSED"; e.failure_reason = "normalized path is duplicated"; return; }
    if (e.case_collision) { e.state = "CASE_COLLISION_REFUSED"; e.failure_reason = "portable ASCII case-fold path collision"; return; }
    if (e.encrypted) { e.state = "EXPLICIT_CREDENTIAL_REQUIRED"; e.failure_reason = "encrypted ZIP member; no credential guessing is attempted"; return; }
    if (!e.supported_method) { e.state = "UNSUPPORTED_METHOD"; e.failure_reason = "compression/encryption method is unsupported by the bounded decoder"; return; }
    if (e.uncompressed_size > limits.max_member_uncompressed_bytes) {
        e.state = "BUDGET_REFUSED"; e.failure_reason = "declared uncompressed member size exceeds limit"; return;
    }
    const double ratio = e.compressed_size == 0 ? (e.uncompressed_size == 0 ? 1.0 : std::numeric_limits<double>::infinity())
                                               : static_cast<double>(e.uncompressed_size) / static_cast<double>(e.compressed_size);
    if (ratio > limits.max_expansion_ratio) {
        e.state = "BUDGET_REFUSED"; e.failure_reason = "declared expansion ratio exceeds limit"; return;
    }
    e.state = "SAFE_TO_MATERIALIZE";
    e.safe_to_materialize = true;
}

std::string coordinate_for(const ContainerMemberIdentity& e) {
    std::ostringstream ss;
    ss << "zip:member[" << e.index << "]:compressed@" << e.data_offset << "+" << e.compressed_size;
    return ss.str();
}

bool ensure_safe_output_parents(const std::filesystem::path& root, const std::filesystem::path& relative,
                                std::string& error) {
    std::error_code ec;
    const auto root_status = std::filesystem::symlink_status(root, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
        error = "cannot inspect output root: " + ec.message();
        return false;
    }
    ec.clear();
    if (std::filesystem::exists(root_status)) {
        if (std::filesystem::is_symlink(root_status) || !std::filesystem::is_directory(root_status)) {
            error = "output root exists but is not a real directory";
            return false;
        }
    } else if (!std::filesystem::create_directories(root, ec) && ec) {
        error = "cannot create output root: " + ec.message();
        return false;
    }

    auto cur = root;
    auto parent = relative.parent_path();
    for (const auto& part : parent) {
        if (part.empty() || part == "." || part == "..") {
            error = "validated path produced an invalid filesystem component";
            return false;
        }
        cur /= part;
        ec.clear();
        const auto st = std::filesystem::symlink_status(cur, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            error = "cannot inspect output path component: " + ec.message();
            return false;
        }
        ec.clear();
        if (std::filesystem::exists(st)) {
            if (std::filesystem::is_symlink(st) || !std::filesystem::is_directory(st)) {
                error = "output path component is a symlink or non-directory";
                return false;
            }
        } else if (!std::filesystem::create_directory(cur, ec) && ec) {
            error = "cannot create output path component: " + ec.message();
            return false;
        }
    }
    return true;
}

std::optional<std::uint64_t> strict_eocd_offset(std::span<const std::uint8_t> data) {
    if (data.size() < 22) return std::nullopt;
    const std::size_t floor = data.size() > 65557 ? data.size() - 65557 : 0;
    for (std::size_t pos = data.size() - 22;; --pos) {
        if (le32(data, pos) == kEocdSig) {
            const auto comment = le16(data, pos + 20);
            if (pos + 22u + comment == data.size()) return static_cast<std::uint64_t>(pos);
        }
        if (pos == floor) break;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> classic_prefix_base(std::span<const std::uint8_t> data, std::uint64_t eocd) {
    if (!span_in_bounds(data, eocd, 22)) return std::nullopt;
    const auto cd_size32 = le32(data, eocd + 12);
    const auto cd_off32 = le32(data, eocd + 16);
    if (cd_size32 == 0xffffffffu || cd_off32 == 0xffffffffu) return std::nullopt;
    if (std::uint64_t(cd_size32) > eocd) return std::nullopt;
    const auto physical_cd = eocd - std::uint64_t(cd_size32);
    if (physical_cd < cd_off32) return std::nullopt;
    const auto base = physical_cd - cd_off32;
    if (base == 0 || base >= data.size()) return std::nullopt;
    if (!span_in_bounds(data, physical_cd, 4) || le32(data, physical_cd) != kCentralHeaderSig) return std::nullopt;
    return base;
}

}  // namespace

bool has_strict_zip_eocd(std::span<const std::uint8_t> data) {
    return strict_eocd_offset(data).has_value();
}

ContainerIngressInfo inspect_zip_container(std::span<const std::uint8_t> data, std::string source_identity,
                                           const ContainerIngressLimits& limits) {
    ContainerIngressInfo out;
    out.source_identity = std::move(source_identity);
    out.parent_size = data.size();
    out.limits = limits;
    out.layers = initial_layers(limits, data.size());
    const auto eocd = strict_eocd_offset(data);
    if (!eocd) return out;
    out.recognized = true;
    out.kind = "zip";
    out.layers[0].state = "CANDIDATE";
    out.layers[0].evidence.push_back("EOCD with self-consistent comment length reaches EOF");
    if (data.size() > limits.max_input_bytes) {
        out.state = "REFUSED";
        out.failure_reason = "container input bytes exceed L0 safety budget";
        out.layers[0].state = "REFUSED";
        out.layers[0].failure_reason = out.failure_reason;
        return out;
    }
    out.parent_sha256 = sha256_bytes(data);

    mz_zip_archive zip{};
    ZipCloser close{&zip};
    std::span<const std::uint8_t> archive = data;
    if (!mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0)) {
        const auto first_error = miniz_error(zip);
        const auto prefix = classic_prefix_base(data, *eocd);
        if (!prefix) {
            fail_structure(out, "ZIP central-directory validation failed: " + first_error);
            return out;
        }
        zip = {};
        out.archive_base_offset = *prefix;
        archive = data.subspan(static_cast<std::size_t>(*prefix));
        if (!mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0)) {
            fail_structure(out, "prefix-adjusted ZIP central-directory validation failed: " + miniz_error(zip));
            return out;
        }
        out.layers[0].evidence.push_back("self-extracting/prefixed ZIP base proven from EOCD central-directory geometry");
    }
    out.member_count = mz_zip_reader_get_num_files(&zip);
    out.layers[1].budget_used = out.member_count;
    out.central_directory_offset = out.archive_base_offset + zip.m_central_directory_file_ofs;
    out.zip64 = mz_zip_is_zip64(&zip) != 0;
    out.layers[0].evidence.push_back("miniz central-directory reader accepted archive geometry");
    if (out.member_count > limits.max_members) {
        out.state = "REFUSED";
        out.failure_reason = "member count exceeds L1 inventory budget";
        out.layers[0].state = "PARTIAL";
        out.layers[1].state = "REFUSED";
        out.layers[1].failure_reason = out.failure_reason;
        return out;
    }

    out.members.reserve(static_cast<std::size_t>(out.member_count));
    std::unordered_map<std::string, std::size_t> exact_seen;
    std::unordered_map<std::string, std::size_t> case_seen;

    for (std::uint32_t i = 0; i < out.member_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            fail_structure(out, "cannot read ZIP central-directory entry " + std::to_string(i) + ": " + miniz_error(zip));
            return out;
        }
        const std::uint64_t central_off = out.archive_base_offset + zip.m_central_directory_file_ofs + st.m_central_dir_ofs;
        if (!span_in_bounds(data, central_off, 46) || le32(data, central_off) != kCentralHeaderSig) {
            fail_structure(out, "invalid ZIP central-directory entry geometry at index " + std::to_string(i));
            return out;
        }
        const auto central_name_len = le16(data, central_off + 28);
        const auto central_extra_len = le16(data, central_off + 30);
        const auto central_comment_len = le16(data, central_off + 32);
        std::uint64_t central_end = central_off + 46;
        if (!add_u64(central_end, std::uint64_t(central_name_len) + central_extra_len + central_comment_len, central_end) ||
            central_end > data.size()) {
            fail_structure(out, "truncated ZIP central-directory variable fields at index " + std::to_string(i));
            return out;
        }
        std::string raw_name(reinterpret_cast<const char*>(data.data() + static_cast<std::size_t>(central_off + 46)), central_name_len);
        const auto local_off = out.archive_base_offset + st.m_local_header_ofs;
        if (!span_in_bounds(data, local_off, 30) || le32(data, local_off) != kLocalHeaderSig) {
            fail_structure(out, "invalid ZIP local-header geometry at index " + std::to_string(i));
            return out;
        }
        const auto local_name_len = le16(data, local_off + 26);
        const auto local_extra_len = le16(data, local_off + 28);
        std::uint64_t data_off = local_off + 30;
        if (!add_u64(data_off, std::uint64_t(local_name_len) + local_extra_len, data_off) || data_off > data.size()) {
            fail_structure(out, "truncated ZIP local-header fields at index " + std::to_string(i));
            return out;
        }
        if (local_name_len != central_name_len || !span_in_bounds(data, local_off + 30, local_name_len) ||
            std::memcmp(raw_name.data(), data.data() + static_cast<std::size_t>(local_off + 30), local_name_len) != 0) {
            fail_structure(out, "ZIP local/central filename mismatch at index " + std::to_string(i));
            return out;
        }
        if (!span_in_bounds(data, data_off, st.m_comp_size) || data_off + st.m_comp_size > out.central_directory_offset) {
            fail_structure(out, "ZIP compressed payload geometry exceeds member-data region at index " + std::to_string(i));
            return out;
        }
        const auto local_flags = le16(data, local_off + 6);
        const auto local_method = le16(data, local_off + 8);
        if (local_flags != st.m_bit_flag) {
            fail_structure(out, "ZIP local/central flags mismatch at index " + std::to_string(i));
            return out;
        }
        if (local_method != st.m_method) {
            fail_structure(out, "ZIP local/central compression-method mismatch at index " + std::to_string(i));
            return out;
        }
        const bool has_descriptor = (st.m_bit_flag & kZipFlagDataDescriptor) != 0;
        if (!has_descriptor) {
            const auto local_crc = le32(data, local_off + 14);
            const auto local_comp = le32(data, local_off + 18);
            const auto local_uncomp = le32(data, local_off + 22);
            if (local_crc != st.m_crc32 ||
                (local_comp != 0xffffffffu && std::uint64_t(local_comp) != st.m_comp_size) ||
                (local_uncomp != 0xffffffffu && std::uint64_t(local_uncomp) != st.m_uncomp_size)) {
                fail_structure(out, "ZIP local/central CRC or size mismatch at index " + std::to_string(i));
                return out;
            }
        } else if (!descriptor_matches(data, data_off + st.m_comp_size, st.m_crc32, st.m_comp_size, st.m_uncomp_size)) {
            fail_structure(out, "ZIP data descriptor does not match central-directory CRC/sizes at index " + std::to_string(i));
            return out;
        }
        if (!st.m_is_encrypted && st.m_is_supported && !st.m_is_directory &&
            !mz_zip_validate_file(&zip, i, MZ_ZIP_FLAG_VALIDATE_HEADERS_ONLY)) {
            fail_structure(out, "ZIP library header validation failed at index " + std::to_string(i) + ": " + miniz_error(zip));
            return out;
        }

        ContainerMemberIdentity e;
        e.index = i;
        e.name = std::move(raw_name);
        e.compressed_size = st.m_comp_size;
        e.uncompressed_size = st.m_uncomp_size;
        e.crc32 = st.m_crc32;
        e.method = st.m_method;
        e.flags = st.m_bit_flag;
        e.local_header_offset = local_off;
        e.data_offset = data_off;
        e.central_directory_offset = central_off;
        e.directory = st.m_is_directory != 0;
        e.encrypted = st.m_is_encrypted != 0 || (st.m_bit_flag & (kZipFlagEncrypted | kZipFlagStrongEncryption)) != 0;
        e.supported_method = st.m_is_supported != 0;
        e.data_descriptor = has_descriptor;
        const auto creator = std::uint8_t(st.m_version_made_by >> 8);
        const auto unix_mode = std::uint16_t(st.m_external_attr >> 16);
        const auto unix_type = std::uint16_t(unix_mode & 0170000);
        e.symlink = (creator == 3 || creator == 19) && unix_type == 0120000;
        e.special_file = (creator == 3 || creator == 19) && unix_type != 0 && unix_type != 0100000 &&
                         unix_type != 0040000 && unix_type != 0120000;
        e.safe_path = safe_relative_name(e.name, e.directory, limits.max_path_bytes, e.normalized_path, e.portable_path);
        e.compressed_sha256 = sha256_bytes(data.subspan(static_cast<std::size_t>(data_off), static_cast<std::size_t>(st.m_comp_size)));
        e.coordinate = coordinate_for(e);

        if (e.safe_path && !e.normalized_path.empty()) {
            if (const auto it = exact_seen.find(e.normalized_path); it != exact_seen.end()) {
                e.duplicate_path = true;
                out.members[it->second].duplicate_path = true;
                push_anomaly(out, "duplicate normalized member path: " + e.normalized_path);
            } else {
                exact_seen.emplace(e.normalized_path, out.members.size());
            }
            const auto folded = lower_ascii(e.normalized_path);
            if (const auto it = case_seen.find(folded); it != case_seen.end()) {
                if (out.members[it->second].normalized_path != e.normalized_path) {
                    e.case_collision = true;
                    out.members[it->second].case_collision = true;
                    push_anomaly(out, "portable case collision: " + out.members[it->second].normalized_path + " <> " + e.normalized_path);
                }
            } else {
                case_seen.emplace(folded, out.members.size());
            }
        }
        if (!e.directory) {
            ++out.regular_file_count;
            if (e.encrypted) ++out.encrypted_file_count;
        }
        if (out.total_compressed_bytes > std::numeric_limits<std::uint64_t>::max() - e.compressed_size ||
            out.total_declared_uncompressed_bytes > std::numeric_limits<std::uint64_t>::max() - e.uncompressed_size) {
            fail_structure(out, "ZIP aggregate member sizes overflow uint64 accounting");
            return out;
        }
        out.total_compressed_bytes += e.compressed_size;
        out.total_declared_uncompressed_bytes += e.uncompressed_size;
        out.members.push_back(std::move(e));
    }

    for (auto& e : out.members) {
        finalize_member_state(e, limits);
        if (e.safe_to_materialize) ++out.safe_materialization_count;
        if (!e.directory && !e.safe_to_materialize) out.policy_gated = true;
    }
    if (out.total_declared_uncompressed_bytes > limits.max_total_declared_uncompressed_bytes) {
        out.policy_gated = true;
        push_anomaly(out, "aggregate declared uncompressed bytes exceed default ingress policy");
    }
    out.credential_required = out.encrypted_file_count != 0;
    out.structurally_valid = true;
    out.layers[0].state = "CONFIRMED";
    out.layers[0].evidence.push_back("every central entry matched its local filename/flags/method and CRC/size contract");
    out.layers[1].state = out.policy_gated ? "CONFIRMED_WITH_POLICY_GATES" : "CONFIRMED";
    out.layers[1].evidence.push_back("member index, safe path, compressed identity, size, CRC, and parent-file offsets recorded");
    out.layers[1].budget_used = out.member_count;
    if (out.regular_file_count != 0 && out.encrypted_file_count == out.regular_file_count) {
        out.state = "EXPLICIT_CREDENTIAL_REQUIRED";
    } else if (out.policy_gated) {
        out.state = "CONFIRMED_WITH_POLICY_GATES";
    } else {
        out.state = "CONFIRMED";
    }
    return out;
}

ContainerMaterializationResult materialize_zip_member(std::span<const std::uint8_t> data,
                                                       const ContainerIngressInfo& info,
                                                       std::uint64_t member_index,
                                                       const std::filesystem::path& output_root,
                                                       std::uint64_t current_depth,
                                                       std::uint64_t remaining_output_bytes) {
    ContainerMaterializationResult out;
    out.member_index = member_index;
    out.parent_sha256 = info.parent_sha256;
    if (!info.recognized || !info.structurally_valid || info.kind != "zip") {
        out.failure_reason = "container was not structurally confirmed as ZIP";
        return out;
    }
    if (member_index >= info.members.size() || info.members[static_cast<std::size_t>(member_index)].index != member_index) {
        out.failure_reason = "member index is outside the inspected inventory";
        return out;
    }
    const auto& e = info.members[static_cast<std::size_t>(member_index)];
    out.member_name = e.name;
    out.compressed_sha256 = e.compressed_sha256;
    out.compressed_size = e.compressed_size;
    out.uncompressed_size = e.uncompressed_size;
    out.data_offset = e.data_offset;
    out.coordinate = e.coordinate;
    if (!e.safe_to_materialize) {
        out.state = e.state;
        out.failure_reason = e.failure_reason;
        return out;
    }
    if (current_depth >= info.limits.max_recursive_depth) {
        out.state = "BUDGET_REFUSED";
        out.failure_reason = "recursive depth budget exhausted before child materialization";
        return out;
    }
    if (remaining_output_bytes == std::numeric_limits<std::uint64_t>::max())
        remaining_output_bytes = info.limits.max_total_materialized_bytes;
    if (e.uncompressed_size > remaining_output_bytes || e.uncompressed_size > info.limits.max_total_materialized_bytes) {
        out.state = "BUDGET_REFUSED";
        out.failure_reason = "remaining materialized-byte budget cannot admit this child";
        return out;
    }
    if (sha256_bytes(data) != info.parent_sha256) {
        out.state = "IDENTITY_MISMATCH";
        out.failure_reason = "input bytes changed since ZIP inspection";
        return out;
    }

    std::string safe_error;
    const std::filesystem::path relative(e.normalized_path);
    if (!ensure_safe_output_parents(output_root, relative, safe_error)) {
        out.state = "OUTPUT_PATH_REFUSED";
        out.failure_reason = std::move(safe_error);
        return out;
    }
    const auto dest = output_root / relative;
    std::error_code ec;
    const auto dst_status = std::filesystem::symlink_status(dest, ec);
    if (!ec && std::filesystem::exists(dst_status)) {
        out.state = "OUTPUT_PATH_REFUSED";
        out.failure_reason = "destination already exists; overwrite is forbidden";
        return out;
    }
    ec.clear();
    auto part = dest;
    part += ".auto-refirst-part-" + std::to_string(member_index);
    const auto part_status = std::filesystem::symlink_status(part, ec);
    if (!ec && std::filesystem::exists(part_status)) {
        out.state = "OUTPUT_PATH_REFUSED";
        out.failure_reason = "temporary destination already exists";
        return out;
    }
    ec.clear();

    if (info.archive_base_offset > data.size()) {
        out.state = "IDENTITY_MISMATCH";
        out.failure_reason = "stored ZIP archive base is outside current parent bytes";
        return out;
    }
    const auto archive = data.subspan(static_cast<std::size_t>(info.archive_base_offset));
    mz_zip_archive zip{};
    ZipCloser close{&zip};
    if (!mz_zip_reader_init_mem(&zip, archive.data(), archive.size(), 0)) {
        out.state = "DECOMPRESSION_FAILED";
        out.failure_reason = "cannot reopen verified ZIP at stored archive base: " + miniz_error(zip);
        return out;
    }
    std::ofstream f(part, std::ios::binary | std::ios::trunc);
    if (!f) {
        out.state = "OUTPUT_PATH_REFUSED";
        out.failure_reason = "cannot create temporary output file";
        return out;
    }
    auto* it = mz_zip_reader_extract_iter_new(&zip, static_cast<mz_uint>(member_index), 0);
    if (!it) {
        f.close();
        std::filesystem::remove(part, ec);
        out.state = "DECOMPRESSION_FAILED";
        out.failure_reason = "cannot start ZIP member decompression: " + miniz_error(zip);
        return out;
    }
    std::vector<std::uint8_t> buffer(kIoChunk);
    std::uint64_t written = 0;
    bool stream_ok = true;
    while (written < e.uncompressed_size) {
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), e.uncompressed_size - written));
        const auto got = mz_zip_reader_extract_iter_read(it, buffer.data(), want);
        if (got == 0 || got > want || written > remaining_output_bytes - got) { stream_ok = false; break; }
        f.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(got));
        if (!f) { stream_ok = false; break; }
        written += got;
    }
    std::uint8_t extra = 0;
    if (stream_ok && mz_zip_reader_extract_iter_read(it, &extra, 1) != 0) stream_ok = false;
    const bool crc_ok = mz_zip_reader_extract_iter_free(it) != 0;
    f.close();
    if (!stream_ok || !crc_ok || written != e.uncompressed_size) {
        std::filesystem::remove(part, ec);
        out.state = "DECOMPRESSION_OR_CRC_FAILED";
        out.failure_reason = "streamed output did not match declared size and ZIP CRC";
        return out;
    }
    std::filesystem::rename(part, dest, ec);
    if (ec) {
        std::filesystem::remove(part, ec);
        out.state = "OUTPUT_PATH_REFUSED";
        out.failure_reason = "cannot atomically finalize output file: " + ec.message();
        return out;
    }
    out.output_path = dest;
    out.bytes_written = written;
    out.uncompressed_sha256 = sha256_file(dest);
    out.state = "MATERIALIZED_VERIFIED";
    out.success = true;
    return out;
}

}  // namespace prts
