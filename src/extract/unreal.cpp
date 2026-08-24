#include "prts/unreal.hpp"

#include "prts/path_utf8.hpp"
#include "prts/sha1.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <set>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace prts {
namespace {

constexpr std::uint32_t kPakMagic = 0x5a6f12e1U;
constexpr std::array<std::uint8_t, 16> kIoStoreMagic = {
    '-', '=', '=', '-', '-', '=', '=', '-', '-', '=', '=', '-', '-', '=', '=', '-'};
constexpr std::uint32_t kPakEntryBudget = 1'000'000U;
constexpr std::uint32_t kIoEntryBudget = 1'000'000U;
constexpr std::uint32_t kIoBlockBudget = 4'000'000U;
constexpr std::uint32_t kIoMethodBudget = 64U;
constexpr std::uint32_t kIoPartitionBudget = 128U;
constexpr std::uint32_t kSiblingBudget = 8192U;
constexpr std::uint64_t kDirectoryIndexBudget = 256ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t kSignatureBudget = 16ULL * 1024ULL * 1024ULL;

bool checked_add(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

bool checked_mul(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool read_le32(std::span<const std::uint8_t> data, std::uint64_t off, std::uint32_t& out) {
    std::uint64_t end = 0;
    if (!checked_add(off, 4, end) || end > data.size()) return false;
    const auto p = static_cast<std::size_t>(off);
    out = static_cast<std::uint32_t>(data[p]) |
          (static_cast<std::uint32_t>(data[p + 1]) << 8U) |
          (static_cast<std::uint32_t>(data[p + 2]) << 16U) |
          (static_cast<std::uint32_t>(data[p + 3]) << 24U);
    return true;
}

bool read_le64(std::span<const std::uint8_t> data, std::uint64_t off, std::uint64_t& out) {
    std::uint64_t end = 0;
    if (!checked_add(off, 8, end) || end > data.size()) return false;
    out = 0;
    const auto p = static_cast<std::size_t>(off);
    for (unsigned i = 0; i < 8; ++i) out |= static_cast<std::uint64_t>(data[p + i]) << (8U * i);
    return true;
}

std::uint64_t read_le_n(const std::uint8_t* p, unsigned count) {
    std::uint64_t out = 0;
    for (unsigned i = 0; i < count; ++i) out |= static_cast<std::uint64_t>(p[i]) << (8U * i);
    return out;
}

std::uint64_t read_be5(const std::uint8_t* p) {
    std::uint64_t out = 0;
    for (unsigned i = 0; i < 5; ++i) out = (out << 8U) | p[i];
    return out;
}

std::string lower_ascii(std::string value) {
    for (char& c : value) {
        const auto uc = static_cast<unsigned char>(c);
        if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc - 'A' + 'a');
    }
    return value;
}

bool has_extension(const std::filesystem::path& input, const char* wanted) {
    return lower_ascii(path_utf8(input.extension())) == wanted;
}

bool all_zero(std::span<const std::uint8_t> data, std::size_t begin, std::size_t end) {
    if (end > data.size() || begin > end) return false;
    return std::all_of(data.begin() + static_cast<std::ptrdiff_t>(begin),
                       data.begin() + static_cast<std::ptrdiff_t>(end),
                       [](std::uint8_t b) { return b == 0; });
}

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7fU) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ffU) {
        out.push_back(static_cast<char>(0xc0U | (cp >> 6U)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else if (cp <= 0xffffU) {
        out.push_back(static_cast<char>(0xe0U | (cp >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else {
        out.push_back(static_cast<char>(0xf0U | (cp >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    }
}

bool valid_utf8(std::span<const std::uint8_t> bytes) {
    std::size_t i = 0;
    while (i < bytes.size()) {
        const std::uint8_t lead = bytes[i++];
        if (lead <= 0x7fU) continue;
        unsigned trailing = 0;
        std::uint32_t cp = 0;
        if ((lead & 0xe0U) == 0xc0U) {
            trailing = 1;
            cp = lead & 0x1fU;
        } else if ((lead & 0xf0U) == 0xe0U) {
            trailing = 2;
            cp = lead & 0x0fU;
        } else if ((lead & 0xf8U) == 0xf0U) {
            trailing = 3;
            cp = lead & 0x07U;
        } else {
            return false;
        }
        if (i + trailing > bytes.size()) return false;
        for (unsigned j = 0; j < trailing; ++j) {
            const std::uint8_t b = bytes[i++];
            if ((b & 0xc0U) != 0x80U) return false;
            cp = (cp << 6U) | (b & 0x3fU);
        }
        if ((trailing == 1 && cp < 0x80U) || (trailing == 2 && cp < 0x800U) ||
            (trailing == 3 && cp < 0x10000U) || cp > 0x10ffffU ||
            (cp >= 0xd800U && cp <= 0xdfffU)) {
            return false;
        }
    }
    return true;
}

bool parse_fstring(std::span<const std::uint8_t> data, std::uint64_t& cursor,
                   std::string& value, std::string& error) {
    std::uint32_t raw = 0;
    if (!read_le32(data, cursor, raw)) {
        error = "Pak index mount point length is truncated";
        return false;
    }
    cursor += 4;
    const auto signed_len = static_cast<std::int32_t>(raw);
    if (signed_len == 0) {
        value.clear();
        return true;
    }
    if (signed_len > 0) {
        const auto bytes = static_cast<std::uint64_t>(signed_len);
        if (bytes > 4096U) {
            error = "Pak index mount point exceeds the 4096-byte string budget";
            return false;
        }
        std::uint64_t end = 0;
        if (!checked_add(cursor, bytes, end) || end > data.size()) {
            error = "Pak index mount point is truncated";
            return false;
        }
        const auto begin = static_cast<std::size_t>(cursor);
        if (data[static_cast<std::size_t>(end - 1)] != 0) {
            error = "Pak index mount point lacks its terminal NUL";
            return false;
        }
        const auto text = data.subspan(begin, static_cast<std::size_t>(bytes - 1));
        if (std::find(text.begin(), text.end(), 0) != text.end() || !valid_utf8(text)) {
            error = "Pak index mount point is not a canonical UTF-8 FString";
            return false;
        }
        value.assign(reinterpret_cast<const char*>(text.data()), text.size());
        cursor = end;
        return true;
    }
    if (signed_len == std::numeric_limits<std::int32_t>::min()) {
        error = "Pak index mount point has an invalid UTF-16 length";
        return false;
    }
    const auto units = static_cast<std::uint64_t>(-static_cast<std::int64_t>(signed_len));
    std::uint64_t bytes = 0;
    if (units > 2048U || !checked_mul(units, 2, bytes)) {
        error = "Pak index mount point exceeds the 2048-unit UTF-16 budget";
        return false;
    }
    std::uint64_t end = 0;
    if (!checked_add(cursor, bytes, end) || end > data.size()) {
        error = "Pak UTF-16 mount point is truncated";
        return false;
    }
    const auto at = [&](std::uint64_t unit) {
        const auto p = static_cast<std::size_t>(cursor + unit * 2);
        return static_cast<std::uint16_t>(data[p]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[p + 1]) << 8U);
    };
    if (at(units - 1) != 0) {
        error = "Pak UTF-16 mount point lacks its terminal NUL";
        return false;
    }
    value.clear();
    for (std::uint64_t i = 0; i + 1 < units; ++i) {
        std::uint32_t cp = at(i);
        if (cp == 0) {
            error = "Pak UTF-16 mount point contains an embedded NUL";
            return false;
        }
        if (cp >= 0xd800U && cp <= 0xdbffU) {
            if (i + 2 >= units) {
                error = "Pak UTF-16 mount point has a truncated surrogate pair";
                return false;
            }
            const std::uint32_t low = at(++i);
            if (low < 0xdc00U || low > 0xdfffU) {
                error = "Pak UTF-16 mount point has an invalid surrogate pair";
                return false;
            }
            cp = 0x10000U + ((cp - 0xd800U) << 10U) + (low - 0xdc00U);
        } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
            error = "Pak UTF-16 mount point has an unpaired low surrogate";
            return false;
        }
        append_utf8(value, cp);
    }
    cursor = end;
    return true;
}

struct PakProfile {
    const char* name;
    std::uint32_t first_version;
    std::uint32_t last_version;
    std::uint64_t size;
    std::uint64_t magic_offset;
    std::uint32_t compression_slots;
    bool encrypted_field;
    bool frozen_field;
};

constexpr std::array<PakProfile, 8> kPakProfiles = {{
    {"v1-v3-core44", 1, 3, 44, 0, 0, false, false},
    {"v4-v6-encrypted45", 4, 6, 45, 1, 0, true, false},
    {"v7-guid61", 7, 7, 61, 17, 0, true, false},
    {"v8a-four-method189", 8, 8, 189, 17, 4, true, false},
    {"v8b-five-method221", 8, 8, 221, 17, 5, true, false},
    {"v9-frozen222", 9, 9, 222, 17, 5, true, true},
    {"v10-v11-five-method221", 10, 11, 221, 17, 5, true, false},
    {"v12-utf8-index221", 12, 12, 221, 17, 5, true, false},
}};

bool parse_compression_slots(std::span<const std::uint8_t> data, std::uint64_t off,
                             std::uint32_t count, std::vector<std::string>& names,
                             std::string& error) {
    names.clear();
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto p = static_cast<std::size_t>(off + static_cast<std::uint64_t>(i) * 32U);
        std::size_t length = 0;
        while (length < 32 && data[p + length] != 0) ++length;
        if (length == 32) {
            error = "Pak compression method slot lacks NUL padding";
            return false;
        }
        for (std::size_t j = 0; j < length; ++j) {
            if (data[p + j] < 0x20U || data[p + j] > 0x7eU) {
                error = "Pak compression method slot is not printable ASCII";
                return false;
            }
        }
        if (!all_zero(data, p + length, p + 32)) {
            error = "Pak compression method slot has nonzero bytes after its name";
            return false;
        }
        if (length != 0) {
            names.emplace_back(reinterpret_cast<const char*>(data.data() + p), length);
        }
    }
    return true;
}

UnrealPakInfo parse_pak_profile(std::span<const std::uint8_t> data, const PakProfile& profile) {
    UnrealPakInfo out;
    out.candidate = true;
    out.footer_profile = profile.name;
    out.footer_size = profile.size;
    out.footer_offset = data.size() - profile.size;
    const std::uint64_t footer = out.footer_offset;
    const std::uint64_t magic_at = footer + profile.magic_offset;
    std::uint32_t magic = 0;
    read_le32(data, magic_at, magic);
    std::uint32_t version = 0;
    read_le32(data, magic_at + 4, version);
    out.version = version;
    out.supported_version = version >= profile.first_version && version <= profile.last_version;
    if (magic != kPakMagic || !out.supported_version) {
        out.state = "FAILED";
        out.error = "Pak footer magic/version does not match its exact version profile";
        return out;
    }
    if (profile.encrypted_field) {
        const auto flag = data[static_cast<std::size_t>(footer + profile.magic_offset - 1)];
        if (flag > 1) {
            out.state = "FAILED";
            out.error = "Pak encrypted-index flag is not a serialized boolean";
            return out;
        }
        out.encrypted_index = flag != 0;
    }
    const auto core = magic_at;
    if (!read_le64(data, core + 8, out.index_offset) ||
        !read_le64(data, core + 16, out.index_size)) {
        out.state = "FAILED";
        out.error = "Pak footer core is truncated";
        return out;
    }
    if (out.index_size == 0) {
        out.state = "FAILED";
        out.error = "Pak footer declares an empty primary index";
        return out;
    }
    std::uint64_t index_end = 0;
    if (!checked_add(out.index_offset, out.index_size, index_end) || index_end > footer) {
        out.state = "FAILED";
        out.error = "Pak primary index range exceeds the exact footer boundary";
        return out;
    }
    std::uint64_t compression_at = core + 44;
    if (profile.frozen_field) {
        const auto frozen = data[static_cast<std::size_t>(compression_at)];
        if (frozen > 1) {
            out.state = "FAILED";
            out.error = "Pak frozen-index flag is not a serialized boolean";
            return out;
        }
        out.frozen_index = frozen != 0;
        ++compression_at;
    }
    if (!parse_compression_slots(data, compression_at, profile.compression_slots,
                                 out.compression_methods, out.error)) {
        out.state = "FAILED";
        return out;
    }
    if (out.encrypted_index) {
        out.state = "PARTIAL";
        out.error = "Pak primary index is encrypted; an explicit credential is required";
        return out;
    }
    const auto index = data.subspan(static_cast<std::size_t>(out.index_offset),
                                    static_cast<std::size_t>(out.index_size));
    const auto actual_hash = sha1_bytes(index);
    out.index_hash_checked = true;
    out.index_hash_matches =
        std::equal(actual_hash.begin(), actual_hash.end(),
                   data.begin() + static_cast<std::ptrdiff_t>(core + 24));
    if (!out.index_hash_matches) {
        out.state = "FAILED";
        out.error = "Pak primary index SHA-1 does not match the footer";
        return out;
    }
    std::uint64_t cursor = 0;
    if (!parse_fstring(index, cursor, out.mount_point, out.error)) {
        out.state = "FAILED";
        return out;
    }
    std::uint32_t count = 0;
    if (!read_le32(index, cursor, count)) {
        out.state = "FAILED";
        out.error = "Pak primary index entry count is truncated";
        return out;
    }
    cursor += 4;
    out.entry_count = count;
    if (count > kPakEntryBudget) {
        out.budget_exhausted = true;
        out.state = "PARTIAL";
        out.error = "Pak primary index entry count exceeds the static recognition budget";
        return out;
    }
    std::uint64_t minimum_names = 0;
    if (!checked_mul(count, 4, minimum_names) || minimum_names > index.size() - cursor) {
        out.state = "FAILED";
        out.error = "Pak primary index is too small for its declared entry count";
        return out;
    }
    if (version >= 10) {
        std::uint64_t min_header = 0;
        if (!checked_add(cursor, 12, min_header) || min_header > index.size()) {
            out.state = "FAILED";
            out.error = "Pak path-hash index header is truncated";
            return out;
        }
        cursor += 8;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> secondary_ranges;
        out.secondary_index_hashes_match = true;
        for (unsigned selector = 0; selector < 2; ++selector) {
            std::uint32_t present = 0;
            if (!read_le32(index, cursor, present) || present > 1) {
                out.state = "FAILED";
                out.error = "Pak secondary-index presence field is not a serialized boolean";
                return out;
            }
            cursor += 4;
            if (present != 0) {
                std::uint64_t descriptor_end = 0;
                if (!checked_add(cursor, 36, descriptor_end) || descriptor_end > index.size()) {
                    out.state = "FAILED";
                    out.error = "Pak secondary-index descriptor is truncated";
                    return out;
                }
                std::uint64_t secondary_offset = 0;
                std::uint64_t secondary_size = 0;
                read_le64(index, cursor, secondary_offset);
                read_le64(index, cursor + 8, secondary_size);
                std::uint64_t secondary_end = 0;
                if (secondary_size == 0 ||
                    !checked_add(secondary_offset, secondary_size, secondary_end) ||
                    secondary_offset < index_end || secondary_end > footer) {
                    out.state = "FAILED";
                    out.error = "Pak secondary-index range is empty or outside the post-primary pre-footer region";
                    return out;
                }
                const auto secondary = data.subspan(
                    static_cast<std::size_t>(secondary_offset),
                    static_cast<std::size_t>(secondary_size));
                const auto actual_secondary_hash = sha1_bytes(secondary);
                out.secondary_index_hashes_checked = true;
                if (!std::equal(actual_secondary_hash.begin(), actual_secondary_hash.end(),
                                index.begin() + static_cast<std::ptrdiff_t>(cursor + 16))) {
                    out.secondary_index_hashes_match = false;
                    out.state = "FAILED";
                    out.error = "Pak secondary-index SHA-1 does not match its primary-index descriptor";
                    return out;
                }
                secondary_ranges.emplace_back(secondary_offset, secondary_end);
                ++out.secondary_index_count;
                cursor = descriptor_end;
            }
        }
        std::sort(secondary_ranges.begin(), secondary_ranges.end());
        for (std::size_t i = 1; i < secondary_ranges.size(); ++i) {
            if (secondary_ranges[i].first < secondary_ranges[i - 1].second) {
                out.state = "FAILED";
                out.error = "Pak secondary-index ranges overlap";
                return out;
            }
        }
        std::uint32_t encoded_size = 0;
        if (!read_le32(index, cursor, encoded_size)) {
            out.state = "FAILED";
            out.error = "Pak encoded-entry array size is truncated";
            return out;
        }
        cursor += 4;
        std::uint64_t encoded_end = 0;
        out.encoded_entry_bytes = encoded_size;
        if (!checked_add(cursor, encoded_size, encoded_end) ||
            !checked_add(encoded_end, 4, min_header) || min_header > index.size()) {
            out.state = "FAILED";
            out.error = "Pak encoded-entry array exceeds the primary index";
            return out;
        }
        std::uint32_t non_encoded_count = 0;
        if (!read_le32(index, encoded_end, non_encoded_count)) {
            out.state = "FAILED";
            out.error = "Pak non-encoded entry count is truncated";
            return out;
        }
        out.non_encoded_entry_count = non_encoded_count;
        if (non_encoded_count > count) {
            out.state = "FAILED";
            out.error = "Pak non-encoded entry count exceeds the primary entry count";
            return out;
        }
        std::uint64_t minimum_non_encoded_bytes = 0;
        if (!checked_mul(non_encoded_count, 53, minimum_non_encoded_bytes) ||
            minimum_non_encoded_bytes > index.size() - (encoded_end + 4)) {
            out.state = "FAILED";
            out.error = "Pak primary index is too small for its non-encoded entry count";
            return out;
        }
    }
    out.index_header_valid = true;
    if (out.frozen_index) {
        out.state = "PARTIAL";
        out.error = "Pak v9 frozen index is structurally recognized but unsupported";
        return out;
    }
    out.valid = true;
    out.state = "CONFIRMED";
    return out;
}

UnrealPakInfo detect_pak(std::span<const std::uint8_t> data,
                         const std::filesystem::path& input) {
    std::vector<UnrealPakInfo> parsed;
    for (const auto& profile : kPakProfiles) {
        if (data.size() < profile.size) continue;
        const auto footer = static_cast<std::uint64_t>(data.size()) - profile.size;
        std::uint32_t magic = 0;
        std::uint32_t version = 0;
        if (!read_le32(data, footer + profile.magic_offset, magic) ||
            !read_le32(data, footer + profile.magic_offset + 4, version) ||
            magic != kPakMagic || version < profile.first_version ||
            version > profile.last_version) {
            continue;
        }
        parsed.push_back(parse_pak_profile(data, profile));
    }
    const auto viable = std::count_if(parsed.begin(), parsed.end(), [](const UnrealPakInfo& p) {
        return p.state == "CONFIRMED" || p.state == "PARTIAL";
    });
    if (viable > 1) {
        UnrealPakInfo out;
        out.candidate = true;
        out.state = "PARTIAL";
        out.footer_profile = "AMBIGUOUS_EXACT_EOF_PROFILES";
        out.error = "multiple exact Pak footer profiles remain structurally viable";
        return out;
    }
    if (viable == 1) {
        return *std::find_if(parsed.begin(), parsed.end(), [](const UnrealPakInfo& p) {
            return p.state == "CONFIRMED" || p.state == "PARTIAL";
        });
    }
    if (!parsed.empty()) return parsed.front();
    std::vector<UnrealPakInfo> unknown_version_positions;
    for (const auto& profile : kPakProfiles) {
        if (data.size() < profile.size) continue;
        const auto footer = static_cast<std::uint64_t>(data.size()) - profile.size;
        std::uint32_t magic = 0;
        std::uint32_t version = 0;
        if (!read_le32(data, footer + profile.magic_offset, magic) ||
            !read_le32(data, footer + profile.magic_offset + 4, version) ||
            magic != kPakMagic) {
            continue;
        }
        UnrealPakInfo unknown;
        unknown.candidate = true;
        unknown.state = "PARTIAL";
        unknown.footer_profile = "unknown-version-known-eof-position";
        unknown.version = version;
        unknown.footer_offset = footer;
        unknown.footer_size = profile.size;
        unknown.error = "Pak magic occurs at a known exact EOF position, but the version has no pinned layout";
        unknown_version_positions.push_back(std::move(unknown));
    }
    if (!unknown_version_positions.empty()) {
        auto out = std::move(unknown_version_positions.front());
        if (unknown_version_positions.size() > 1) {
            out.footer_profile = "AMBIGUOUS_UNKNOWN_VERSION_EOF_POSITIONS";
            out.footer_offset = 0;
            out.footer_size = 0;
            out.error = "Pak magic/version candidate matches multiple known EOF positions without a pinned layout";
        }
        return out;
    }
    UnrealPakInfo out;
    if (has_extension(input, ".pak")) {
        out.candidate = true;
        out.state = "PARTIAL";
        out.error = "Pak filename extension is present without a recognized exact EOF footer profile";
    }
    return out;
}

bool has_iostore_magic(std::span<const std::uint8_t> data) {
    return data.size() >= kIoStoreMagic.size() &&
           std::equal(kIoStoreMagic.begin(), kIoStoreMagic.end(), data.begin());
}

bool partition_suffix(const std::string& lower_name, const std::string& lower_stem) {
    const std::string prefix = lower_stem + "_s";
    constexpr const char* suffix = ".ucas";
    if (lower_name.size() <= prefix.size() + 5 ||
        lower_name.compare(0, prefix.size(), prefix) != 0 ||
        lower_name.compare(lower_name.size() - 5, 5, suffix) != 0) {
        return false;
    }
    const auto digits_end = lower_name.size() - 5;
    return std::all_of(lower_name.begin() + static_cast<std::ptrdiff_t>(prefix.size()),
                       lower_name.begin() + static_cast<std::ptrdiff_t>(digits_end),
                       [](char c) { return c >= '0' && c <= '9'; });
}

std::filesystem::path expected_partition_path(const std::filesystem::path& toc,
                                              std::uint32_t partition) {
    auto base = toc;
    base.replace_extension();
    if (partition == 0) return path_with_ascii_suffix(base, ".ucas");
    return path_with_ascii_suffix(base, "_s" + std::to_string(partition) + ".ucas");
}

void evaluate_partitions(UnrealIoStoreInfo& out, const std::filesystem::path& input,
                         const std::vector<std::uint64_t>& required) {
    out.pair_checked = true;
    out.partitions.clear();
    for (std::uint32_t i = 0; i < out.partition_count; ++i) {
        UnrealIoStorePartitionInfo part;
        part.index = i;
        part.path = expected_partition_path(input, i);
        part.required_bytes = required[i];
        out.partitions.push_back(std::move(part));
    }
    const auto directory = input.parent_path().empty() ? std::filesystem::path(".") : input.parent_path();
    std::error_code ec;
    std::filesystem::directory_iterator iterator(directory, ec);
    if (ec) {
        out.error = "IoStore sibling directory cannot be inventoried: " + ec.message();
        out.state = "PARTIAL";
        return;
    }
    std::vector<std::filesystem::path> siblings;
    std::uint32_t seen = 0;
    for (const auto& entry : iterator) {
        if (++seen > kSiblingBudget) {
            out.sibling_inventory_truncated = true;
            out.budget_exhausted = true;
            out.error = "IoStore sibling inventory exceeds the bounded directory budget";
            out.state = "PARTIAL";
            return;
        }
        siblings.push_back(entry.path());
    }
    const auto lower_stem = lower_ascii(path_utf8(input.stem()));
    bool bad = false;
    for (auto& part : out.partitions) {
        const auto wanted = path_utf8(part.path.filename());
        const auto lower_wanted = lower_ascii(wanted);
        std::vector<std::filesystem::path> matches;
        for (const auto& sibling : siblings) {
            if (lower_ascii(path_utf8(sibling.filename())) == lower_wanted) matches.push_back(sibling);
        }
        if (matches.size() != 1 || path_utf8(matches.front().filename()) != wanted) {
            bad = true;
            part.state = "PARTIAL";
            part.error = matches.empty() ? "required IoStore partition is missing"
                                         : "required IoStore partition has a case collision or noncanonical case";
            continue;
        }
        std::error_code status_ec;
        const auto status = std::filesystem::symlink_status(matches.front(), status_ec);
        if (status_ec || std::filesystem::is_symlink(status) ||
            !std::filesystem::is_regular_file(status)) {
            bad = true;
            part.state = "PARTIAL";
            part.error = "IoStore partition is not a regular non-symlink file";
            continue;
        }
        const auto size = std::filesystem::file_size(matches.front(), status_ec);
        if (status_ec) {
            bad = true;
            part.state = "PARTIAL";
            part.error = "IoStore partition size cannot be read";
            continue;
        }
        part.file_size = size;
        if (size < part.required_bytes) {
            bad = true;
            part.state = "PARTIAL";
            part.error = "IoStore partition is smaller than declared block geometry";
            continue;
        }
        part.state = "CONFIRMED";
    }
    for (const auto& sibling : siblings) {
        const auto lower_name = lower_ascii(path_utf8(sibling.filename()));
        if (!partition_suffix(lower_name, lower_stem)) continue;
        bool expected = false;
        for (const auto& part : out.partitions) {
            if (lower_ascii(path_utf8(part.path.filename())) == lower_name) {
                expected = true;
                break;
            }
        }
        if (!expected) {
            bad = true;
            out.error = "unexpected IoStore split partition is present beside the TOC";
            break;
        }
    }
    out.pair_valid = !bad;
    if (bad) out.state = "PARTIAL";
}

bool add_section(std::uint64_t& cursor, std::uint64_t count, std::uint64_t width,
                 std::uint64_t file_size) {
    std::uint64_t bytes = 0;
    std::uint64_t end = 0;
    if (!checked_mul(count, width, bytes) || !checked_add(cursor, bytes, end) ||
        end > file_size) {
        return false;
    }
    cursor = end;
    return true;
}

UnrealIoStoreInfo detect_iostore(std::span<const std::uint8_t> data,
                                 const std::filesystem::path& input) {
    UnrealIoStoreInfo out;
    const bool magic = has_iostore_magic(data);
    const bool extension = has_extension(input, ".utoc");
    if (!magic) {
        if (extension || has_extension(input, ".ucas")) {
            out.candidate = true;
            out.state = "PARTIAL";
            out.error = has_extension(input, ".ucas")
                            ? "UCAS data requires a sibling UTOC; no standalone UCAS identity is claimed"
                            : "UTOC filename extension is present without the fixed IoStore TOC magic";
        }
        return out;
    }
    out.candidate = true;
    if (data.size() < 144) {
        out.state = "FAILED";
        out.error = "IoStore TOC header is truncated";
        return out;
    }
    out.version = data[16];
    if (out.version < 1 || out.version > 8) {
        out.state = "PARTIAL";
        out.error = "IoStore TOC version is outside the pinned v1-v8 layout set";
        return out;
    }
    out.supported_version = true;
    read_le32(data, 20, out.header_size);
    read_le32(data, 24, out.entry_count);
    read_le32(data, 28, out.compressed_block_count);
    read_le32(data, 32, out.compressed_block_entry_size);
    read_le32(data, 36, out.compression_method_name_count);
    read_le32(data, 40, out.compression_method_name_length);
    read_le32(data, 44, out.compression_block_size);
    read_le32(data, 48, out.directory_index_size);
    read_le32(data, 52, out.partition_count);
    out.container_flags = data[80];
    read_le32(data, 84, out.perfect_hash_seed_count);
    read_le64(data, 88, out.partition_size);
    read_le32(data, 96, out.chunks_without_perfect_hash_count);
    out.compressed = (out.container_flags & 1U) != 0;
    out.encrypted = (out.container_flags & 2U) != 0;
    out.signed_container = (out.container_flags & 4U) != 0;
    out.indexed = (out.container_flags & 8U) != 0;
    if (out.header_size != 144 || out.compressed_block_entry_size != 12 ||
        out.compression_method_name_length != 32 || out.compression_block_size == 0 ||
        out.partition_count == 0 || out.partition_size == 0 ||
        (out.container_flags & 0xf0U) != 0 || !all_zero(data, 17, 20) ||
        !all_zero(data, 81, 84) || !all_zero(data, 100, 144)) {
        out.state = "FAILED";
        out.error = "IoStore TOC fixed header invariants do not match the pinned layout";
        return out;
    }
    if (out.version < 4 && out.perfect_hash_seed_count != 0) {
        out.state = "FAILED";
        out.error = "IoStore TOC declares perfect-hash seeds before the supporting version";
        return out;
    }
    if (out.version < 5 && out.chunks_without_perfect_hash_count != 0) {
        out.state = "FAILED";
        out.error = "IoStore TOC declares perfect-hash overflow entries before the supporting version";
        return out;
    }
    if (out.entry_count > kIoEntryBudget || out.compressed_block_count > kIoBlockBudget ||
        out.compression_method_name_count > kIoMethodBudget ||
        out.partition_count > kIoPartitionBudget ||
        out.directory_index_size > kDirectoryIndexBudget) {
        out.budget_exhausted = true;
        out.state = "PARTIAL";
        out.error = "IoStore TOC declarations exceed static recognition budgets";
        return out;
    }
    std::uint64_t cursor = out.header_size;
    const auto chunk_ids_at = cursor;
    if (!add_section(cursor, out.entry_count, 12, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore chunk-ID section exceeds the TOC";
        return out;
    }
    const auto offsets_at = cursor;
    if (!add_section(cursor, out.entry_count, 10, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore offset/length section exceeds the TOC";
        return out;
    }
    if (out.version >= 4 &&
        !add_section(cursor, out.perfect_hash_seed_count, 4, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore perfect-hash seed section exceeds the TOC";
        return out;
    }
    if (out.version >= 5 &&
        !add_section(cursor, out.chunks_without_perfect_hash_count, 4, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore perfect-hash overflow section exceeds the TOC";
        return out;
    }
    const auto blocks_at = cursor;
    if (!add_section(cursor, out.compressed_block_count, 12, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore compressed-block section exceeds the TOC";
        return out;
    }
    const auto methods_at = cursor;
    if (!add_section(cursor, out.compression_method_name_count, 32, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore compression-method section exceeds the TOC";
        return out;
    }
    out.compression_methods.clear();
    for (std::uint32_t i = 0; i < out.compression_method_name_count; ++i) {
        const auto at = static_cast<std::size_t>(methods_at + static_cast<std::uint64_t>(i) * 32U);
        std::size_t length = 0;
        while (length < 32 && data[at + length] != 0) ++length;
        if (length == 0 || length == 32 || !all_zero(data, at + length, at + 32)) {
            out.state = "FAILED";
            out.error = "IoStore compression-method slot is empty or lacks canonical NUL padding";
            return out;
        }
        for (std::size_t j = 0; j < length; ++j) {
            if (data[at + j] < 0x20U || data[at + j] > 0x7eU) {
                out.state = "FAILED";
                out.error = "IoStore compression-method name is not printable ASCII";
                return out;
            }
        }
        out.compression_methods.emplace_back(
            reinterpret_cast<const char*>(data.data() + at), length);
    }
    if (out.signed_container) {
        std::uint32_t signature_size = 0;
        if (!read_le32(data, cursor, signature_size) || signature_size > kSignatureBudget) {
            out.state = signature_size > kSignatureBudget ? "PARTIAL" : "FAILED";
            out.budget_exhausted = signature_size > kSignatureBudget;
            out.error = "IoStore signed-section size is truncated or exceeds budget";
            return out;
        }
        cursor += 4;
        if (!add_section(cursor, 2, signature_size, data.size()) ||
            !add_section(cursor, out.compressed_block_count, 20, data.size())) {
            out.state = "FAILED";
            out.error = "IoStore signed section exceeds the TOC";
            return out;
        }
        out.signature_table_structurally_present = true;
    }
    if (out.encrypted && out.directory_index_size % 16U != 0) {
        out.state = "FAILED";
        out.error = "encrypted IoStore directory index is not AES-block aligned";
        return out;
    }
    if (!add_section(cursor, 1, out.directory_index_size, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore directory-index section exceeds the TOC";
        return out;
    }
    const auto meta_width = out.version >= 8 ? 24U : 33U;
    if (!add_section(cursor, out.entry_count, meta_width, data.size())) {
        out.state = "FAILED";
        out.error = "IoStore entry-metadata section exceeds the TOC";
        return out;
    }
    if (cursor != data.size()) {
        out.state = "FAILED";
        out.error = "IoStore TOC contains trailing or unaccounted section bytes";
        return out;
    }
    out.toc_layout_bytes = cursor;

    std::vector<std::array<std::uint8_t, 12>> chunk_ids;
    chunk_ids.reserve(out.entry_count);
    for (std::uint32_t i = 0; i < out.entry_count; ++i) {
        std::array<std::uint8_t, 12> id{};
        const auto at = static_cast<std::size_t>(chunk_ids_at + static_cast<std::uint64_t>(i) * 12U);
        std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(at), 12, id.begin());
        chunk_ids.push_back(id);
    }
    std::sort(chunk_ids.begin(), chunk_ids.end());
    if (std::adjacent_find(chunk_ids.begin(), chunk_ids.end()) != chunk_ids.end()) {
        out.duplicate_chunk_ids = true;
        out.state = "FAILED";
        out.error = "IoStore TOC contains duplicate chunk IDs";
        return out;
    }
    std::uint64_t logical_capacity = 0;
    if (!checked_mul(out.compressed_block_count, out.compression_block_size, logical_capacity)) {
        out.state = "FAILED";
        out.error = "IoStore logical block capacity overflows";
        return out;
    }
    for (std::uint32_t i = 0; i < out.entry_count; ++i) {
        const auto at = static_cast<std::size_t>(offsets_at + static_cast<std::uint64_t>(i) * 10U);
        const auto offset = read_be5(data.data() + at);
        const auto length = read_be5(data.data() + at + 5);
        std::uint64_t end = 0;
        if (!checked_add(offset, length, end) || end > logical_capacity) {
            out.state = "FAILED";
            out.error = "IoStore chunk offset/length exceeds logical block capacity";
            return out;
        }
    }
    std::vector<std::vector<std::pair<std::uint64_t, std::uint64_t>>> ranges(out.partition_count);
    std::vector<std::uint64_t> required(out.partition_count, 0);
    for (std::uint32_t i = 0; i < out.compressed_block_count; ++i) {
        const auto at = static_cast<std::size_t>(blocks_at + static_cast<std::uint64_t>(i) * 12U);
        const auto offset = read_le_n(data.data() + at, 5);
        const auto compressed_size = static_cast<std::uint32_t>(read_le_n(data.data() + at + 5, 3));
        const auto uncompressed_size = static_cast<std::uint32_t>(read_le_n(data.data() + at + 8, 3));
        const auto method = data[at + 11];
        if (compressed_size == 0 || uncompressed_size == 0 ||
            uncompressed_size > out.compression_block_size ||
            method > out.compression_method_name_count) {
            out.state = "FAILED";
            out.error = "IoStore compressed-block sizes or method index are invalid";
            return out;
        }
        std::uint64_t stored_size = compressed_size;
        if (out.encrypted) {
            std::uint64_t padded = 0;
            if (!checked_add(stored_size, 15, padded)) {
                out.state = "FAILED";
                out.error = "IoStore encrypted block size overflows alignment";
                return out;
            }
            stored_size = padded & ~15ULL;
        }
        const auto partition = offset / out.partition_size;
        const auto local = offset % out.partition_size;
        std::uint64_t local_end = 0;
        if (partition >= out.partition_count || !checked_add(local, stored_size, local_end) ||
            local_end > out.partition_size) {
            out.state = "FAILED";
            out.error = "IoStore compressed block falls outside one declared partition";
            return out;
        }
        auto& partition_ranges = ranges[static_cast<std::size_t>(partition)];
        partition_ranges.emplace_back(local, local_end);
        required[static_cast<std::size_t>(partition)] =
            std::max(required[static_cast<std::size_t>(partition)], local_end);
    }
    for (auto& partition_ranges : ranges) {
        std::sort(partition_ranges.begin(), partition_ranges.end());
        for (std::size_t i = 1; i < partition_ranges.size(); ++i) {
            if (partition_ranges[i].first < partition_ranges[i - 1].second) {
                out.state = "FAILED";
                out.error = "IoStore compressed block ranges overlap within a partition";
                return out;
            }
        }
    }
    out.toc_valid = true;
    out.state = "CONFIRMED";
    evaluate_partitions(out, input, required);
    if (!out.pair_valid) {
        out.valid = false;
        if (out.error.empty()) out.error = "IoStore TOC did not close to all exact UCAS partitions";
        out.state = "PARTIAL";
        return out;
    }
    if (out.encrypted) {
        out.valid = false;
        out.state = "PARTIAL";
        out.error = "IoStore directory index is encrypted; an explicit credential is required";
        return out;
    }
    out.valid = true;
    out.state = "CONFIRMED";
    return out;
}

std::string bool_text(bool value) {
    return value ? "true" : "false";
}

} // namespace

UnrealInfo detect_unreal_container(std::span<const std::uint8_t> data,
                                   const std::filesystem::path& input) {
    UnrealInfo out;
    out.iostore = detect_iostore(data, input);
    const auto use_iostore = [&]() {
        out.candidate = true;
        out.valid = out.iostore.valid;
        out.kind = has_extension(input, ".ucas") && !has_iostore_magic(data)
                       ? "iostore-ucas"
                       : "iostore-utoc";
        out.state = out.iostore.state;
        out.error = out.iostore.error;
    };
    const auto use_pak = [&]() {
        out.candidate = true;
        out.valid = out.pak.valid;
        out.kind = "pak";
        out.state = out.pak.state;
        out.error = out.pak.error;
    };
    if (has_iostore_magic(data)) {
        use_iostore();
        return out;
    }
    out.pak = detect_pak(data, input);
    if (out.pak.candidate &&
        (!out.pak.footer_profile.empty() || !out.iostore.candidate)) {
        use_pak();
        return out;
    }
    if (out.iostore.candidate) use_iostore();
    return out;
}

Finding unreal_container_finding(const UnrealInfo& info) {
    Finding finding;
    finding.kind = "container";
    finding.state = info.state;
    if (info.kind == "pak") {
        const auto& pak = info.pak;
        finding.family = "Unreal Engine Pak";
        finding.variant = pak.footer_profile.empty() ? "extension-only" : pak.footer_profile;
        finding.fields["version"] = std::to_string(pak.version);
        finding.fields["footer_profile"] = pak.footer_profile;
        finding.fields["index_offset"] = std::to_string(pak.index_offset);
        finding.fields["index_size"] = std::to_string(pak.index_size);
        finding.fields["entry_count"] = std::to_string(pak.entry_count);
        finding.fields["mount_point"] = pak.mount_point;
        finding.fields["encrypted_index"] = bool_text(pak.encrypted_index);
        finding.fields["frozen_index"] = bool_text(pak.frozen_index);
        finding.fields["index_hash_checked"] = bool_text(pak.index_hash_checked);
        finding.fields["index_hash_matches"] = bool_text(pak.index_hash_matches);
        finding.fields["secondary_index_count"] = std::to_string(pak.secondary_index_count);
        finding.fields["secondary_index_hashes_checked"] =
            bool_text(pak.secondary_index_hashes_checked);
        finding.fields["secondary_index_hashes_match"] =
            bool_text(pak.secondary_index_hashes_match);
        finding.fields["content_readable"] = "false";
        finding.fields["asset_semantics_enumerated"] = "false";
        if (pak.footer_size != 0) {
            finding.ranges.push_back(
                file_offset_range(pak.footer_offset, pak.footer_size, "exact-version Pak footer"));
        }
        if (pak.index_size != 0) {
            finding.ranges.push_back(
                file_offset_range(pak.index_offset, pak.index_size, "Pak primary index"));
        }
        if (pak.valid) {
            finding.confidence = 0.99;
            finding.evidence.push_back(
                "exact EOF footer profile, bounded index range, primary-index SHA-1, and minimum version-specific index structure validated");
            finding.evidence.push_back(
                "recognition is structural only; no asset list, decryption, decompression, or extraction is claimed");
        } else if (!pak.error.empty()) {
            finding.negative_evidence.push_back(pak.error);
        }
    } else {
        const auto& io = info.iostore;
        finding.family = "Unreal Engine IoStore";
        finding.variant = info.kind;
        finding.fields["version"] = std::to_string(io.version);
        finding.fields["toc_valid"] = bool_text(io.toc_valid);
        finding.fields["pair_checked"] = bool_text(io.pair_checked);
        finding.fields["pair_valid"] = bool_text(io.pair_valid);
        finding.fields["entry_count"] = std::to_string(io.entry_count);
        finding.fields["compressed_block_count"] = std::to_string(io.compressed_block_count);
        finding.fields["partition_count"] = std::to_string(io.partition_count);
        finding.fields["partition_size"] = std::to_string(io.partition_size);
        finding.fields["encrypted"] = bool_text(io.encrypted);
        finding.fields["signed_flag"] = bool_text(io.signed_container);
        finding.fields["signature_table_structurally_present"] =
            bool_text(io.signature_table_structurally_present);
        finding.fields["signature_verification_performed"] = "false";
        finding.fields["indexed"] = bool_text(io.indexed);
        finding.fields["asset_semantics_enumerated"] = "false";
        finding.fields["content_readable"] = "false";
        if (io.header_size != 0) {
            finding.ranges.push_back(file_offset_range(0, io.header_size, "IoStore TOC header"));
        }
        if (io.toc_layout_bytes != 0) {
            finding.ranges.push_back(
                file_offset_range(0, io.toc_layout_bytes, "bounded IoStore TOC layout"));
        }
        if (io.valid) {
            finding.confidence = 0.99;
            finding.evidence.push_back(
                "fixed TOC header, every bounded section, chunk uniqueness, block geometry, and exact UCAS partition set validated");
            if (io.signed_container) {
                finding.evidence.push_back(
                    "signature table is structurally present; cryptographic signature verification was not performed");
            }
            finding.evidence.push_back(
                "recognition is structural only; no directory-index semantics, decryption, decompression, or extraction is claimed");
        } else if (!io.error.empty()) {
            finding.negative_evidence.push_back(io.error);
        }
    }
    if (!info.error.empty() && finding.negative_evidence.empty()) {
        finding.negative_evidence.push_back(info.error);
    }
    return finding;
}

} // namespace prts
