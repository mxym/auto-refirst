#include "prts/apk.hpp"
#include "prts/android.hpp"
#include "prts/unity.hpp"
#include "prts/elf.hpp"
#include "Zydis.h"
#include "prts/hermes.hpp"
#include "prts/sha256.hpp"

#define MINIZ_NO_ZLIB_APIS
#include "miniz.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <deque>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace prts {
namespace {

constexpr std::uint32_t kLocalHeaderSig = 0x04034b50u;
constexpr std::uint32_t kCentralHeaderSig = 0x02014b50u;
constexpr std::uint32_t kV2BlockId = 0x7109871au;
constexpr std::uint32_t kV3BlockId = 0xf05368c0u;
constexpr std::uint32_t kV31BlockId = 0x1b93ad61u;
constexpr std::uint32_t kV32BlockId = 0x70e1c89fu;
constexpr std::uint32_t kSourceStampV1BlockId = 0x2b09189eu;
constexpr std::uint32_t kSourceStampV2BlockId = 0x6dff800du;
constexpr std::uint32_t kVerityPaddingBlockId = 0x42726577u;
constexpr std::uint16_t kZipFlagEncrypted = 0x0001u;
constexpr std::array<std::uint8_t, 8> kHermesMagic = {
    0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f
};
constexpr std::uint32_t kMaxHermesProbeEntries = 512;
constexpr std::uint64_t kMaxHermesProbeBytes = 64ull * 1024 * 1024;
constexpr std::uint16_t kZipFlagStrongEncryption = 0x0040u;
constexpr std::array<std::uint8_t, 16> kApkSigMagic = {
    'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'
};

std::uint16_t le16(std::span<const std::uint8_t> b, std::uint64_t off) {
    if (off > b.size() || 2 > b.size() - off) return 0;
    return std::uint16_t(b[off]) | (std::uint16_t(b[off + 1]) << 8);
}

std::uint32_t le32(std::span<const std::uint8_t> b, std::uint64_t off) {
    if (off > b.size() || 4 > b.size() - off) return 0;
    return std::uint32_t(b[off]) | (std::uint32_t(b[off + 1]) << 8) |
           (std::uint32_t(b[off + 2]) << 16) | (std::uint32_t(b[off + 3]) << 24);
}

std::uint64_t le64(std::span<const std::uint8_t> b, std::uint64_t off) {
    if (off > b.size() || 8 > b.size() - off) return 0;
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= std::uint64_t(b[off + i]) << (i * 8);
    return v;
}

bool add_u64(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (b > std::numeric_limits<std::uint64_t>::max() - a) return false;
    out = a + b;
    return true;
}

std::string lower_ascii(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool ends_with_ci(std::string_view s, std::string_view suffix) {
    if (s.size() < suffix.size()) return false;
    return lower_ascii(s.substr(s.size() - suffix.size())) == lower_ascii(suffix);
}

bool windows_reserved_component(std::string_view part) {
    if (part.empty()) return true;
    if (part.back() == ' ' || part.back() == '.') return true;
    const auto dot = part.find('.');
    const auto base = lower_ascii(part.substr(0, dot));
    if (base == "con" || base == "prn" || base == "aux" || base == "nul" ||
        base == "conin$" || base == "conout$") return true;
    if (base.size() == 4 && (base.starts_with("com") || base.starts_with("lpt")) &&
        base[3] >= '1' && base[3] <= '9') return true;
    return false;
}

bool safe_relative_name(std::string_view raw, bool directory, std::string& normalized) {
    normalized.clear();
    if (raw.empty() || raw.front() == '/' || raw.front() == '\\') return false;
    std::string tmp;
    tmp.reserve(raw.size());
    for (const unsigned char c : raw) {
        if (c < 0x20 || c == 0x7f || c == ':') return false;
        tmp.push_back(c == '\\' ? '/' : static_cast<char>(c));
    }
    while (directory && !tmp.empty() && tmp.back() == '/') tmp.pop_back();
    if (tmp.empty()) return directory;
    std::size_t start = 0;
    while (start <= tmp.size()) {
        const auto slash = tmp.find('/', start);
        const auto end = slash == std::string::npos ? tmp.size() : slash;
        const auto part = std::string_view(tmp).substr(start, end - start);
        if (part.empty() || part == "." || part == ".." || windows_reserved_component(part)) return false;
        if (!normalized.empty()) normalized += '/';
        normalized.append(part);
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return !normalized.empty();
}

bool is_dex_name(std::string_view name) {
    if (name == "classes.dex") return true;
    if (!name.starts_with("classes") || !name.ends_with(".dex")) return false;
    const auto digits = name.substr(7, name.size() - 7 - 4);
    if (digits.empty()) return false;
    std::uint64_t n = 0;
    for (const char c : digits) {
        if (c < '0' || c > '9') return false;
        n = n * 10 + std::uint64_t(c - '0');
        if (n > 1000000) return false;
    }
    return n >= 2;
}

bool is_native_library_path(std::string_view name, std::string& abi) {
    abi.clear();
    if (!name.starts_with("lib/") || !ends_with_ci(name, ".so")) return false;
    const auto first = name.find('/', 4);
    if (first == std::string_view::npos || first == 4 || first + 1 >= name.size()) return false;
    if (name.find('/', first + 1) != std::string_view::npos) return false;
    abi.assign(name.substr(4, first - 4));
    return true;
}

bool is_v1_signing_file(std::string_view name) {
    const auto low = lower_ascii(name);
    if (!low.starts_with("meta-inf/")) return false;
    const auto leaf = std::string_view(low).substr(9);
    if (leaf.empty() || leaf.find('/') != std::string_view::npos) return false;
    return leaf == "manifest.mf" || leaf.ends_with(".sf") || leaf.ends_with(".rsa") ||
           leaf.ends_with(".dsa") || leaf.ends_with(".ec");
}

bool is_nested_archive(std::string_view name) {
    return ends_with_ci(name, ".apk") || ends_with_ci(name, ".jar") || ends_with_ci(name, ".zip");
}

bool is_godot_legacy_engine_config_resource_path(std::string_view name) {
    return lower_ascii(name) == "assets/engine.cfb";
}

bool is_unity_il2cpp_metadata_resource_path(std::string_view name) {
    const auto low = lower_ascii(name);
    if (!low.starts_with("assets/")) return false;
    return low.ends_with("/managed/metadata/global-metadata.dat") ||
           low.ends_with("/il2cpp_data/metadata/global-metadata.dat");
}

bool has_analysis_extension(std::string_view name) {
    const auto slash = name.find_last_of('/');
    const auto leaf = slash == std::string_view::npos ? name : name.substr(slash + 1);
    const auto dot = leaf.find_last_of('.');
    if (dot == std::string_view::npos) return false;
    const auto ext = lower_ascii(leaf.substr(dot));
    static const std::set<std::string> exts = {
        ".bin", ".cfg", ".dat", ".db", ".dex", ".html", ".htm", ".ini", ".jar", ".js", ".json",
        ".kt", ".kts", ".lua", ".mjs", ".pak", ".prof", ".profm", ".properties", ".py", ".sqlite",
        ".toml", ".txt", ".wasm", ".xml", ".yaml", ".yml", ".zip"
    };
    return exts.contains(ext);
}

std::uint8_t analysis_priority_for(const ApkEntryInfo& e, std::string_view logical) {
    // Manifest/resources are already deeply decoded in the parent APK report, so recursive
    // materialization prioritizes children that can produce new static-analysis facts.
    if (e.manifest || e.resources_arsc) return 0;
    if (e.dex) return 100;
    if (e.native_library || e.nested_archive) return 95;
    if (e.godot_legacy_engine_config_candidate) return 92;
    if (e.unity_il2cpp_metadata_candidate) return 90;
    if (logical.starts_with("res/raw/") || logical.starts_with("res/xml/")) return 80;
    if (e.asset && has_analysis_extension(logical)) return 75;
    if ((logical.starts_with("META-INF/services/") || logical.starts_with("META-INF/com/android/build/gradle/")) &&
        has_analysis_extension(logical)) return 65;
    if (logical.find('/') == std::string_view::npos && has_analysis_extension(logical) && e.uncompressed_size <= 1024u * 1024u) return 60;
    return 0;
}

std::string signing_block_label(std::uint32_t id) {
    switch (id) {
        case kV2BlockId: return "APK Signature Scheme v2";
        case kV3BlockId: return "APK Signature Scheme v3";
        case kV31BlockId: return "APK Signature Scheme v3.1";
        case kV32BlockId: return "APK Signature Scheme v3.2";
        case kSourceStampV1BlockId: return "APK Source Stamp v1";
        case kSourceStampV2BlockId: return "APK Source Stamp v2";
        case kVerityPaddingBlockId: return "APK Signing Block verity padding";
        default: return {};
    }
}

ApkSigningBlockInfo parse_signing_block(std::span<const std::uint8_t> data,
                                        std::uint64_t central_dir_off) {
    ApkSigningBlockInfo out;
    if (central_dir_off < 24 || central_dir_off > data.size()) return out;
    const auto magic_off = central_dir_off - 16;
    if (!std::equal(kApkSigMagic.begin(), kApkSigMagic.end(), data.begin() + magic_off)) return out;
    out.present = true;
    const auto footer_size_off = central_dir_off - 24;
    const auto size = le64(data, footer_size_off);
    if (size < 24 || size > central_dir_off - 8) {
        out.error = "invalid APK Signing Block size";
        out.error_offset = footer_size_off;
        return out;
    }
    const auto total = size + 8;
    const auto block_off = central_dir_off - total;
    out.block_offset = block_off;
    out.block_size = total;
    if (le64(data, block_off) != size) {
        out.error = "APK Signing Block header/footer size mismatch";
        out.error_offset = block_off;
        return out;
    }
    std::uint64_t cursor = block_off + 8;
    const auto pairs_end = footer_size_off;
    std::set<std::uint32_t> ids;
    while (cursor < pairs_end) {
        if (pairs_end - cursor < 8) {
            out.error = "truncated APK Signing Block pair length";
            out.error_offset = cursor;
            return out;
        }
        const auto pair_off = cursor;
        const auto pair_size = le64(data, cursor);
        cursor += 8;
        if (pair_size < 4 || pair_size > pairs_end - cursor) {
            out.error = "invalid APK Signing Block pair size";
            out.error_offset = pair_off;
            return out;
        }
        const auto id = le32(data, cursor);
        if (!ids.insert(id).second) {
            out.anomalies.push_back("duplicate APK Signing Block pair ID 0x" + [&](){
                constexpr char hex[] = "0123456789abcdef";
                std::string x(8, '0');
                for (unsigned n = 0; n < 8; ++n) x[7 - n] = hex[(id >> (n * 4)) & 0xfu];
                return x;
            }() + " (inventory ambiguity; signature verification not performed)");
        }
        ApkSigningBlockPair p;
        p.id = id;
        p.value_size = pair_size - 4;
        p.pair_offset = pair_off;
        p.label = signing_block_label(id);
        out.pairs.push_back(std::move(p));
        if (id == kV2BlockId) out.has_v2 = true;
        else if (id == kV3BlockId) out.has_v3 = true;
        else if (id == kV31BlockId) out.has_v31 = true;
        else if (id == kV32BlockId) out.has_v32 = true;
        else if (id == kSourceStampV1BlockId) out.has_source_stamp_v1 = true;
        else if (id == kSourceStampV2BlockId) out.has_source_stamp_v2 = true;
        else if (id == kVerityPaddingBlockId) out.has_verity_padding = true;
        else out.has_unknown_pairs = true;
        cursor += pair_size;
    }
    if (cursor != pairs_end) {
        out.error = "APK Signing Block pairs do not end at footer";
        out.error_offset = cursor;
        return out;
    }
    out.valid = true;
    if (out.pairs.empty()) out.anomalies.push_back("APK Signing Block has no ID-value pairs");
    return out;
}

std::vector<std::uint8_t> entry_prefix(mz_zip_archive& zip, const ApkEntryInfo& e,
                                       std::size_t want, std::span<const std::uint8_t> data) {
    const auto n64 = std::min<std::uint64_t>(e.uncompressed_size, want);
    const auto n = static_cast<std::size_t>(n64);
    std::vector<std::uint8_t> out(n);
    if (n == 0 || e.directory || e.encrypted || !e.supported) return out;
    if (e.method == 0) {
        if (e.data_offset > data.size() || n > data.size() - e.data_offset) return {};
        std::copy_n(data.begin() + e.data_offset, n, out.begin());
        return out;
    }
    auto* it = mz_zip_reader_extract_iter_new(&zip, e.index, 0);
    if (!it) return {};
    std::size_t got = 0;
    while (got < n) {
        const auto z = mz_zip_reader_extract_iter_read(it, out.data() + got, n - got);
        if (z == 0) break;
        got += z;
    }
    (void)mz_zip_reader_extract_iter_free(it);  // Prefix probing intentionally stops early.
    // Early iterator disposal reports an incomplete extraction by design. Prefix probing
    // is not a full-entry integrity check, so do not let that stale status poison a later
    // real ZIP diagnostic.
    mz_zip_clear_last_error(&zip);
    if (got != n) return {};
    return out;
}

void append_utf8_cp(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7f) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
    }
}

bool valid_utf8(std::string_view s) {
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<std::uint8_t>(s[i]);
        if (c < 0x80) { ++i; continue; }
        unsigned n = 0; std::uint32_t cp = 0, min = 0;
        if ((c & 0xe0u) == 0xc0u) { n = 2; cp = c & 0x1fu; min = 0x80; }
        else if ((c & 0xf0u) == 0xe0u) { n = 3; cp = c & 0x0fu; min = 0x800; }
        else if ((c & 0xf8u) == 0xf0u) { n = 4; cp = c & 0x07u; min = 0x10000; }
        else return false;
        if (i + n > s.size()) return false;
        for (unsigned z = 1; z < n; ++z) {
            const auto q = static_cast<std::uint8_t>(s[i + z]);
            if ((q & 0xc0u) != 0x80u) return false;
            cp = (cp << 6) | (q & 0x3fu);
        }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
        i += n;
    }
    return true;
}

std::string utf16le_to_utf8(std::span<const std::uint8_t> bytes, std::uint32_t units, bool& ok) {
    ok = false;
    if (std::uint64_t(units) * 2 > bytes.size()) return {};
    std::string out;
    for (std::uint32_t i = 0; i < units; ++i) {
        const auto u = std::uint16_t(bytes[i * 2]) | (std::uint16_t(bytes[i * 2 + 1]) << 8);
        if (u >= 0xd800 && u <= 0xdbff) {
            if (++i >= units) return {};
            const auto lo = std::uint16_t(bytes[i * 2]) | (std::uint16_t(bytes[i * 2 + 1]) << 8);
            if (lo < 0xdc00 || lo > 0xdfff) return {};
            append_utf8_cp(out, 0x10000u + ((std::uint32_t(u - 0xd800) << 10) | std::uint32_t(lo - 0xdc00)));
        } else if (u >= 0xdc00 && u <= 0xdfff) return {};
        else append_utf8_cp(out, u);
    }
    ok = true;
    return out;
}

struct AxmlError {
    std::string message;
    std::uint64_t offset = 0;
};

class AxmlParser {
public:
    explicit AxmlParser(std::span<const std::uint8_t> data) : d_(data) {}
    ApkManifestInfo run() {
        if (d_.size() < 8 || le16(d_, 0) != 0x0003) return out_;
        out_.candidate = true;
        try {
            parse();
            out_.valid = true;
            out_.parse_complete = true;
        } catch (const AxmlError& e) {
            out_.error = e.message;
            out_.error_offset = e.offset;
        }
        return out_;
    }
private:
    static constexpr std::uint32_t kNoString = 0xffffffffu;
    std::span<const std::uint8_t> d_;
    ApkManifestInfo out_;
    std::vector<std::string> strings_;
    std::vector<std::uint32_t> resource_ids_;
    std::vector<std::string> element_stack_;
    bool string_pool_seen_ = false;
    bool resource_map_seen_ = false;
    bool root_seen_ = false;
    bool root_closed_ = false;

    [[noreturn]] void fail(std::uint64_t off, std::string msg) const { throw AxmlError{std::move(msg), off}; }
    void need(std::uint64_t off, std::uint64_t n, std::string_view what) const {
        if (off > d_.size() || n > d_.size() - off) fail(off, "truncated binary Android XML " + std::string(what));
    }
    std::uint16_t u16(std::uint64_t off) const { need(off, 2, "uint16"); return le16(d_, off); }
    std::uint32_t u32(std::uint64_t off) const { need(off, 4, "uint32"); return le32(d_, off); }
    const std::string& str(std::uint32_t idx, std::uint64_t ref_off, bool allow_none = false) const {
        static const std::string empty;
        if (idx == kNoString && allow_none) return empty;
        if (idx >= strings_.size()) fail(ref_off, "binary Android XML string index out of range");
        return strings_[idx];
    }
    static bool read_len8(std::span<const std::uint8_t> d, std::uint64_t& p, std::uint64_t end, std::uint32_t& out) {
        if (p >= end) return false;
        const auto x = d[p++];
        if ((x & 0x80u) == 0) { out = x; return true; }
        if (p >= end) return false;
        out = (std::uint32_t(x & 0x7fu) << 8) | d[p++];
        return true;
    }
    static bool read_len16(std::span<const std::uint8_t> d, std::uint64_t& p, std::uint64_t end, std::uint32_t& out) {
        if (p + 2 > end) return false;
        auto x = std::uint16_t(d[p]) | (std::uint16_t(d[p + 1]) << 8); p += 2;
        if ((x & 0x8000u) == 0) { out = x; return true; }
        if (p + 2 > end) return false;
        auto y = std::uint16_t(d[p]) | (std::uint16_t(d[p + 1]) << 8); p += 2;
        out = (std::uint32_t(x & 0x7fffu) << 16) | y; return true;
    }
    void parse_string_pool(std::uint64_t off, std::uint16_t hs, std::uint32_t size) {
        if (string_pool_seen_) fail(off, "duplicate binary Android XML string pool");
        if (hs < 28 || size < hs) fail(off, "invalid binary Android XML string-pool header");
        const auto count = u32(off + 8), style_count = u32(off + 12), flags = u32(off + 16);
        const auto strings_start = u32(off + 20), styles_start = u32(off + 24);
        if (count > 1000000 || style_count > 1000000) fail(off + 8, "unreasonable binary Android XML string/style count");
        const auto offsets_bytes = std::uint64_t(count + style_count) * 4;
        if (offsets_bytes > size - hs) fail(off + hs, "binary Android XML string/style offset arrays exceed chunk");
        if (strings_start < std::uint64_t(hs) + offsets_bytes || strings_start >= size) fail(off + 20, "invalid binary Android XML stringsStart");
        if (styles_start != 0 && (styles_start < strings_start || styles_start >= size)) fail(off + 24, "invalid binary Android XML stylesStart");
        const auto string_end = styles_start ? std::uint64_t(off) + styles_start : std::uint64_t(off) + size;
        const bool utf8 = (flags & 0x100u) != 0;
        out_.string_pool_utf8 = utf8;
        strings_.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto roff = u32(off + hs + std::uint64_t(i) * 4);
            if (roff >= size - strings_start) fail(off + hs + std::uint64_t(i) * 4, "binary Android XML string offset exceeds string data");
            std::uint64_t p = off + strings_start + roff;
            if (p >= string_end) fail(p, "binary Android XML string offset exceeds string pool");
            if (utf8) {
                std::uint32_t utf16_len = 0, bytes_len = 0;
                if (!read_len8(d_, p, string_end, utf16_len) || !read_len8(d_, p, string_end, bytes_len)) fail(p, "truncated binary Android XML UTF-8 length");
                if (bytes_len > string_end - p || p + bytes_len >= string_end) fail(p, "binary Android XML UTF-8 string exceeds pool");
                std::string text(reinterpret_cast<const char*>(d_.data() + p), bytes_len);
                if (!valid_utf8(text) || d_[p + bytes_len] != 0) fail(p, "invalid binary Android XML UTF-8 string");
                // Validate the encoded UTF-16 length cheaply by counting Unicode scalar units.
                std::uint32_t units = 0;
                for (std::size_t q = 0; q < text.size();) {
                    const auto c = static_cast<std::uint8_t>(text[q]);
                    std::uint32_t cp = 0; unsigned n = 0;
                    if (c < 0x80) { cp = c; n = 1; }
                    else if ((c & 0xe0u) == 0xc0u) { cp = c & 0x1fu; n = 2; }
                    else if ((c & 0xf0u) == 0xe0u) { cp = c & 0x0fu; n = 3; }
                    else { cp = c & 0x07u; n = 4; }
                    for (unsigned z = 1; z < n; ++z) cp = (cp << 6) | (static_cast<std::uint8_t>(text[q + z]) & 0x3fu);
                    units += cp > 0xffff ? 2u : 1u; q += n;
                }
                if (units != utf16_len) fail(p, "binary Android XML UTF-8 UTF-16-length mismatch");
                strings_.push_back(std::move(text));
            } else {
                std::uint32_t units = 0;
                if (!read_len16(d_, p, string_end, units)) fail(p, "truncated binary Android XML UTF-16 length");
                const auto bytes = std::uint64_t(units) * 2;
                if (bytes > string_end - p || p + bytes + 2 > string_end || u16(p + bytes) != 0) fail(p, "binary Android XML UTF-16 string exceeds pool");
                bool ok = false; auto text = utf16le_to_utf8(d_.subspan(p, bytes), units, ok);
                if (!ok) fail(p, "invalid surrogate sequence in binary Android XML UTF-16 string");
                strings_.push_back(std::move(text));
            }
        }
        string_pool_seen_ = true;
        out_.string_count = count;
    }
    struct Attr {
        std::string name;
        std::string ns;
        std::string raw;
        std::uint8_t type = 0;
        std::uint32_t data = 0;
        std::string value;
        bool reference = false;
    };
    Attr attr(std::uint64_t a, std::uint16_t asz) const {
        if (asz < 20) fail(a, "binary Android XML attributeSize is smaller than ResXMLTree_attribute");
        Attr x;
        const auto ns_idx = u32(a), name_idx = u32(a + 4), raw_idx = u32(a + 8);
        x.ns = str(ns_idx, a, true); x.name = str(name_idx, a + 4); x.raw = str(raw_idx, a + 8, true);
        const auto value_size = u16(a + 12);
        const auto res0 = d_[a + 14];
        x.type = d_[a + 15]; x.data = u32(a + 16);
        if (value_size != 8 || res0 != 0) fail(a + 12, "invalid binary Android XML Res_value header");
        if (x.type == 0x03) x.value = str(x.data, a + 16);
        else if (x.type == 0x12) x.value = x.data ? "true" : "false";
        else if (x.type == 0x10) x.value = std::to_string(x.data);
        else if (x.type == 0x11) {
            constexpr char h[] = "0123456789abcdef"; x.value = "0x"; bool started = false;
            for (int n = 7; n >= 0; --n) { const auto q = unsigned((x.data >> (n * 4)) & 0xfu); if (q || started || n == 0) { x.value.push_back(h[q]); started = true; } }
        } else if (x.type == 0x01 || x.type == 0x07) {
            x.reference = true; constexpr char h[] = "0123456789abcdef"; x.value = "@0x";
            for (int n = 7; n >= 0; --n) x.value.push_back(h[(x.data >> (n * 4)) & 0xfu]);
        } else if (!x.raw.empty()) x.value = x.raw;
        else {
            constexpr char h[] = "0123456789abcdef"; x.value = "type=0x"; x.value.push_back(h[(x.type >> 4)&0xf]); x.value.push_back(h[x.type&0xf]); x.value += ":0x";
            for (int n = 7; n >= 0; --n) x.value.push_back(h[(x.data >> (n * 4)) & 0xfu]);
        }
        return x;
    }
    static std::string qualify(std::string_view package, std::string name) {
        if (name.empty() || package.empty()) return name;
        if (name.front() == '.') return std::string(package) + name;
        if (name.find('.') == std::string::npos) return std::string(package) + "." + name;
        return name;
    }
    const Attr* find_plain_attr(const std::vector<Attr>& attrs, std::string_view name) const {
        const auto it = std::find_if(attrs.begin(), attrs.end(), [&](const Attr& a){ return a.name == name && a.ns.empty(); });
        return it == attrs.end() ? nullptr : &*it;
    }
    const Attr* find_android_attr(const std::vector<Attr>& attrs, std::string_view name) const {
        constexpr std::string_view android_ns = "http://schemas.android.com/apk/res/android";
        const auto it = std::find_if(attrs.begin(), attrs.end(), [&](const Attr& a){ return a.name == name && a.ns == android_ns; });
        return it == attrs.end() ? nullptr : &*it;
    }
    std::string_view parent_tag() const { return element_stack_.empty() ? std::string_view{} : std::string_view(element_stack_.back()); }
    void consume_element(std::string tag, const std::vector<Attr>& attrs, std::uint64_t chunk_off) {
        if (element_stack_.empty()) {
            if (root_seen_) fail(chunk_off, "binary Android XML contains multiple root elements");
            if (tag != "manifest") fail(chunk_off, "binary Android XML root element is not manifest");
            root_seen_ = true;
        }
        const auto parent = parent_tag();
        if (tag == "manifest") {
            if (!parent.empty()) fail(chunk_off, "manifest element is nested instead of root");
            if (const auto* a = find_plain_attr(attrs, "package")) {
                if (!a->reference && a->type == 0x03) out_.package_name = a->value;
                else out_.anomalies.push_back("manifest package is not a literal string: " + a->value);
            }
            if (const auto* a = find_android_attr(attrs, "versionName")) out_.version_name = a->value;
            if (const auto* a = find_android_attr(attrs, "versionCode")) {
                if (a->type == 0x10 || a->type == 0x11) { out_.version_code_known = true; out_.version_code = a->data; }
                else out_.anomalies.push_back("versionCode is not a literal integer: " + a->value);
            }
        } else if (tag == "uses-sdk" && parent == "manifest") {
            if (const auto* a = find_android_attr(attrs, "minSdkVersion")) {
                if (a->type == 0x10 || a->type == 0x11) { out_.min_sdk_known = true; out_.min_sdk = a->data; }
                else out_.anomalies.push_back("minSdkVersion is not a literal integer: " + a->value);
            }
            if (const auto* a = find_android_attr(attrs, "targetSdkVersion")) {
                if (a->type == 0x10 || a->type == 0x11) { out_.target_sdk_known = true; out_.target_sdk = a->data; }
                else out_.anomalies.push_back("targetSdkVersion is not a literal integer: " + a->value);
            }
        } else if (tag == "application" && parent == "manifest") {
            if (const auto* a = find_android_attr(attrs, "name")) {
                if (!a->reference && a->type == 0x03) out_.application_name = qualify(out_.package_name, a->value);
                else out_.anomalies.push_back("application name is not a literal string: " + a->value);
            }
            if (const auto* a = find_android_attr(attrs, "debuggable")) {
                if (a->type == 0x12) { out_.debuggable_known = true; out_.debuggable = a->data != 0; }
                else if (a->reference) { out_.debuggable_reference = true; out_.debuggable_reference_id = a->data; }
                else out_.anomalies.push_back("application debuggable has unresolved typed value: " + a->value);
            }
        } else if ((tag == "uses-permission" || tag == "uses-permission-sdk-23" || tag == "uses-permission-sdk-m") && parent == "manifest") {
            if (const auto* a = find_android_attr(attrs, "name"); a && !a->reference && a->type == 0x03 && !a->value.empty()) out_.permissions.push_back(a->value);
        } else {
            const bool instrumentation = tag == "instrumentation" && parent == "manifest";
            const bool app_component = (tag == "activity" || tag == "activity-alias" || tag == "service" || tag == "receiver" || tag == "provider") && parent == "application";
            if (instrumentation || app_component) {
                ApkManifestComponent c; c.kind = tag;
                if (const auto* a = find_android_attr(attrs, "name")) { if (!a->reference && a->type == 0x03) c.name = qualify(out_.package_name, a->value); }
                if (const auto* a = find_android_attr(attrs, "process")) { if (!a->reference && a->type == 0x03) c.process = a->value; }
                if (const auto* a = find_android_attr(attrs, "exported")) {
                    if (a->type == 0x12) { c.exported_known = true; c.exported = a->data != 0; }
                    else if (a->reference) { c.exported_reference = true; c.exported_reference_id = a->data; }
                }
                out_.components.push_back(std::move(c));
            }
        }
    }
    void parse_start_element(std::uint64_t off, std::uint16_t hs, std::uint32_t size) {
        if (!string_pool_seen_) fail(off, "binary Android XML start element appears before string pool");
        if (root_closed_) fail(off, "binary Android XML start element appears after root close");
        if (hs < 16 || size < std::uint32_t(hs) + 20u) fail(off, "invalid binary Android XML start-element header");
        const auto ext = off + hs;
        const auto tag = str(u32(ext + 4), ext + 4);
        const auto attribute_start = u16(ext + 8), attribute_size = u16(ext + 10), attribute_count = u16(ext + 12);
        const auto id_index = u16(ext + 14), class_index = u16(ext + 16), style_index = u16(ext + 18);
        if (attribute_size < 20) fail(ext + 10, "binary Android XML attributeSize is too small");
        if ((id_index && id_index > attribute_count) || (class_index && class_index > attribute_count) || (style_index && style_index > attribute_count)) fail(ext + 14, "binary Android XML special attribute index exceeds attributeCount");
        const auto attrs = ext + attribute_start;
        const auto bytes = std::uint64_t(attribute_size) * attribute_count;
        if (attribute_start < 20 || attrs > off + size || bytes > off + size - attrs) fail(ext + 8, "binary Android XML attributes exceed start-element chunk");
        std::vector<Attr> av; av.reserve(attribute_count);
        std::set<std::pair<std::string,std::string>> attr_names;
        for (std::uint16_t i = 0; i < attribute_count; ++i) {
            auto x = attr(attrs + std::uint64_t(i) * attribute_size, attribute_size);
            if (!attr_names.emplace(x.ns, x.name).second) fail(attrs + std::uint64_t(i) * attribute_size, "duplicate binary Android XML attribute namespace/name");
            av.push_back(std::move(x));
        }
        consume_element(tag, av, off);
        element_stack_.push_back(tag); ++out_.start_element_count;
    }
    void parse_end_element(std::uint64_t off, std::uint16_t hs, std::uint32_t size) {
        if (hs < 16 || size < std::uint32_t(hs) + 8u) fail(off, "invalid binary Android XML end-element header");
        const auto ext = off + hs; const auto tag = str(u32(ext + 4), ext + 4);
        if (element_stack_.empty() || element_stack_.back() != tag) fail(off, "binary Android XML element nesting mismatch at " + tag);
        element_stack_.pop_back();
        if (element_stack_.empty()) root_closed_ = true;
    }
    void parse() {
        const auto root_hs = u16(2);
        const auto root_size = u32(4);
        if (root_hs != 8 || root_size != d_.size()) fail(0, "invalid binary Android XML root chunk geometry");
        std::uint64_t p = root_hs;
        while (p < d_.size()) {
            need(p, 8, "chunk header"); const auto type = u16(p), hs = u16(p + 2); const auto size = u32(p + 4);
            if (hs < 8 || size < hs || size > d_.size() - p) fail(p, "invalid binary Android XML child chunk geometry");
            switch (type) {
                case 0x0001: parse_string_pool(p, hs, size); break;
                case 0x0180: {
                    if (!string_pool_seen_) fail(p, "binary Android XML resource map appears before string pool");
                    if (hs != 8 || (size - hs) % 4 != 0) fail(p, "invalid binary Android XML resource-map geometry");
                    if (resource_map_seen_) fail(p, "duplicate binary Android XML resource map");
                    resource_map_seen_ = true;
                    for (std::uint64_t q = p + hs; q < p + size; q += 4) resource_ids_.push_back(u32(q));
                    out_.resource_id_count = static_cast<std::uint32_t>(resource_ids_.size());
                    break;
                }
                case 0x0100: case 0x0101: // namespace
                    if (hs < 16 || size < std::uint32_t(hs) + 8u) fail(p, "invalid binary Android XML namespace chunk");
                    (void)str(u32(p + hs), p + hs, true); (void)str(u32(p + hs + 4), p + hs + 4, true); break;
                case 0x0102: parse_start_element(p, hs, size); break;
                case 0x0103: parse_end_element(p, hs, size); break;
                case 0x0104: // CDATA: validate string index and typed value geometry.
                    if (hs < 16 || size < std::uint32_t(hs) + 12u) fail(p, "invalid binary Android XML CDATA chunk");
                    (void)str(u32(p + hs), p + hs); if (u16(p + hs + 4) != 8 || d_[p + hs + 6] != 0) fail(p + hs + 4, "invalid binary Android XML CDATA typed value"); break;
                default: fail(p, "unsupported binary Android XML chunk type");
            }
            p += size;
        }
        if (!string_pool_seen_ || !root_seen_ || !root_closed_ || !element_stack_.empty()) fail(p, "incomplete binary Android XML document");
        if (out_.package_name.empty()) out_.anomalies.push_back("manifest package name was not recovered");
        std::sort(out_.permissions.begin(), out_.permissions.end());
        out_.permissions.erase(std::unique(out_.permissions.begin(), out_.permissions.end()), out_.permissions.end());
    }
};

ApkManifestInfo parse_binary_manifest(std::span<const std::uint8_t> data) {
    return AxmlParser(data).run();
}

std::vector<std::uint8_t> entry_full_bounded(mz_zip_archive& zip, const ApkEntryInfo& e,
                                             std::uint64_t max_bytes, std::span<const std::uint8_t> data) {
    if (e.uncompressed_size > max_bytes || e.uncompressed_size > std::numeric_limits<std::size_t>::max() ||
        e.directory || e.encrypted || !e.supported) return {};
    std::vector<std::uint8_t> out(static_cast<std::size_t>(e.uncompressed_size));
    if (e.uncompressed_size == 0) return out;
    if (e.method == 0) {
        if (e.data_offset > data.size() || e.uncompressed_size > data.size() - e.data_offset) return {};
        std::copy_n(data.begin() + e.data_offset, out.size(), out.begin());
        // Stored entries are still CRC-validated below through miniz to avoid accepting changed evidence bytes.
    }
    if (!mz_zip_reader_extract_to_mem(&zip, e.index, out.data(), out.size(), 0)) return {};
    return out;
}

struct ResourceScalar {
    std::uint8_t type = 0;
    std::uint32_t data = 0;
    std::string value;
    std::string package_name;
    std::string type_name;
    std::string key_name;
};

struct ResourceTableParse {
    ApkResourceTableInfo info;
    std::unordered_map<std::uint32_t, ResourceScalar> defaults;
};

struct ArscError { std::string message; std::uint64_t offset = 0; };

class ArscParser {
public:
    explicit ArscParser(std::span<const std::uint8_t> data) : d_(data) {}

    ResourceTableParse run() {
        if (d_.size() < 12 || le16(d_, 0) != 0x0002) return result_;
        result_.info.candidate = true;
        try {
            parse();
            result_.info.valid = true;
            result_.info.parse_complete = true;
        } catch (const ArscError& e) {
            result_.info.error = e.message;
            result_.info.error_offset = e.offset;
        }
        return std::move(result_);
    }

private:
    std::span<const std::uint8_t> d_;
    ResourceTableParse result_;
    std::vector<std::string> global_strings_;

    [[noreturn]] void fail(std::uint64_t off, std::string msg) const {
        throw ArscError{std::move(msg), off};
    }

    void need(std::uint64_t off, std::uint64_t n, std::string_view what) const {
        if (off > d_.size() || n > d_.size() - off) {
            fail(off, "truncated Android resource table " + std::string(what));
        }
    }

    std::uint16_t u16(std::uint64_t off) const {
        need(off, 2, "uint16");
        return le16(d_, off);
    }

    std::uint32_t u32(std::uint64_t off) const {
        need(off, 4, "uint32");
        return le32(d_, off);
    }

    static bool len8(std::span<const std::uint8_t> data, std::uint64_t& p,
                     std::uint64_t end, std::uint32_t& out) {
        if (p >= end) return false;
        const auto x = data[p++];
        if ((x & 0x80u) == 0) {
            out = x;
            return true;
        }
        if (p >= end) return false;
        out = (std::uint32_t(x & 0x7fu) << 8) | data[p++];
        return true;
    }

    static bool len16(std::span<const std::uint8_t> data, std::uint64_t& p,
                      std::uint64_t end, std::uint32_t& out) {
        if (p + 2 > end) return false;
        const auto x = std::uint16_t(data[p]) | (std::uint16_t(data[p + 1]) << 8);
        p += 2;
        if ((x & 0x8000u) == 0) {
            out = x;
            return true;
        }
        if (p + 2 > end) return false;
        const auto y = std::uint16_t(data[p]) | (std::uint16_t(data[p + 1]) << 8);
        p += 2;
        out = (std::uint32_t(x & 0x7fffu) << 16) | y;
        return true;
    }

    std::vector<std::string> pool(std::uint64_t off, std::uint64_t limit,
                                  std::string_view label) {
        if (off + 8 > limit || u16(off) != 0x0001) {
            fail(off, std::string(label) + " does not point to ResStringPool");
        }
        const std::uint16_t header_size = u16(off + 2);
        const std::uint32_t size = u32(off + 4);
        if (header_size < 28 || size < header_size || size > limit - off) {
            fail(off, "invalid " + std::string(label) + " string pool geometry");
        }
        const std::uint32_t count = u32(off + 8);
        const std::uint32_t styles = u32(off + 12);
        const std::uint32_t flags = u32(off + 16);
        const std::uint32_t strings_start = u32(off + 20);
        const std::uint32_t styles_start = u32(off + 24);
        if (count > 1000000 || styles > 1000000) {
            fail(off + 8, "unreasonable " + std::string(label) + " string/style count");
        }
        const auto index_bytes = std::uint64_t(count + styles) * 4;
        if (index_bytes > size - header_size) {
            fail(off + header_size, "string pool index arrays exceed chunk");
        }
        if (count == 0 && styles == 0) {
            if (strings_start != 0 && strings_start < std::uint64_t(header_size) + index_bytes) {
                fail(off + 20, "invalid empty string pool stringsStart");
            }
            return {};
        }
        if (strings_start < std::uint64_t(header_size) + index_bytes || strings_start >= size) {
            fail(off + 20, "invalid string pool stringsStart");
        }
        if (styles_start != 0 && (styles_start < strings_start || styles_start >= size)) {
            fail(off + 24, "invalid string pool stylesStart");
        }
        const auto string_end = styles_start ? off + styles_start : off + size;
        const bool utf8 = (flags & 0x100u) != 0;
        std::vector<std::string> out;
        out.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto ref_off = off + header_size + std::uint64_t(i) * 4;
            const auto rel = u32(ref_off);
            if (rel >= size - strings_start) fail(ref_off, "string offset exceeds pool");
            std::uint64_t p = off + strings_start + rel;
            if (p >= string_end) fail(p, "string starts past string pool");
            if (utf8) {
                std::uint32_t utf16_units = 0, bytes = 0;
                if (!len8(d_, p, string_end, utf16_units) || !len8(d_, p, string_end, bytes) ||
                    bytes > string_end - p || p + bytes >= string_end) {
                    fail(p, "invalid UTF-8 resource string geometry");
                }
                std::string text(reinterpret_cast<const char*>(d_.data() + p), bytes);
                if (!valid_utf8(text) || d_[p + bytes] != 0) {
                    fail(p, "invalid UTF-8 resource string");
                }
                out.push_back(std::move(text));
            } else {
                std::uint32_t units = 0;
                if (!len16(d_, p, string_end, units)) fail(p, "invalid UTF-16 resource string length");
                const auto bytes = std::uint64_t(units) * 2;
                if (bytes > string_end - p || p + bytes + 2 > string_end || u16(p + bytes) != 0) {
                    fail(p, "invalid UTF-16 resource string geometry");
                }
                bool ok = false;
                auto text = utf16le_to_utf8(d_.subspan(p, bytes), units, ok);
                if (!ok) fail(p, "invalid UTF-16 resource string");
                out.push_back(std::move(text));
            }
        }
        return out;
    }

    std::string package_name(std::uint64_t off) {
        need(off, 256, "package name");
        std::uint32_t units = 0;
        while (units < 128 && u16(off + std::uint64_t(units) * 2) != 0) ++units;
        if (units == 128) fail(off, "unterminated Android resource package name");
        bool ok = false;
        auto text = utf16le_to_utf8(d_.subspan(off, std::uint64_t(units) * 2), units, ok);
        if (!ok || text.empty()) fail(off, "invalid Android resource package name");
        return text;
    }

    bool default_config(std::uint64_t off, std::uint32_t size) const {
        if (size < 4) return false;
        for (std::uint32_t i = 4; i < size; ++i) {
            if (d_[off + i] != 0) return false;
        }
        return true;
    }

    void validate_value(std::uint64_t off, std::uint64_t end, std::uint8_t& type,
                        std::uint32_t& data) {
        if (off + 8 > end) fail(off, "resource value exceeds type chunk");
        if (u16(off) != 8 || d_[off + 2] != 0) fail(off, "invalid resource Res_value header");
        type = d_[off + 3];
        data = u32(off + 4);
        if (type == 0x03 && data >= global_strings_.size()) {
            fail(off + 4, "resource string value index out of range");
        }
    }

    ResourceScalar scalar(std::uint8_t type, std::uint32_t data, const std::string& package,
                          const std::string& type_name, const std::string& key) {
        ResourceScalar x;
        x.type = type;
        x.data = data;
        x.package_name = package;
        x.type_name = type_name;
        x.key_name = key;
        if (type == 0x03) x.value = global_strings_[data];
        else if (type == 0x12) x.value = data ? "true" : "false";
        else if (type == 0x10) x.value = std::to_string(data);
        else if (type == 0x11) {
            constexpr char hex[] = "0123456789abcdef";
            x.value = "0x";
            bool started = false;
            for (int n = 7; n >= 0; --n) {
                const auto q = (data >> (n * 4)) & 0xfu;
                if (q || started || n == 0) { x.value.push_back(hex[q]); started = true; }
            }
        } else if (type == 0x01 || type == 0x07) {
            constexpr char hex[] = "0123456789abcdef";
            x.value = "@0x";
            for (int n = 7; n >= 0; --n) x.value.push_back(hex[(data >> (n * 4)) & 0xfu]);
        }
        return x;
    }

    void parse_entry(std::uint64_t entry, std::uint64_t chunk_end, std::uint32_t resid,
                     const std::string& package, const std::string& type_name,
                     const std::vector<std::string>& keys, bool store_default) {
        if (entry + 8 > chunk_end) fail(entry, "resource entry header exceeds type chunk");
        const std::uint16_t first = u16(entry);
        const std::uint16_t flags = u16(entry + 2);
        std::uint32_t key_index = 0;
        std::uint8_t data_type = 0;
        std::uint32_t data = 0;
        if (flags & 0x0008u) {
            if (flags & 0x0001u) fail(entry + 2, "compact resource entry is also marked complex");
            key_index = first;
            data_type = std::uint8_t(flags >> 8);
            data = u32(entry + 4);
            if (data_type == 0x03 && data >= global_strings_.size()) {
                fail(entry + 4, "compact resource string index out of range");
            }
        } else {
            const std::uint16_t entry_size = first;
            if (entry_size < 8 || entry + entry_size > chunk_end) fail(entry, "invalid resource entry size");
            key_index = u32(entry + 4);
            if (flags & 0x0001u) {
                if (entry_size < 16) fail(entry, "complex resource entry header too small");
                const auto count = u32(entry + 12);
                if (count > 1000000 || std::uint64_t(count) * 12 > chunk_end - (entry + entry_size)) {
                    fail(entry + 12, "complex resource map exceeds type chunk");
                }
                for (std::uint32_t i = 0; i < count; ++i) {
                    const auto map = entry + entry_size + std::uint64_t(i) * 12;
                    (void)u32(map); // map name resource id
                    std::uint8_t map_type = 0; std::uint32_t map_data = 0;
                    validate_value(map + 4, chunk_end, map_type, map_data);
                }
                ++result_.info.complex_entry_count;
                return;
            }
            validate_value(entry + entry_size, chunk_end, data_type, data);
        }
        if (key_index >= keys.size()) fail(entry + 4, "resource key index out of range");
        if (!store_default) return;
        auto value = scalar(data_type, data, package, type_name, keys[key_index]);
        if (!result_.defaults.emplace(resid, std::move(value)).second) {
            fail(entry, "duplicate default resource value");
        }
        ++result_.info.default_scalar_count;
    }

    void parse_type(std::uint64_t off, std::uint32_t size, const std::string& package,
                    std::uint32_t package_id, std::uint32_t type_offset,
                    const std::vector<std::string>& types, const std::vector<std::string>& keys,
                    const std::map<std::uint8_t,std::uint32_t>& spec_counts) {
        const std::uint16_t header_size = u16(off + 2);
        if (header_size < 24 || size < header_size) fail(off, "invalid ResTable_type header");
        const auto id = d_[off + 8];
        const auto flags = d_[off + 9];
        if (id == 0 || (flags & ~0x03u) != 0 || u16(off + 10) != 0) {
            fail(off + 8, "invalid ResTable_type id/flags/reserved");
        }
        const auto count = u32(off + 12);
        const auto entries_start = u32(off + 16);
        const auto config_size = u32(off + 20);
        if (config_size < 4 || 20u + config_size > header_size) fail(off + 20, "invalid ResTable_config size");
        if (count > 1000000) fail(off + 12, "unreasonable resource type entryCount");
        const auto effective_type = std::uint32_t(id) + type_offset;
        if (effective_type == 0 || effective_type > 255) fail(off + 8, "resource effective type id out of range");
        if (id > types.size()) fail(off + 8, "resource type id exceeds typeStrings");
        const auto spec = spec_counts.find(id);
        if (spec == spec_counts.end()) fail(off + 8, "ResTable_type has no matching typeSpec");
        if ((flags & 0x01u) == 0 && count != spec->second) {
            fail(off + 12, "ResTable_type entryCount differs from typeSpec");
        }
        if ((flags & 0x01u) != 0 && count > spec->second) {
            fail(off + 12, "sparse ResTable_type entryCount exceeds typeSpec");
        }
        ++result_.info.type_config_count;
        const bool is_default = default_config(off + 20, config_size);
        if (!is_default) ++result_.info.nondefault_config_count;
        std::uint64_t index_bytes = 0;
        if (flags & 0x01u) index_bytes = std::uint64_t(count) * 4;
        else if (flags & 0x02u) index_bytes = std::uint64_t(count) * 2;
        else index_bytes = std::uint64_t(count) * 4;
        if (index_bytes > size - header_size || entries_start < std::uint64_t(header_size) + index_bytes || entries_start > size) {
            fail(off + header_size, "resource type index/entriesStart geometry invalid");
        }
        const auto chunk_end = off + size;
        const auto& type_name = types[id - 1];
        if (flags & 0x01u) {
            std::uint16_t previous = 0; bool have_previous = false;
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto pos = off + header_size + std::uint64_t(i) * 4;
                const auto entry_index = u16(pos);
                const auto offset16 = u16(pos + 2);
                if (have_previous && entry_index <= previous) fail(pos, "sparse resource indices are unsorted/duplicate");
                if (entry_index >= spec->second) fail(pos, "sparse resource entry index exceeds typeSpec");
                if (offset16 == 0xffffu) fail(pos + 2, "sparse resource entry uses NO_ENTRY offset");
                previous = entry_index; have_previous = true;
                const auto entry_offset = std::uint32_t(offset16) * 4u;
                if (entry_offset > size - entries_start) fail(pos + 2, "sparse resource offset exceeds chunk");
                const auto resid = (package_id << 24) | (effective_type << 16) | entry_index;
                parse_entry(off + entries_start + entry_offset, chunk_end, resid, package, type_name, keys, is_default);
            }
        } else {
            for (std::uint32_t entry_index = 0; entry_index < count; ++entry_index) {
                const auto pos = off + header_size + (flags & 0x02u ? std::uint64_t(entry_index) * 2 : std::uint64_t(entry_index) * 4);
                std::uint32_t entry_offset = 0xffffffffu;
                if (flags & 0x02u) {
                    const auto x = u16(pos);
                    if (x != 0xffffu) entry_offset = std::uint32_t(x) * 4u;
                } else entry_offset = u32(pos);
                if (entry_offset == 0xffffffffu) continue;
                if (entry_offset > size - entries_start) fail(pos, "resource entry offset exceeds chunk");
                const auto resid = (package_id << 24) | (effective_type << 16) | entry_index;
                parse_entry(off + entries_start + entry_offset, chunk_end, resid, package, type_name, keys, is_default);
            }
        }
    }

    void parse_package(std::uint64_t off, std::uint16_t header_size, std::uint32_t size) {
        if (header_size < 284 || size < header_size) fail(off, "invalid ResTable_package header");
        const auto package_id = u32(off + 8);
        if (package_id == 0 || package_id > 255) fail(off + 8, "invalid resource package id");
        const auto name = package_name(off + 12);
        const auto type_strings_off = u32(off + 268);
        const auto key_strings_off = u32(off + 276);
        const auto type_id_offset = header_size >= 288 ? u32(off + 284) : 0;
        if (type_strings_off < header_size || key_strings_off < header_size ||
            type_strings_off >= size || key_strings_off >= size) {
            fail(off + 268, "invalid resource package string-pool offsets");
        }
        const auto types = pool(off + type_strings_off, off + size, "typeStrings");
        const auto keys = pool(off + key_strings_off, off + size, "keyStrings");
        result_.info.package_names.push_back(name);
        ++result_.info.parsed_package_count;

        std::map<std::uint8_t,std::uint32_t> specs;
        std::uint64_t p = off + header_size;
        while (p < off + size) {
            if (p + 8 > off + size) fail(p, "truncated resource package child chunk");
            const std::uint16_t type = u16(p);
            const std::uint16_t hs = u16(p + 2);
            const std::uint32_t child_size = u32(p + 4);
            if (hs < 8 || child_size < hs || child_size > off + size - p) {
                fail(p, "invalid resource package child chunk geometry");
            }
            if (type == 0x0202) {
                if (hs != 16 || child_size < 16) fail(p, "invalid ResTable_typeSpec header");
                const auto id = d_[p + 8];
                if (id == 0 || d_[p + 9] != 0 || u16(p + 10) != 0 || id > types.size()) {
                    fail(p + 8, "invalid ResTable_typeSpec id/reserved");
                }
                const auto entry_count = u32(p + 12);
                if (entry_count > 65536 || std::uint64_t(entry_count) * 4 != child_size - 16) {
                    fail(p + 12, "ResTable_typeSpec entryCount/size mismatch");
                }
                if (!specs.emplace(id, entry_count).second) fail(p + 8, "duplicate ResTable_typeSpec id");
                ++result_.info.type_spec_count;
            }
            p += child_size;
        }

        p = off + header_size;
        while (p < off + size) {
            const std::uint16_t type = u16(p);
            const std::uint32_t child_size = u32(p + 4);
            if (type == 0x0201) {
                parse_type(p, child_size, name, package_id, type_id_offset, types, keys, specs);
            } else if (type != 0x0001 && type != 0x0202) {
                constexpr char hex[] = "0123456789abcdef";
                std::string x = "uninterpreted resource package chunk type 0x";
                for (int n = 3; n >= 0; --n) x.push_back(hex[(type >> (n * 4)) & 0xfu]);
                result_.info.anomalies.push_back(std::move(x));
            }
            p += child_size;
        }
    }

    void parse() {
        if (u16(2) != 12 || u32(4) != d_.size()) fail(0, "invalid Android resource-table root geometry");
        result_.info.declared_package_count = u32(8);
        if (result_.info.declared_package_count == 0 || result_.info.declared_package_count > 255) {
            fail(8, "invalid Android resource-table packageCount");
        }
        std::uint64_t p = 12;
        bool global_seen = false;
        while (p < d_.size()) {
            need(p, 8, "child chunk");
            const std::uint16_t type = u16(p);
            const std::uint16_t header_size = u16(p + 2);
            const std::uint32_t size = u32(p + 4);
            if (header_size < 8 || size < header_size || size > d_.size() - p) {
                fail(p, "invalid Android resource-table child geometry");
            }
            if (type == 0x0001) {
                if (global_seen) fail(p, "duplicate global resource string pool");
                global_strings_ = pool(p, d_.size(), "global");
                global_seen = true;
            } else if (type == 0x0200) {
                if (!global_seen) fail(p, "resource package appears before global string pool");
                parse_package(p, header_size, size);
            } else {
                fail(p, "unsupported top-level Android resource-table chunk");
            }
            p += size;
        }
        if (!global_seen || result_.info.parsed_package_count != result_.info.declared_package_count) {
            fail(p, "resource-table package count mismatch");
        }
    }
};
ResourceTableParse parse_resource_table(std::span<const std::uint8_t> data) { return ArscParser(data).run(); }

const ResourceScalar* resolve_default_resource(const ResourceTableParse& table,std::uint32_t id,std::uint32_t& final_id) {
    std::set<std::uint32_t> seen;final_id=id;for(unsigned depth=0;depth<32;++depth){if(!seen.insert(final_id).second)return nullptr;const auto it=table.defaults.find(final_id);if(it==table.defaults.end())return nullptr;if(it->second.type==0x01||it->second.type==0x07){final_id=it->second.data;continue;}return &it->second;}return nullptr;
}

void resolve_manifest_resources(ApkManifestInfo& manifest,const ResourceTableParse& table) {
    if(!table.info.valid)return;
    if(manifest.debuggable_reference){std::uint32_t rid=0;if(const auto* x=resolve_default_resource(table,manifest.debuggable_reference_id,rid);x&&x->type==0x12){manifest.debuggable_known=true;manifest.debuggable=x->data!=0;manifest.debuggable_reference_resolved=true;}}
}

bool binary_xml_header(std::span<const std::uint8_t> p, std::uint64_t size) {
    if (p.size() < 8 || size < 8) return false;
    const auto type = le16(p, 0), header_size = le16(p, 2);
    const auto chunk_size = le32(p, 4);
    return type == 0x0003 && header_size == 8 && chunk_size == size && chunk_size >= header_size;
}

bool resources_table_header(std::span<const std::uint8_t> p, std::uint64_t size) {
    if (p.size() < 12 || size < 12) return false;
    const auto type = le16(p, 0), header_size = le16(p, 2);
    const auto chunk_size = le32(p, 4), packages = le32(p, 8);
    return type == 0x0002 && header_size >= 12 && chunk_size == size && chunk_size >= header_size && packages != 0;
}

bool dex_header(std::span<const std::uint8_t> p, std::uint64_t physical_size) {
    if (p.size() < 0x70 || physical_size < 0x70 || physical_size > 0xffffffffull ||
        p[0] != 'd' || p[1] != 'e' || p[2] != 'x' || p[3] != '\n' || p[7] != 0) return false;
    const std::string version(reinterpret_cast<const char*>(p.data() + 4), 3);
    static const std::set<std::string> versions = {"035","037","038","039","040","041"};
    if (!versions.contains(version)) return false;
    const auto endian_raw = le32(p, 0x28);
    bool reverse = false;
    if (endian_raw == 0x12345678u) reverse = false;
    else if (endian_raw == 0x78563412u) reverse = true;
    else return false;
    const auto rd32 = [&](std::size_t off) -> std::uint32_t {
        auto x = le32(p, off);
        if (!reverse) return x;
        return ((x & 0x000000ffu) << 24) | ((x & 0x0000ff00u) << 8) |
               ((x & 0x00ff0000u) >> 8) | ((x & 0xff000000u) >> 24);
    };
    const bool v41 = version == "041";
    const auto expected_header = v41 ? 0x78u : 0x70u;
    if (p.size() < expected_header || rd32(0x24) != expected_header) return false;
    const auto file_size = rd32(0x20);
    if (file_size < expected_header || file_size > physical_size) return false;
    if (!v41 && file_size != physical_size) return false;
    if (v41) {
        if (rd32(0x70) != physical_size || rd32(0x74) != 0) return false;
    }
    const auto map_off = rd32(0x34);
    if (map_off == 0 || (map_off & 3u) != 0 || map_off >= physical_size) return false;
    struct Table { std::size_t size_off, off_off; std::uint32_t item_size; };
    constexpr std::array<Table, 6> tables = {{{0x38,0x3c,4},{0x40,0x44,4},{0x48,0x4c,12},
                                               {0x50,0x54,8},{0x58,0x5c,8},{0x60,0x64,32}}};
    for (const auto& t : tables) {
        const auto count = rd32(t.size_off), off = rd32(t.off_off);
        if (count == 0) { if (off != 0) return false; continue; }
        if (off == 0 || (off & 3u) != 0) return false;
        const auto bytes = std::uint64_t(count) * t.item_size;
        if (off > physical_size || bytes > physical_size - off) return false;
    }
    if (!v41) {
        const auto data_size = rd32(0x68), data_off = rd32(0x6c);
        if (data_size == 0) {
            if (data_off != 0) return false;
        } else {
            if ((data_size & 3u) != 0 || (data_off & 3u) != 0 || data_off > physical_size ||
                std::uint64_t(data_size) > physical_size - data_off || std::uint64_t(data_off) + data_size != physical_size) return false;
        }
    }
    return true;
}

bool elf_header(std::span<const std::uint8_t> p) {
    if (p.size() < 20 || p[0] != 0x7f || p[1] != 'E' || p[2] != 'L' || p[3] != 'F') return false;
    const auto elf_class = p[4], endian = p[5], ident_version = p[6];
    if ((elf_class != 1 && elf_class != 2) || (endian != 1 && endian != 2) || ident_version != 1) return false;
    const auto rd16 = [&](std::size_t off) -> std::uint16_t {
        if (off + 2 > p.size()) return 0;
        if (endian == 1) return std::uint16_t(p[off]) | (std::uint16_t(p[off + 1]) << 8);
        return (std::uint16_t(p[off]) << 8) | std::uint16_t(p[off + 1]);
    };
    const auto rd32 = [&](std::size_t off) -> std::uint32_t {
        if (off + 4 > p.size()) return 0;
        if (endian == 1) return std::uint32_t(p[off]) | (std::uint32_t(p[off + 1]) << 8) |
                                (std::uint32_t(p[off + 2]) << 16) | (std::uint32_t(p[off + 3]) << 24);
        return (std::uint32_t(p[off]) << 24) | (std::uint32_t(p[off + 1]) << 16) |
               (std::uint32_t(p[off + 2]) << 8) | std::uint32_t(p[off + 3]);
    };
    if (rd16(16) == 0 || rd16(18) == 0 || rd32(20) != 1) return false;
    if (elf_class == 1) return p.size() >= 52 && rd16(40) == 52;
    return p.size() >= 64 && rd16(52) == 64;
}

std::optional<bool> apk_abi_matches_elf(std::string_view abi, const ElfInfo& elf) {
    if (abi == "x86_64") return elf.elf64 && elf.machine == 62;
    if (abi == "arm64-v8a") return elf.elf64 && elf.machine == 183;
    if (abi == "riscv64") return elf.elf64 && elf.machine == 243;
    if (abi == "x86") return !elf.elf64 && elf.machine == 3;
    if (abi == "armeabi" || abi == "armeabi-v7a") return !elf.elf64 && elf.machine == 40;
    if (abi == "mips") return !elf.elf64 && elf.machine == 8;
    if (abi == "mips64") return elf.elf64 && elf.machine == 8;
    return std::nullopt;
}

bool archive_magic(std::span<const std::uint8_t> data) {
    if (data.size() < 4) return false;
    const auto sig = le32(data, 0);
    return sig == 0x04034b50u || sig == 0x06054b50u || sig == 0x08074b50u;
}

void push_interesting(ApkInfo& out, const std::string& name) {
    if (out.interesting_entries.size() < 512) out.interesting_entries.push_back(name);
}

void push_anomaly(ApkInfo& out, std::string message) {
    constexpr std::size_t kMaxSamples = 128;
    if (out.anomalies.size() < kMaxSamples) out.anomalies.push_back(std::move(message));
    else out.anomaly_samples_truncated = true;
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

struct DexDeclarationEvidence {
    std::string entry;
    DexMethodInfo method;
};

struct DexLoadEvidence {
    std::string entry;
    DexLibraryLoadInfo load;
};

struct NativeExportEvidence {
    std::string entry;
    std::string abi;
    ElfDynamicSymbol symbol;
    bool abi_consistent = false;
    bool fde_exact = false;
    std::uint64_t fde_end_va = 0;
};

struct NativeRegistrationEvidence {
    std::string entry;
    std::string abi;
    std::string class_descriptor;
    std::string method_name;
    std::string method_descriptor;
    std::uint64_t function_va = 0;
    std::uint64_t function_file_offset = 0;
    std::uint64_t function_end_va = 0;
    bool fde_exact = false;
};

struct NativeRegistrationScan {
    std::vector<NativeRegistrationEvidence> evidence;
    bool limited = false;
    std::string error;
};

struct JniDecoded {
    std::uint64_t va = 0;
    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
};

ZydisRegister jni_reg64(ZydisRegister reg) {
    return reg == ZYDIS_REGISTER_NONE ? reg : ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, reg);
}

std::optional<std::uint64_t> jni_add_signed(std::uint64_t base, std::int64_t delta) {
    if (delta >= 0) {
        const auto add = static_cast<std::uint64_t>(delta);
        if (base > std::numeric_limits<std::uint64_t>::max() - add) return std::nullopt;
        return base + add;
    }
    const auto sub = static_cast<std::uint64_t>(-(delta + 1)) + 1;
    if (base < sub) return std::nullopt;
    return base - sub;
}

std::optional<std::pair<std::size_t, std::size_t>> jni_va_extent(
    std::span<const std::uint8_t> data, const ElfInfo& elf, std::uint64_t va) {
    for (const auto& segment : elf.segments) {
        if (segment.type != 1 || va < segment.address) continue;
        const auto delta = va - segment.address;
        if (delta >= segment.file_size || segment.offset > data.size() || delta > data.size() - segment.offset) continue;
        const auto offset = segment.offset + delta;
        if (offset >= data.size()) continue;
        const auto available = std::min<std::uint64_t>(segment.file_size - delta, data.size() - offset);
        return std::pair<std::size_t, std::size_t>{static_cast<std::size_t>(offset), static_cast<std::size_t>(available)};
    }
    return std::nullopt;
}

std::vector<JniDecoded> jni_decode_fde(std::span<const std::uint8_t> data, const ElfInfo& elf,
                                      const ElfUnwindFde& fde, bool& limited) {
    std::vector<JniDecoded> out;
    if (!fde.function_file_backed || !fde.function_size) return out;
    if (fde.function_size > (1u << 20)) {
        limited = true;
        return out;
    }
    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) return out;
    auto va = fde.function_start_va;
    while (va < fde.function_end_va) {
        if (out.size() >= 8192) {
            limited = true;
            return {};
        }
        const auto extent = jni_va_extent(data, elf, va);
        if (!extent) return {};
        JniDecoded decoded;
        decoded.va = va;
        const auto size = std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH, extent->second);
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data.data() + extent->first, size,
                                                 &decoded.instruction, decoded.operands.data())) ||
            !decoded.instruction.length || decoded.instruction.length > fde.function_end_va - va) return {};
        va += decoded.instruction.length;
        out.push_back(decoded);
    }
    return out;
}

struct JniFlow {
    bool complete = false;
    std::vector<std::vector<std::size_t>> edges;
    std::vector<bool> reachable;
};

JniFlow jni_build_flow(const std::vector<JniDecoded>& instructions) {
    JniFlow flow;
    if (instructions.empty()) return flow;
    flow.edges.resize(instructions.size());
    std::unordered_map<std::uint64_t, std::size_t> by_va;
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        if (!by_va.emplace(instructions[i].va, i).second) return flow;
    }
    auto add_fallthrough = [&](std::size_t from) {
        if (from + 1 >= instructions.size() ||
            instructions[from].va + instructions[from].instruction.length != instructions[from + 1].va) return false;
        flow.edges[from].push_back(from + 1);
        return true;
    };
    auto add_direct_target = [&](std::size_t from) {
        const auto& decoded = instructions[from];
        if (!decoded.instruction.operand_count_visible ||
            decoded.operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !decoded.operands[0].imm.is_relative) return false;
        ZyanU64 target = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&decoded.instruction, &decoded.operands[0], decoded.va, &target))) return false;
        const auto it = by_va.find(target);
        if (it == by_va.end()) return false;
        flow.edges[from].push_back(it->second);
        return true;
    };
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        const auto category = instructions[i].instruction.meta.category;
        if (category == ZYDIS_CATEGORY_RET) continue;
        if (category == ZYDIS_CATEGORY_UNCOND_BR) {
            if (instructions[i].instruction.operand_count_visible &&
                instructions[i].operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                instructions[i].operands[0].imm.is_relative && !add_direct_target(i)) return flow;
            continue;
        }
        if (category == ZYDIS_CATEGORY_COND_BR) {
            if (!add_direct_target(i) || !add_fallthrough(i)) return flow;
            continue;
        }
        if (i + 1 < instructions.size()) {
            if (!add_fallthrough(i)) return flow;
        } else if (category != ZYDIS_CATEGORY_CALL) {
            return flow;
        }
    }
    for (auto& edges : flow.edges) {
        std::sort(edges.begin(), edges.end());
        edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
    }
    flow.reachable.assign(instructions.size(), false);
    std::deque<std::size_t> pending;
    flow.reachable[0] = true;
    pending.push_back(0);
    while (!pending.empty()) {
        const auto at = pending.front();
        pending.pop_front();
        for (const auto to : flow.edges[at]) if (!flow.reachable[to]) {
            flow.reachable[to] = true;
            pending.push_back(to);
        }
    }
    flow.complete = true;
    return flow;
}

bool jni_dominates(const JniFlow& flow, std::size_t blocker, std::size_t target) {
    if (!flow.complete || blocker >= flow.edges.size() || target >= flow.edges.size() ||
        !flow.reachable[blocker] || !flow.reachable[target]) return false;
    if (blocker == 0 || blocker == target) return true;
    std::vector<bool> visited(flow.edges.size(), false);
    std::deque<std::size_t> pending;
    visited[0] = true;
    pending.push_back(0);
    while (!pending.empty()) {
        const auto at = pending.front();
        pending.pop_front();
        for (const auto to : flow.edges[at]) {
            if (to == blocker || visited[to]) continue;
            visited[to] = true;
            pending.push_back(to);
        }
    }
    return !visited[target];
}

bool jni_writes_register(const JniDecoded& decoded, ZydisRegister wanted) {
    wanted = jni_reg64(wanted);
    for (std::uint8_t i = 0; i < decoded.instruction.operand_count_visible; ++i) {
        const auto& operand = decoded.operands[i];
        if (operand.type == ZYDIS_OPERAND_TYPE_REGISTER && jni_reg64(operand.reg.value) == wanted &&
            (operand.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0) return true;
    }
    return false;
}

std::optional<std::size_t> jni_last_writer(const std::vector<JniDecoded>& instructions,
                                           std::size_t before, ZydisRegister wanted) {
    for (std::size_t i = before; i-- > 0;) if (jni_writes_register(instructions[i], wanted)) return i;
    return std::nullopt;
}

std::optional<std::uint64_t> jni_rip_literal(const JniDecoded& decoded, ZydisRegister target) {
    if (decoded.instruction.mnemonic != ZYDIS_MNEMONIC_LEA || decoded.instruction.operand_count_visible < 2 ||
        decoded.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        jni_reg64(decoded.operands[0].reg.value) != jni_reg64(target)) return std::nullopt;
    const auto& memory = decoded.operands[1];
    if (memory.type != ZYDIS_OPERAND_TYPE_MEMORY || jni_reg64(memory.mem.base) != ZYDIS_REGISTER_RIP ||
        memory.mem.index != ZYDIS_REGISTER_NONE) return std::nullopt;
    return jni_add_signed(decoded.va + decoded.instruction.length,
                          memory.mem.disp.has_displacement ? memory.mem.disp.value : 0);
}

std::optional<std::uint64_t> jni_immediate(const JniDecoded& decoded, ZydisRegister target) {
    if (decoded.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || decoded.instruction.operand_count_visible < 2 ||
        decoded.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        jni_reg64(decoded.operands[0].reg.value) != jni_reg64(target) ||
        decoded.operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || decoded.operands[1].imm.is_relative) return std::nullopt;
    return decoded.operands[1].imm.value.u;
}

bool jni_register_move(const JniDecoded& decoded, ZydisRegister target, ZydisRegister source) {
    return decoded.instruction.mnemonic == ZYDIS_MNEMONIC_MOV && decoded.instruction.operand_count_visible >= 2 &&
           decoded.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           decoded.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
           jni_reg64(decoded.operands[0].reg.value) == jni_reg64(target) &&
           jni_reg64(decoded.operands[1].reg.value) == jni_reg64(source);
}

std::optional<ZydisRegister> jni_indirect_table_call_base(const JniDecoded& decoded, std::int64_t displacement) {
    if (decoded.instruction.meta.category != ZYDIS_CATEGORY_CALL || !decoded.instruction.operand_count_visible) return std::nullopt;
    const auto& operand = decoded.operands[0];
    if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY || operand.mem.index != ZYDIS_REGISTER_NONE ||
        !operand.mem.disp.has_displacement || operand.mem.disp.value != displacement ||
        operand.mem.base == ZYDIS_REGISTER_NONE || operand.mem.base == ZYDIS_REGISTER_RIP) return std::nullopt;
    return jni_reg64(operand.mem.base);
}

bool jni_interface_table_load(const JniDecoded& decoded, ZydisRegister target) {
    if (decoded.instruction.mnemonic != ZYDIS_MNEMONIC_MOV || decoded.instruction.operand_count_visible < 2 ||
        decoded.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        jni_reg64(decoded.operands[0].reg.value) != jni_reg64(target)) return false;
    const auto& source = decoded.operands[1];
    return source.type == ZYDIS_OPERAND_TYPE_MEMORY && jni_reg64(source.mem.base) == ZYDIS_REGISTER_RDI &&
           source.mem.index == ZYDIS_REGISTER_NONE &&
           (!source.mem.disp.has_displacement || source.mem.disp.value == 0);
}

std::optional<std::string> jni_cstring(std::span<const std::uint8_t> data, const ElfInfo& elf,
                                       std::uint64_t va, std::size_t limit = 512) {
    const auto extent = jni_va_extent(data, elf, va);
    if (!extent) return std::nullopt;
    std::vector<std::uint16_t> units;
    const auto count = std::min(limit, extent->second);
    for (std::size_t i = 0; i < count; ++i) {
        const auto c = data[extent->first + i];
        if (c == 0) {
            if (units.empty()) return std::nullopt;
            std::string out;
            for (std::size_t z = 0; z < units.size(); ++z) {
                const auto unit = units[z];
                if (unit >= 0xd800 && unit <= 0xdbff) {
                    if (z + 1 >= units.size() || units[z + 1] < 0xdc00 || units[z + 1] > 0xdfff)
                        return std::nullopt;
                    const auto code_point = 0x10000u +
                        (static_cast<std::uint32_t>(unit - 0xd800) << 10) +
                        static_cast<std::uint32_t>(units[++z] - 0xdc00);
                    append_utf8_cp(out, code_point);
                } else {
                    if (unit >= 0xdc00 && unit <= 0xdfff) return std::nullopt;
                    append_utf8_cp(out, unit);
                }
            }
            return out;
        }
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f) return std::nullopt;
            units.push_back(c);
            continue;
        }
        if ((c & 0xe0u) == 0xc0u) {
            if (++i >= count) return std::nullopt;
            const auto c2 = data[extent->first + i];
            if ((c2 & 0xc0u) != 0x80u) return std::nullopt;
            const auto unit = static_cast<std::uint16_t>(((c & 0x1fu) << 6) | (c2 & 0x3fu));
            if (unit == 0) {
                if (c != 0xc0 || c2 != 0x80) return std::nullopt;
            } else if (unit < 0x80) return std::nullopt;
            units.push_back(unit);
            continue;
        }
        if ((c & 0xf0u) == 0xe0u) {
            if (i + 2 >= count) return std::nullopt;
            const auto c2 = data[extent->first + ++i], c3 = data[extent->first + ++i];
            if ((c2 & 0xc0u) != 0x80u || (c3 & 0xc0u) != 0x80u) return std::nullopt;
            const auto unit = static_cast<std::uint16_t>(
                ((c & 0x0fu) << 12) | ((c2 & 0x3fu) << 6) | (c3 & 0x3fu));
            if (unit < 0x800) return std::nullopt;
            units.push_back(unit);
            continue;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> jni_relocated_pointer(const ElfInfo& elf, std::uint64_t slot_va) {
    const auto relative_type = elf.machine == 62 ? 8u : 1027u;
    for (const auto& relocation : elf.dynamic.relocations) {
        if (relocation.target_va == slot_va && relocation.target_file_backed &&
            relocation.type == relative_type && relocation.has_addend && relocation.addend >= 0)
            return static_cast<std::uint64_t>(relocation.addend);
    }
    return std::nullopt;
}

const ElfUnwindFde* jni_exact_fde(const ElfInfo& elf, std::uint64_t va) {
    for (const auto& fde : elf.unwind.fdes) {
        if (fde.function_file_backed && fde.function_start_va == va && fde.function_end_va > va) return &fde;
    }
    return nullptr;
}

struct JniA64Decoded {
    std::uint64_t va = 0;
    std::uint32_t word = 0;
};

std::int64_t jni_a64_sign_extend(std::uint64_t value, unsigned bits) {
    const auto sign = std::uint64_t{1} << (bits - 1);
    return static_cast<std::int64_t>((value ^ sign) - sign);
}

bool jni_a64_blr(std::uint32_t word, std::uint8_t& target) {
    if ((word & 0xfffffc1fu) != 0xd63f0000u) return false;
    target = static_cast<std::uint8_t>((word >> 5) & 31u);
    return true;
}

bool jni_a64_ldr_unsigned(std::uint32_t word, std::uint8_t& target,
                          std::uint8_t& base, std::uint64_t& offset) {
    if ((word & 0xffc00000u) != 0xf9400000u) return false;
    target = static_cast<std::uint8_t>(word & 31u);
    base = static_cast<std::uint8_t>((word >> 5) & 31u);
    offset = std::uint64_t((word >> 10) & 0xfffu) * 8;
    return true;
}

bool jni_a64_move(std::uint32_t word, std::uint8_t target, std::uint8_t source) {
    return (word & 0xffe0ffe0u) == 0xaa0003e0u &&
           (word & 31u) == target && ((word >> 16) & 31u) == source;
}

std::optional<std::uint64_t> jni_a64_movz(std::uint32_t word, std::uint8_t target) {
    if ((word & 0x7f800000u) != 0x52800000u || (word & 31u) != target) return std::nullopt;
    const auto shift = unsigned((word >> 21) & 3u) * 16;
    if ((word & 0x80000000u) == 0 && shift > 16) return std::nullopt;
    return std::uint64_t((word >> 5) & 0xffffu) << shift;
}

bool jni_a64_control(std::uint32_t word) {
    return (word & 0xfc000000u) == 0x14000000u ||
           (word & 0xfc000000u) == 0x94000000u ||
           (word & 0xff000010u) == 0x54000000u ||
           (word & 0x7e000000u) == 0x34000000u ||
           (word & 0x7e000000u) == 0x36000000u ||
           (word & 0xfffffc1fu) == 0xd61f0000u ||
           (word & 0xfffffc1fu) == 0xd63f0000u ||
           (word & 0xfffffc1fu) == 0xd65f0000u;
}

std::optional<std::size_t> jni_a64_last_writer(const std::vector<JniA64Decoded>& instructions,
                                               std::size_t before, std::uint8_t wanted) {
    for (std::size_t i = before; i-- > 0;) {
        const auto word = instructions[i].word;
        std::uint8_t ignored = 0;
        if (((word & 0xfc000000u) == 0x94000000u || jni_a64_blr(word, ignored)) && wanted <= 18)
            return std::nullopt;
        if (!jni_a64_control(word) && (word & 31u) == wanted) return i;
    }
    return std::nullopt;
}

std::optional<std::uint64_t> jni_a64_pc_address(const JniA64Decoded& decoded,
                                                std::uint8_t target) {
    const auto word = decoded.word;
    if ((word & 31u) != target || (word & 0x1f000000u) != 0x10000000u) return std::nullopt;
    const auto immediate = ((std::uint64_t(word >> 29) & 3u) |
                            (std::uint64_t(word >> 5) & 0x7ffffu) << 2);
    const bool page = (word & 0x80000000u) != 0;
    const auto base = page ? decoded.va & ~std::uint64_t{0xfff} : decoded.va;
    return jni_add_signed(base, jni_a64_sign_extend(immediate, 21) * (page ? 4096 : 1));
}

std::optional<std::uint64_t> jni_a64_address(const std::vector<JniA64Decoded>& instructions,
                                             std::size_t writer, std::uint8_t target) {
    if (const auto direct = jni_a64_pc_address(instructions[writer], target)) return direct;
    const auto word = instructions[writer].word;
    if ((word & 0xffc00000u) != 0x91000000u || (word & 31u) != target) return std::nullopt;
    const auto base = static_cast<std::uint8_t>((word >> 5) & 31u);
    const auto base_writer = jni_a64_last_writer(instructions, writer, base);
    if (!base_writer) return std::nullopt;
    const auto page = jni_a64_pc_address(instructions[*base_writer], base);
    if (!page || (instructions[*base_writer].word & 0x80000000u) == 0) return std::nullopt;
    const auto shift = (word >> 22) & 1u;
    const auto add = std::uint64_t((word >> 10) & 0xfffu) << (shift ? 12 : 0);
    if (*page > std::numeric_limits<std::uint64_t>::max() - add) return std::nullopt;
    return *page + add;
}

std::optional<std::uint64_t> jni_a64_branch_target(const JniA64Decoded& decoded) {
    const auto word = decoded.word;
    if ((word & 0xfc000000u) == 0x14000000u || (word & 0xfc000000u) == 0x94000000u)
        return jni_add_signed(decoded.va, jni_a64_sign_extend(word & 0x03ffffffu, 26) * 4);
    if ((word & 0xff000010u) == 0x54000000u || (word & 0x7e000000u) == 0x34000000u)
        return jni_add_signed(decoded.va, jni_a64_sign_extend((word >> 5) & 0x7ffffu, 19) * 4);
    if ((word & 0x7e000000u) == 0x36000000u)
        return jni_add_signed(decoded.va, jni_a64_sign_extend((word >> 5) & 0x3fffu, 14) * 4);
    return std::nullopt;
}

std::vector<JniA64Decoded> jni_a64_decode_fde(std::span<const std::uint8_t> data,
                                              const ElfInfo& elf, const ElfUnwindFde& fde,
                                              bool& limited) {
    std::vector<JniA64Decoded> out;
    if (!fde.function_file_backed || !fde.function_size || (fde.function_size & 3u)) return out;
    if (fde.function_size > (1u << 20) || fde.function_size / 4 > 8192) {
        limited = true;
        return out;
    }
    out.reserve(static_cast<std::size_t>(fde.function_size / 4));
    for (auto va = fde.function_start_va; va < fde.function_end_va; va += 4) {
        const auto extent = jni_va_extent(data, elf, va);
        if (!extent || extent->second < 4) return {};
        out.push_back({va, le32(data, extent->first)});
    }
    return out;
}

JniFlow jni_a64_build_flow(const std::vector<JniA64Decoded>& instructions) {
    JniFlow flow;
    if (instructions.empty()) return flow;
    flow.edges.resize(instructions.size());
    std::unordered_map<std::uint64_t, std::size_t> by_va;
    for (std::size_t i = 0; i < instructions.size(); ++i)
        if (!by_va.emplace(instructions[i].va, i).second) return flow;
    auto fallthrough = [&](std::size_t i) {
        if (i + 1 >= instructions.size() || instructions[i + 1].va != instructions[i].va + 4) return false;
        flow.edges[i].push_back(i + 1);
        return true;
    };
    auto target = [&](std::size_t i) {
        const auto address = jni_a64_branch_target(instructions[i]);
        if (!address) return false;
        const auto found = by_va.find(*address);
        if (found == by_va.end()) return false;
        flow.edges[i].push_back(found->second);
        return true;
    };
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        const auto word = instructions[i].word;
        if ((word & 0xfffffc1fu) == 0xd65f0000u) continue;
        if ((word & 0xfffffc1fu) == 0xd61f0000u) return flow;
        if ((word & 0xfc000000u) == 0x14000000u) {
            if (!target(i)) return flow;
            continue;
        }
        const bool conditional = (word & 0xff000010u) == 0x54000000u ||
                                 (word & 0x7e000000u) == 0x34000000u ||
                                 (word & 0x7e000000u) == 0x36000000u;
        if (conditional) {
            if (!target(i) || !fallthrough(i)) return flow;
            continue;
        }
        if (i + 1 < instructions.size()) {
            if (!fallthrough(i)) return flow;
        } else {
            return flow;
        }
    }
    flow.reachable.assign(instructions.size(), false);
    std::deque<std::size_t> pending{0};
    flow.reachable[0] = true;
    while (!pending.empty()) {
        const auto at = pending.front();
        pending.pop_front();
        for (const auto next : flow.edges[at]) if (!flow.reachable[next]) {
            flow.reachable[next] = true;
            pending.push_back(next);
        }
    }
    flow.complete = true;
    return flow;
}

struct JniA64InterfaceCall {
    std::size_t table_writer = 0;
    std::size_t target_writer = 0;
};

std::optional<JniA64InterfaceCall> jni_a64_interface_call(
    const std::vector<JniA64Decoded>& instructions, std::size_t call, std::uint64_t offset) {
    std::uint8_t call_register = 0;
    if (!jni_a64_blr(instructions[call].word, call_register)) return std::nullopt;
    const auto target_writer = jni_a64_last_writer(instructions, call, call_register);
    if (!target_writer) return std::nullopt;
    std::uint8_t target = 0, table = 0;
    std::uint64_t target_offset = 0;

    if (!jni_a64_ldr_unsigned(instructions[*target_writer].word, target, table, target_offset) ||
        target != call_register || target_offset != offset) return std::nullopt;
    const auto table_writer = jni_a64_last_writer(instructions, *target_writer, table);
    if (!table_writer) return std::nullopt;
    std::uint8_t loaded = 0, base = 0;
    std::uint64_t table_offset = 0;
    if (!jni_a64_ldr_unsigned(instructions[*table_writer].word, loaded, base, table_offset) ||
        loaded != table || base != 0 || table_offset != 0) return std::nullopt;
    return JniA64InterfaceCall{*table_writer, *target_writer};
}

NativeRegistrationScan recover_register_natives_x86_64(
    std::span<const std::uint8_t> data, const ElfInfo& elf, std::string_view entry, std::string_view abi) {
    NativeRegistrationScan result;
    auto& out = result.evidence;
    if (!elf.valid || !elf.elf64 || !elf.little_endian || elf.machine != 62 ||
        elf.dynamic.state != "RESOLVED" || elf.unwind.state != "RESOLVED") return result;
    const ElfDynamicSymbol* onload = nullptr;
    for (const auto& symbol : elf.dynamic.symbols) {
        if (symbol.exported && symbol.type == 2 && symbol.name == "JNI_OnLoad") { onload = &symbol; break; }
    }
    if (!onload) return result;
    const auto* fde = jni_exact_fde(elf, onload->value);
    if (!fde) return result;
    bool decode_limited = false;
    const auto instructions = jni_decode_fde(data, elf, *fde, decode_limited);
    result.limited = decode_limited;
    if (decode_limited)
        result.error = "x86-64 JNI_OnLoad exceeded the 1 MiB/8192-instruction decode budget; RegisterNatives evidence omitted";
    if (instructions.empty()) return result;
    const auto flow = jni_build_flow(instructions);
    if (!flow.complete) return result;
    for (std::size_t call = 0; call < instructions.size(); ++call) {
        const auto register_table_base = jni_indirect_table_call_base(instructions[call], 215 * 8);
        if (!register_table_base || !flow.reachable[call]) continue;
        const auto methods_writer = jni_last_writer(instructions, call, ZYDIS_REGISTER_RDX);
        const auto count_writer = jni_last_writer(instructions, call, ZYDIS_REGISTER_RCX);
        const auto class_writer = jni_last_writer(instructions, call, ZYDIS_REGISTER_RSI);
        const auto register_table_writer = jni_last_writer(instructions, call, *register_table_base);
        if (!methods_writer || !count_writer || !class_writer || !register_table_writer || *class_writer == 0 ||
            !jni_interface_table_load(instructions[*register_table_writer], *register_table_base) ||
            !jni_register_move(instructions[*class_writer], ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RAX) ||
            !jni_indirect_table_call_base(instructions[*class_writer - 1], 6 * 8)) continue;
        const auto find_call = *class_writer - 1;
        const auto find_table_base = jni_indirect_table_call_base(instructions[find_call], 6 * 8);
        if (!find_table_base) continue;
        const auto find_table_writer = jni_last_writer(instructions, find_call, *find_table_base);
        const auto class_literal_writer = jni_last_writer(instructions, find_call, ZYDIS_REGISTER_RSI);
        if (!find_table_writer || !class_literal_writer ||
            !jni_interface_table_load(instructions[*find_table_writer], *find_table_base)) continue;
        const std::array<std::size_t, 7> required = {*methods_writer, *count_writer, *class_writer,
            *register_table_writer, find_call, *find_table_writer, *class_literal_writer};
        if (!std::ranges::all_of(required, [&](std::size_t writer) { return jni_dominates(flow, writer, call); })) continue;
        const auto methods_va = jni_rip_literal(instructions[*methods_writer], ZYDIS_REGISTER_RDX);
        const auto class_va = jni_rip_literal(instructions[*class_literal_writer], ZYDIS_REGISTER_RSI);
        const auto count = jni_immediate(instructions[*count_writer], ZYDIS_REGISTER_RCX);
        if (!methods_va || !class_va || !count || !*count) continue;
        if (*count > 64) {
            result.limited = true;
            result.error = "x86-64 RegisterNatives method count exceeded the 64-row table budget; table evidence omitted";
            continue;
        }
        const auto class_name = jni_cstring(data, elf, *class_va);
        if (!class_name) {
            result.limited = true;
            result.error = "x86-64 RegisterNatives class literal is not bounded valid JNI modified UTF-8; table evidence omitted";
            continue;
        }
        if (class_name->front() == '/' || class_name->back() == '/' ||
            class_name->find("//") != std::string::npos) continue;
        const auto descriptor = "L" + *class_name + ";";
        for (std::uint64_t i = 0; i < *count; ++i) {
            const auto row_va = *methods_va + i * 24;
            const auto name_va = jni_relocated_pointer(elf, row_va);
            const auto signature_va = jni_relocated_pointer(elf, row_va + 8);
            const auto function_va = jni_relocated_pointer(elf, row_va + 16);
            if (!name_va || !signature_va || !function_va || !*function_va) break;
            const auto name = jni_cstring(data, elf, *name_va);
            const auto signature = jni_cstring(data, elf, *signature_va);
            if (!name || !signature) {
                result.limited = true;
                result.error = "x86-64 RegisterNatives row is not bounded valid JNI modified UTF-8; table evidence omitted";
                break;
            }
            if (signature->front() != '(' || signature->find(')') == std::string::npos) break;
            if (out.size() >= 256) {
                result.limited = true;
                result.error = "x86-64 RegisterNatives evidence exceeded the 256-row library budget; additional rows omitted";
                return result;
            }
            NativeRegistrationEvidence evidence;
            evidence.entry = std::string(entry);
            evidence.abi = std::string(abi);
            evidence.class_descriptor = descriptor;
            evidence.method_name = *name;
            evidence.method_descriptor = *signature;
            evidence.function_va = *function_va;
            if (const auto extent = jni_va_extent(data, elf, *function_va)) evidence.function_file_offset = extent->first;
            if (const auto* function_fde = jni_exact_fde(elf, *function_va)) {
                evidence.fde_exact = true;
                evidence.function_end_va = function_fde->function_end_va;
            }
            out.push_back(std::move(evidence));
        }
    }
    return result;
}

NativeRegistrationScan recover_register_natives_aarch64(
    std::span<const std::uint8_t> data, const ElfInfo& elf, std::string_view entry, std::string_view abi) {
    NativeRegistrationScan result;
    auto& out = result.evidence;
    if (!elf.valid || !elf.elf64 || !elf.little_endian || elf.machine != 183 ||
        elf.dynamic.state != "RESOLVED" || elf.unwind.state != "RESOLVED") return result;
    const ElfDynamicSymbol* onload = nullptr;
    for (const auto& symbol : elf.dynamic.symbols) {
        if (symbol.exported && symbol.type == 2 && symbol.name == "JNI_OnLoad") {
            onload = &symbol;
            break;
        }
    }
    if (!onload) return result;
    const auto* fde = jni_exact_fde(elf, onload->value);
    if (!fde) return result;
    bool decode_limited = false;
    const auto instructions = jni_a64_decode_fde(data, elf, *fde, decode_limited);
    if (decode_limited) {
        result.limited = true;
        result.error = "AArch64 JNI_OnLoad exceeded the 1 MiB/8192-instruction decode budget; RegisterNatives evidence omitted";
    }
    if (instructions.empty()) return result;
    const auto flow = jni_a64_build_flow(instructions);
    if (!flow.complete) return result;
    for (std::size_t call = 0; call < instructions.size(); ++call) {
        if (!flow.reachable[call]) continue;
        const auto registration_call = jni_a64_interface_call(instructions, call, 215 * 8);
        if (!registration_call) continue;
        const auto methods_writer = jni_a64_last_writer(instructions, call, 2);
        const auto count_writer = jni_a64_last_writer(instructions, call, 3);
        const auto class_writer = jni_a64_last_writer(instructions, call, 1);
        if (!methods_writer || !count_writer || !class_writer ||
            !jni_a64_move(instructions[*class_writer].word, 1, 0)) continue;
        std::optional<std::size_t> find_call;
        std::optional<JniA64InterfaceCall> find_interface;
        for (std::size_t at = *class_writer; at-- > 0;) {
            if (!flow.reachable[at]) continue;
            const auto candidate = jni_a64_interface_call(instructions, at, 6 * 8);
            if (candidate) {
                find_call = at;
                find_interface = candidate;
                break;
            }
        }
        if (!find_call || !find_interface) continue;
        const auto class_literal_writer = jni_a64_last_writer(instructions, *find_call, 1);
        if (!class_literal_writer) continue;
        const std::array<std::size_t, 9> required = {
            *methods_writer, *count_writer, *class_writer,
            registration_call->table_writer, registration_call->target_writer,
            *find_call, find_interface->table_writer, find_interface->target_writer,
            *class_literal_writer
        };
        if (!std::ranges::all_of(required, [&](std::size_t writer) {
                return jni_dominates(flow, writer, call);
            }) || !jni_dominates(flow, *class_literal_writer, *find_call)) continue;
        const auto methods_va = jni_a64_address(instructions, *methods_writer, 2);
        const auto class_va = jni_a64_address(instructions, *class_literal_writer, 1);
        const auto count = jni_a64_movz(instructions[*count_writer].word, 3);
        if (!methods_va || !class_va || !count || !*count) continue;
        if (*count > 64) {
            result.limited = true;
            result.error = "AArch64 RegisterNatives method count exceeded the 64-row table budget; table evidence omitted";
            continue;
        }
        const auto class_name = jni_cstring(data, elf, *class_va);
        if (!class_name) {
            result.limited = true;
            result.error = "AArch64 RegisterNatives class literal is not bounded valid JNI modified UTF-8; table evidence omitted";
            continue;
        }
        if (class_name->front() == '/' || class_name->back() == '/' ||
            class_name->find("//") != std::string::npos) continue;
        const auto descriptor = "L" + *class_name + ";";
        for (std::uint64_t i = 0; i < *count; ++i) {
            const auto row_va = *methods_va + i * 24;
            const auto name_va = jni_relocated_pointer(elf, row_va);
            const auto signature_va = jni_relocated_pointer(elf, row_va + 8);
            const auto function_va = jni_relocated_pointer(elf, row_va + 16);
            if (!name_va || !signature_va || !function_va || !*function_va) break;
            const auto name = jni_cstring(data, elf, *name_va);
            const auto signature = jni_cstring(data, elf, *signature_va);
            if (!name || !signature) {
                result.limited = true;
                result.error = "AArch64 RegisterNatives row is not bounded valid JNI modified UTF-8; table evidence omitted";
                break;
            }
            if (signature->front() != '(' || signature->find(')') == std::string::npos)
                break;
            if (out.size() >= 256) {
                result.limited = true;
                result.error = "AArch64 RegisterNatives evidence exceeded the 256-row library budget; additional rows omitted";
                return result;
            }
            NativeRegistrationEvidence evidence;
            evidence.entry = std::string(entry);
            evidence.abi = std::string(abi);
            evidence.class_descriptor = descriptor;
            evidence.method_name = *name;
            evidence.method_descriptor = *signature;
            evidence.function_va = *function_va;
            if (const auto extent = jni_va_extent(data, elf, *function_va))
                evidence.function_file_offset = extent->first;
            if (const auto* function_fde = jni_exact_fde(elf, *function_va)) {
                evidence.fde_exact = true;
                evidence.function_end_va = function_fde->function_end_va;
            }
            out.push_back(std::move(evidence));
        }
    }
    return result;
}

NativeRegistrationScan recover_register_natives(
    std::span<const std::uint8_t> data, const ElfInfo& elf, std::string_view entry, std::string_view abi) {
    if (elf.machine == 62) return recover_register_natives_x86_64(data, elf, entry, abi);
    if (elf.machine == 183) return recover_register_natives_aarch64(data, elf, entry, abi);
    return {};
}
std::optional<std::string> jni_mangle_ascii(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    for (const unsigned char c : value) {
        if (c >= 0x80) return std::nullopt;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) out.push_back(static_cast<char>(c));
        else if (c == '/') out.push_back('_');
        else if (c == '_') out += "_1";
        else if (c == ';') out += "_2";
        else if (c == '[') out += "_3";
        else {
            const auto code_unit = static_cast<std::uint32_t>(c);
            out += "_0";
            out.push_back(hex[(code_unit >> 12) & 0xf]);
            out.push_back(hex[(code_unit >> 8) & 0xf]);
            out.push_back(hex[(code_unit >> 4) & 0xf]);
            out.push_back(hex[code_unit & 0xf]);
        }
    }
    return out;
}

std::optional<std::pair<std::string, std::string>> jni_symbol_names(const DexMethodInfo& method) {
    if (method.owner_descriptor.size() < 3 || method.owner_descriptor.front() != 'L' ||
        method.owner_descriptor.back() != ';') return std::nullopt;
    const auto owner = jni_mangle_ascii(std::string_view(method.owner_descriptor).substr(1, method.owner_descriptor.size() - 2));
    const auto name = jni_mangle_ascii(method.name);
    const auto close = method.descriptor.find(')');
    if (!owner || !name || method.descriptor.empty() || method.descriptor.front() != '(' || close == std::string::npos) return std::nullopt;
    const auto parameters = jni_mangle_ascii(std::string_view(method.descriptor).substr(1, close - 1));
    if (!parameters) return std::nullopt;
    const auto short_name = "Java_" + *owner + "_" + *name;
    return std::pair<std::string, std::string>{short_name, short_name + "__" + *parameters};
}

std::optional<std::string> apk_load_library_name(std::string_view normalized_path) {
    const auto slash = normalized_path.rfind('/');
    const auto leaf = slash == std::string_view::npos ? normalized_path : normalized_path.substr(slash + 1);
    if (leaf.size() <= 6 || !leaf.starts_with("lib") || !ends_with_ci(leaf, ".so")) return std::nullopt;
    const auto name = leaf.substr(3, leaf.size() - 6);
    if (name.empty() || name.size() > 255) return std::nullopt;
    for (const unsigned char c : name) if (c < 0x21 || c > 0x7e || c == '/' || c == '\\') return std::nullopt;
    return std::string(name);
}

}  // namespace

ApkInfo detect_apk(std::span<const std::uint8_t> data) {
    ApkInfo out;
    if (!archive_magic(data)) return out;
    mz_zip_archive zip{};
    ZipCloser close{&zip};
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0)) {
        out.error = "ZIP central directory validation failed: " + miniz_error(zip);
        return out;
    }
    out.zip_valid = true;
    out.entry_count = mz_zip_reader_get_num_files(&zip);
    out.central_directory_offset = zip.m_central_directory_file_ofs;
    out.zip64 = mz_zip_is_zip64(&zip) != 0;
    if (out.entry_count > 200000) {
        out.error = "APK/ZIP entry count exceeds safety limit";
        return out;
    }
    out.entries.reserve(out.entry_count);
    ResourceTableParse resource_parse;
    std::unordered_map<std::string, std::size_t> normalized_seen;
    std::set<std::string> abis;
    constexpr std::uint64_t kMaxNativeDeepEntryBytes = 64ull * 1024 * 1024;
    constexpr std::uint64_t kMaxNativeDeepTotalBytes = 128ull * 1024 * 1024;
    std::uint64_t native_deep_budget_left = kMaxNativeDeepTotalBytes;
    constexpr std::uint64_t kMaxDexDeepEntryBytes = 32ull * 1024 * 1024;
    constexpr std::uint64_t kMaxDexDeepTotalBytes = 64ull * 1024 * 1024;
    constexpr std::uint32_t kMaxDexDeepEntries = 32;
    std::uint64_t dex_deep_budget_left = kMaxDexDeepTotalBytes;
    std::uint32_t dex_deep_entries = 0;
    std::vector<DexDeclarationEvidence> dex_declarations;
    std::vector<DexLoadEvidence> dex_loads;
    std::vector<NativeExportEvidence> native_exports;
    std::vector<NativeRegistrationEvidence> native_registrations;
    constexpr std::uint32_t kMaxUnityMetadataParses = 8;
    constexpr std::uint64_t kMaxUnityMetadataParseBytes = 128ull * 1024 * 1024;

    for (std::uint32_t i = 0; i < out.entry_count; ++i) {
        mz_zip_archive_file_stat st{};
        if (!mz_zip_reader_file_stat(&zip, i, &st)) {
            out.error = "cannot read ZIP central-directory entry " + std::to_string(i) + ": " + miniz_error(zip);
            return out;
        }
        const std::uint64_t central_off = zip.m_central_directory_file_ofs + st.m_central_dir_ofs;
        if (central_off > data.size() || 46 > data.size() - central_off || le32(data, central_off) != kCentralHeaderSig) {
            out.error = "invalid ZIP central-directory entry geometry";
            return out;
        }
        const auto central_name_len = le16(data, central_off + 28);
        const auto central_extra_len = le16(data, central_off + 30);
        const auto central_comment_len = le16(data, central_off + 32);
        std::uint64_t central_end = central_off + 46;
        if (!add_u64(central_end, std::uint64_t(central_name_len) + central_extra_len + central_comment_len, central_end) || central_end > data.size()) {
            out.error = "truncated ZIP central-directory variable fields";
            return out;
        }
        std::string raw_name(reinterpret_cast<const char*>(data.data() + central_off + 46), central_name_len);
        const auto local_off = st.m_local_header_ofs;
        if (local_off > data.size() || 30 > data.size() - local_off || le32(data, local_off) != kLocalHeaderSig) {
            out.error = "invalid ZIP local-header geometry for entry " + std::to_string(i);
            return out;
        }
        const auto local_name_len = le16(data, local_off + 26);
        const auto local_extra_len = le16(data, local_off + 28);
        std::uint64_t data_off = local_off + 30;
        if (!add_u64(data_off, std::uint64_t(local_name_len) + local_extra_len, data_off) || data_off > data.size()) {
            out.error = "truncated ZIP local-header variable fields";
            return out;
        }
        if (local_name_len != central_name_len || local_off + 30 + local_name_len > data.size() ||
            !std::equal(raw_name.begin(), raw_name.end(), data.begin() + local_off + 30)) {
            out.error = "ZIP local/central filename mismatch for entry " + std::to_string(i);
            return out;
        }
        if (st.m_comp_size > data.size() - data_off) {
            out.error = "ZIP compressed data exceeds physical input for entry " + std::to_string(i);
            return out;
        }
        const auto local_flags = le16(data, local_off + 6);
        const auto local_method = le16(data, local_off + 8);
        if (local_flags != st.m_bit_flag) {
            out.error = "ZIP local/central general-purpose flags mismatch for entry " + std::to_string(i);
            return out;
        }
        if (local_method != st.m_method) {
            out.error = "ZIP local/central compression method mismatch for entry " + std::to_string(i);
            return out;
        }
        const bool has_data_descriptor = (st.m_bit_flag & 0x0008u) != 0;
        if (!has_data_descriptor) {
            const auto local_crc = le32(data, local_off + 14);
            const auto local_comp = le32(data, local_off + 18);
            const auto local_uncomp = le32(data, local_off + 22);
            if (local_crc != st.m_crc32) {
                out.error = "ZIP local/central CRC mismatch for entry " + std::to_string(i);
                return out;
            }
            if (local_comp != 0xffffffffu && std::uint64_t(local_comp) != st.m_comp_size) {
                out.error = "ZIP local/central compressed-size mismatch for entry " + std::to_string(i);
                return out;
            }
            if (local_uncomp != 0xffffffffu && std::uint64_t(local_uncomp) != st.m_uncomp_size) {
                out.error = "ZIP local/central uncompressed-size mismatch for entry " + std::to_string(i);
                return out;
            }
        }

        ApkEntryInfo e;
        e.index = i;
        e.name = raw_name;
        e.compressed_size = st.m_comp_size;
        e.uncompressed_size = st.m_uncomp_size;
        e.crc32 = st.m_crc32;
        e.method = st.m_method;
        e.flags = st.m_bit_flag;
        e.local_header_offset = local_off;
        e.data_offset = data_off;
        e.central_directory_offset = central_off;
        e.directory = st.m_is_directory != 0;
        e.encrypted = (st.m_bit_flag & (kZipFlagEncrypted | kZipFlagStrongEncryption)) != 0;
        e.supported = st.m_is_supported != 0;
        if (!e.encrypted && e.supported && !e.directory &&
            !mz_zip_validate_file(&zip, i, MZ_ZIP_FLAG_VALIDATE_HEADERS_ONLY)) {
            out.error = "ZIP local/central header validation failed for entry " + std::to_string(i) + ": " + miniz_error(zip);
            return out;
        }
        const auto creator = std::uint8_t(st.m_version_made_by >> 8);
        const auto unix_mode = std::uint16_t(st.m_external_attr >> 16);
        e.symlink = (creator == 3 || creator == 19) && (unix_mode & 0170000) == 0120000;
        std::string normalized;
        e.safe_path = safe_relative_name(raw_name, e.directory, normalized);
        if (e.safe_path && !normalized.empty()) {
            if (const auto it = normalized_seen.find(lower_ascii(normalized)); it != normalized_seen.end()) {
                e.duplicate_path = true;
                auto& previous = out.entries[it->second];
                if (!previous.duplicate_path) {
                    ++out.duplicate_path_entry_count;
                    if (!previous.directory && previous.safe_path && previous.supported &&
                        !previous.encrypted && !previous.symlink) {
                        out.extractable_bytes -= previous.uncompressed_size;
                        --out.extractable_files;
                        if (previous.analysis_priority != 0) {
                            out.analysis_candidate_bytes -= previous.uncompressed_size;
                            --out.analysis_candidate_files;
                        }
                    }
                }
                ++out.duplicate_path_entry_count;
                previous.analysis_priority = 0;
                previous.duplicate_path = true;
                out.has_duplicate_paths = true;
            } else {
                normalized_seen.emplace(lower_ascii(normalized), out.entries.size());
            }
        }
        if (e.safe_path) e.normalized_name = normalized;
        const std::string_view logical = e.safe_path ? std::string_view(e.normalized_name) : std::string_view(raw_name);
        e.manifest = logical == "AndroidManifest.xml";
        e.dex = is_dex_name(logical);
        e.resources_arsc = logical == "resources.arsc";
        e.asset = logical.starts_with("assets/");
        e.resource = logical.starts_with("res/");
        e.v1_signature_file = is_v1_signing_file(logical);
        e.nested_archive = is_nested_archive(logical);
        e.native_library = is_native_library_path(logical, e.abi);
        e.godot_legacy_engine_config_candidate = is_godot_legacy_engine_config_resource_path(logical);
        e.unity_il2cpp_metadata_candidate = is_unity_il2cpp_metadata_resource_path(logical);
        if (!e.directory && e.safe_path && !e.symlink && !e.encrypted && e.supported && !e.duplicate_path) {
            e.analysis_priority = analysis_priority_for(e, logical);
        }

        // Hermes is a content route, not a filename route. Probe every otherwise safe
        // regular member in archive order, but cap both the number of probes and the
        // aggregate bytes that may be fully decompressed/CRC-validated for HBC identity.
        // Direct child analysis will perform the independently versioned semantic parse.
        if (!e.directory && e.safe_path && !e.symlink && !e.encrypted && e.supported && !e.duplicate_path) {
            if (out.hermes_probe_entry_count >= kMaxHermesProbeEntries) {
                out.hermes_probe_budget_exhausted = true;
            } else {
                ++out.hermes_probe_entry_count;
                const auto prefix = entry_prefix(zip, e, kHermesMagic.size(), data);
                if (prefix.size() == kHermesMagic.size() &&
                    std::equal(kHermesMagic.begin(), kHermesMagic.end(), prefix.begin())) {
                    e.hermes_magic = true;
                    ++out.hermes_magic_count;
                    push_interesting(out, e.name);
                    const bool one_entry_budget = e.uncompressed_size <= kMaxHermesProbeBytes;
                    const bool aggregate_budget = out.hermes_probe_validated_bytes <= kMaxHermesProbeBytes &&
                        e.uncompressed_size <= kMaxHermesProbeBytes - out.hermes_probe_validated_bytes;
                    if (!one_entry_budget || !aggregate_budget) {
                        e.hermes_probe_skipped_budget = true;
                        e.hermes_error = one_entry_budget
                            ? "Hermes HBC integrity probe deferred by bounded 64 MiB aggregate byte budget"
                            : "Hermes HBC member exceeds bounded 64 MiB per-entry byte budget";
                        ++out.hermes_probe_skipped_budget_count;
                        out.hermes_probe_budget_exhausted = true;
                        e.analysis_priority = 0;
                    } else {
                        auto full = entry_full_bounded(zip, e, kMaxHermesProbeBytes, data);
                        if (full.empty()) {
                            e.hermes_error = "Hermes HBC full-entry decompression/CRC validation failed";
                            ++out.hermes_integrity_failure_count;
                            e.analysis_priority = 0;
                        } else {
                            out.hermes_probe_validated_bytes += e.uncompressed_size;
                            e.hermes_integrity_valid = true;
                            e.hermes_sha256 = sha256_bytes(full);
                            const auto hermes = parse_hermes_bytecode(full);
                            e.hermes_version = hermes.version;
                            e.hermes_supported_epoch = hermes.supported_epoch;
                            e.hermes_valid = hermes.valid;
                            e.hermes_parse_complete = hermes.parse_complete;
                            e.hermes_error = hermes.error;
                            e.analysis_priority = std::max<std::uint8_t>(e.analysis_priority, 99);
                        }
                    }
                }
            }
        }

        if (e.manifest && !e.directory) {
            out.has_manifest = true;
            constexpr std::uint64_t kMaxManifestBytes = 8ull * 1024 * 1024;
            const auto manifest_bytes = entry_full_bounded(zip, e, kMaxManifestBytes, data);
            e.manifest_binary_xml = !manifest_bytes.empty() && binary_xml_header(manifest_bytes, e.uncompressed_size);
            if (e.manifest_binary_xml) out.manifest = parse_binary_manifest(manifest_bytes);
            else if (e.uncompressed_size > kMaxManifestBytes) {
                out.manifest.candidate = true;
                out.manifest.error = "AndroidManifest.xml exceeds bounded 8 MiB parser limit";
            }
            out.manifest_binary_xml = out.manifest_binary_xml || e.manifest_binary_xml;
            push_interesting(out, e.name);
        }
        if (e.dex && !e.directory) {
            ++out.dex_count;
            out.dex_entries.push_back(e.name);
            const auto p = entry_prefix(zip, e, 0x78, data);
            e.dex_magic = dex_header(p, e.uncompressed_size);
            if (e.dex_magic) {
                ++out.validated_dex_count;
                if (!e.duplicate_path && e.safe_path && !e.symlink && !e.encrypted && e.supported) {
                    if (e.uncompressed_size > kMaxDexDeepEntryBytes || e.uncompressed_size > dex_deep_budget_left ||
                        dex_deep_entries >= kMaxDexDeepEntries) {
                        e.dex_deep_state = "SKIPPED_BUDGET";
                        e.dex_deep_error = "bounded APK child DEX deep-analysis budget exhausted";
                    } else {
                        ++dex_deep_entries;
                        dex_deep_budget_left -= e.uncompressed_size;
                        const auto full = entry_full_bounded(zip, e, kMaxDexDeepEntryBytes, data);
                        if (full.empty() && e.uncompressed_size != 0) {
                            e.dex_deep_state = "FAILED_EXTRACTION";
                            e.dex_deep_error = "bounded child DEX extraction/CRC validation failed";
                        } else {
                            const auto dex = parse_dex(full);
                            const bool integrity = dex.valid && !dex.container_v41 && dex.checksum_checked &&
                                                   dex.checksum_matches && dex.signature_checked && dex.signature_matches;
                            if (!integrity) {
                                e.dex_deep_state = "FAILED_DEX";
                                e.dex_deep_error = dex.error.empty() ?
                                    "child DEX did not pass exact standalone checksum/signature validation" : dex.error;
                            } else {
                                e.dex_deep_state = dex.jni_surface_scan_complete ? "DEX_VALID" : "PARTIAL";
                                e.dex_deep_error = dex.jni_surface_scan_error;
                                for (const auto& method : dex.methods) {
                                    if (!method.defined || (method.access_flags & 0x0100u) == 0) continue;
                                    ++e.dex_native_declaration_count;
                                    if (dex_declarations.size() < 4096) dex_declarations.push_back({e.normalized_name, method});
                                    else { e.dex_deep_state = "PARTIAL"; e.dex_deep_error = "APK JNI native declaration budget exceeded"; }
                                }
                                for (const auto& load : dex.library_loads) {
                                    ++e.dex_load_library_count;
                                    if (dex_loads.size() < 4096) dex_loads.push_back({e.normalized_name, load});
                                    else { e.dex_deep_state = "PARTIAL"; e.dex_deep_error = "APK JNI loadLibrary evidence budget exceeded"; }
                                }
                            }
                        }
                    }
                }
            }
            push_interesting(out, e.name);
        }
        if (e.resources_arsc && !e.directory) {
            out.has_resources_arsc = true;
            const auto prefix = entry_prefix(zip, e, 12, data);
            e.resources_table = resources_table_header(prefix, e.uncompressed_size);
            if (e.resources_table) {
                constexpr std::uint64_t kMaxResourceTableBytes = 32ull * 1024 * 1024;
                const auto full = entry_full_bounded(zip, e, kMaxResourceTableBytes, data);
                if (!full.empty()) {
                    resource_parse = parse_resource_table(full);
                    out.resource_table = resource_parse.info;
                    out.resources_table_valid = out.resource_table.valid;
                } else if (e.uncompressed_size > kMaxResourceTableBytes) {
                    out.resource_table.candidate = true;
                    out.resource_table.error = "resources.arsc exceeds bounded 32 MiB deep-parser limit";
                }
            }
            push_interesting(out, e.name);
        }
        if (e.native_library && !e.directory) {
            ++out.native_library_count;
            if (!e.abi.empty()) abis.insert(e.abi);
            const auto p = entry_prefix(zip, e, 64, data);
            e.native_elf = elf_header(p);
            if (e.native_elf) {
                ++out.validated_native_elf_count;
                if (!e.duplicate_path && e.safe_path && !e.symlink && !e.encrypted && e.supported) {
                    if (e.uncompressed_size > kMaxNativeDeepEntryBytes || e.uncompressed_size > native_deep_budget_left) {
                        e.native_deep_state = "SKIPPED_BUDGET";
                    } else {
                        const auto full = entry_full_bounded(zip, e, kMaxNativeDeepEntryBytes, data);
                        native_deep_budget_left -= e.uncompressed_size;
                        if (full.empty() && e.uncompressed_size != 0) {
                            e.native_deep_state = "FAILED_EXTRACTION";
                            e.native_deep_error = "bounded native ELF full-entry extraction/CRC validation failed";
                        } else {
                            const auto elf = parse_elf(full);
                            if (!elf.valid) {
                                e.native_deep_state = "FAILED_ELF";
                                e.native_deep_error = elf.error;
                            } else {
                                e.native_deep_state = "ELF_VALID";
                                e.native_machine = elf.machine;
                                e.native_elf64 = elf.elf64;
                                e.native_dynamic_state = elf.dynamic.state;
                                e.native_dynamic_error = elf.dynamic.error;
                                e.native_unwind_state = elf.unwind.state;
                                e.native_unwind_error = elf.unwind.error;
                                if (const auto match = apk_abi_matches_elf(e.abi, elf)) {
                                    e.native_abi_consistent_known = true;
                                    e.native_abi_consistent = *match;
                                }
                                if (elf.dynamic.state == "RESOLVED") {
                                    for (const auto& sym : elf.dynamic.symbols) {
                                        e.native_import_count += sym.imported ? 1u : 0u;
                                        e.native_export_count += sym.exported ? 1u : 0u;
                                        if (!e.jni_onload_export && sym.exported && sym.type == 2 && sym.name == "JNI_OnLoad") {
                                            e.jni_onload_export = true;
                                            e.jni_onload_symbol_index = sym.index;
                                            e.jni_onload_symbol_file_offset = sym.entry_file_offset;
                                            e.jni_onload_va = sym.value;
                                            e.jni_onload_file_backed = sym.value_file_backed;
                                            e.jni_onload_file_offset = sym.value_file_offset;
                                        }
                                        if (sym.exported && sym.type == 2 && sym.name.starts_with("Java_")) {
                                            if (native_exports.size() >= 4096) {
                                                e.native_jni_evidence_limited = true;
                                                e.native_jni_evidence_error = "APK JNI native export evidence budget exceeded; additional Java_* exports omitted";
                                                continue;
                                            }
                                            NativeExportEvidence evidence;
                                            evidence.entry = e.normalized_name;
                                            evidence.abi = e.abi;
                                            evidence.symbol = sym;
                                            evidence.abi_consistent = e.native_abi_consistent_known && e.native_abi_consistent;
                                            if (const auto* fde = jni_exact_fde(elf, sym.value)) {
                                                evidence.fde_exact = true;
                                                evidence.fde_end_va = fde->function_end_va;
                                            }
                                            native_exports.push_back(std::move(evidence));
                                        }
                                    }
                                    e.native_relocation_count = elf.dynamic.relocations.size();
                                }
                                if (elf.unwind.state == "RESOLVED") e.native_fde_count = elf.unwind.fdes.size();
                                if (e.native_abi_consistent_known && e.native_abi_consistent) {
                                    auto registrations = recover_register_natives(full, elf, e.normalized_name, e.abi);
                                    if (registrations.limited) {
                                        e.native_jni_evidence_limited = true;
                                        const auto warning = registrations.error.empty() ?
                                            "APK JNI RegisterNatives evidence budget exceeded; omitted evidence" :
                                            registrations.error;
                                        if (e.native_jni_evidence_error.empty()) e.native_jni_evidence_error = warning;
                                        else e.native_jni_evidence_error += "; " + warning;
                                    }
                                    for (auto& registration : registrations.evidence) {
                                        if (native_registrations.size() >= 4096) {
                                            e.native_jni_evidence_limited = true;
                                            e.native_jni_evidence_error = "APK JNI native registration evidence budget exceeded; additional table rows omitted";
                                            break;
                                        }
                                        native_registrations.push_back(std::move(registration));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            push_interesting(out, e.name);
        }
        if (e.unity_il2cpp_metadata_candidate && !e.directory && e.safe_path && !e.symlink && !e.encrypted && e.supported && !e.duplicate_path) {
            ++out.unity_il2cpp_metadata_candidate_count;
            constexpr std::uint64_t kMaxUnityMetadataBytes = 64ull * 1024 * 1024;
            const bool aggregate_budget = out.unity_il2cpp_metadata_parse_bytes <= kMaxUnityMetadataParseBytes &&
                                          e.uncompressed_size <= kMaxUnityMetadataParseBytes - out.unity_il2cpp_metadata_parse_bytes;
            if (out.unity_il2cpp_metadata_parse_count >= kMaxUnityMetadataParses || !aggregate_budget) {
                e.unity_il2cpp_metadata_parse_skipped_budget = true;
                e.unity_il2cpp_metadata_error = "Unity IL2CPP metadata candidate parse deferred by bounded candidate/aggregate-byte budget";
                e.analysis_priority = 0;out.unity_il2cpp_metadata_parse_budget_exhausted = true;
            } else if (e.uncompressed_size > kMaxUnityMetadataBytes) {
                e.unity_il2cpp_metadata_error = "Unity IL2CPP metadata candidate exceeds bounded 64 MiB parser limit";
                e.analysis_priority = 0;
            } else {
                ++out.unity_il2cpp_metadata_parse_count;out.unity_il2cpp_metadata_parse_bytes += e.uncompressed_size;
                const auto full = entry_full_bounded(zip, e, kMaxUnityMetadataBytes, data);
                if (full.empty() && e.uncompressed_size != 0) {
                    e.unity_il2cpp_metadata_error = "Unity IL2CPP metadata candidate extraction/CRC validation failed";
                    e.analysis_priority = 0;
                } else {
                    const auto unity = inspect_unity_il2cpp_metadata(full);
                    e.unity_il2cpp_metadata_valid = unity.valid && unity.il2cpp && unity.metadata_valid;
                    e.unity_il2cpp_metadata_version = unity.metadata_version;
                    e.unity_il2cpp_metadata_layout = unity.metadata_layout;
                    e.unity_il2cpp_metadata_error = unity.error;
                    if (!e.unity_il2cpp_metadata_valid) e.analysis_priority = 0;
                }
            }
            push_interesting(out, e.name);
        }
        if (e.asset && !e.directory) ++out.asset_count;
        if (e.resource && !e.directory) ++out.resource_count;
        if (e.v1_signature_file && !e.directory) out.has_v1_signature_files = true;
        if (e.nested_archive && !e.directory) {
            ++out.nested_archive_count;
            push_interesting(out, e.name);
        }

        if (!e.safe_path) { ++out.unsafe_path_count; push_anomaly(out, "unsafe APK entry path refused: " + e.name); }
        if (e.symlink) { ++out.symlink_entry_count; push_anomaly(out, "APK symlink entry refused: " + e.name); }
        if (e.encrypted) { ++out.encrypted_entry_count; push_anomaly(out, "encrypted APK entry unsupported: " + e.name); }
        else if (!e.supported && !e.directory) { ++out.unsupported_entry_count; push_anomaly(out, "unsupported APK compression method/feature: " + e.name); }
        if (e.duplicate_path) push_anomaly(out, "duplicate normalized APK entry path: " + e.name);
        if (e.dex && !e.dex_magic) { ++out.invalid_dex_entry_count; push_anomaly(out, "classes*.dex entry lacks supported DEX header geometry: " + e.name); }
        if (e.manifest && !e.manifest_binary_xml) push_anomaly(out, "AndroidManifest.xml lacks a bounded binary Android XML root chunk");
        if (e.manifest && e.manifest_binary_xml && !out.manifest.valid && !out.manifest.error.empty()) {
            push_anomaly(out, "AndroidManifest.xml deep parser failed at 0x" + [&](){
                constexpr char h[]="0123456789abcdef"; auto v=out.manifest.error_offset; std::string x;
                do { x.push_back(h[v&0xfu]); v>>=4; } while(v); std::reverse(x.begin(),x.end()); return x;
            }() + ": " + out.manifest.error);
        }
        if (e.resources_arsc && !e.resources_table) push_anomaly(out, "resources.arsc lacks Android resource-table root chunk header");
        if (e.resources_arsc && e.resources_table && !out.resource_table.valid && !out.resource_table.error.empty()) {
            push_anomaly(out, "resources.arsc deep parser failed at 0x" + [&](){
                constexpr char h[]="0123456789abcdef"; auto v=out.resource_table.error_offset; std::string x;
                do { x.push_back(h[v&0xfu]); v>>=4; } while(v); std::reverse(x.begin(),x.end()); return x;
            }() + ": " + out.resource_table.error);
        }
        if (e.native_library && !e.native_elf) { ++out.invalid_native_entry_count; push_anomaly(out, "lib/<abi>/*.so entry lacks validated ELF header geometry: " + e.name); }

        if (out.total_compressed > std::numeric_limits<std::uint64_t>::max() - e.compressed_size ||
            out.total_uncompressed > std::numeric_limits<std::uint64_t>::max() - e.uncompressed_size) {
            out.error = "APK aggregate size overflow";
            return out;
        }
        out.total_compressed += e.compressed_size;
        out.total_uncompressed += e.uncompressed_size;
        if (!e.directory && e.safe_path && e.supported && !e.encrypted && !e.symlink && !e.duplicate_path) {
            if (out.extractable_bytes > std::numeric_limits<std::uint64_t>::max() - e.uncompressed_size) {
                out.error = "APK extractable size overflow";
                return out;
            }
            out.extractable_bytes += e.uncompressed_size;
            ++out.extractable_files;
            if (e.analysis_priority != 0) {
                if (out.analysis_candidate_bytes > std::numeric_limits<std::uint64_t>::max() - e.uncompressed_size) {
                    out.error = "APK analysis-candidate size overflow";
                    return out;
                }
                out.analysis_candidate_bytes += e.uncompressed_size;
                ++out.analysis_candidate_files;
            }
        }
        out.entries.push_back(std::move(e));
    }

    // Godot 2.x Android exports place the binary project config at the canonical
    // assets/engine.cfb path. Parse only that exact structured member after duplicate
    // reconciliation metadata is known; referenced resources are promoted only through
    // exact application/main_scene/autoload + remap/all identities from the validated ECFG.
    {
        ApkEntryInfo* config_entry=nullptr;
        for(auto&e:out.entries)if(e.godot_legacy_engine_config_candidate&&!e.duplicate_path&&e.safe_path&&!e.symlink&&!e.encrypted&&e.supported){
            ++out.godot_legacy_engine_config_candidate_count;if(!config_entry)config_entry=&e;
        }
        if(out.godot_legacy_engine_config_candidate_count==1&&config_entry){
            constexpr std::uint64_t kMaxGodotLegacyConfigBytes=8ull*1024ull*1024ull;
            auto full=entry_full_bounded(zip,*config_entry,kMaxGodotLegacyConfigBytes,data);
            if(full.empty()&&config_entry->uncompressed_size){config_entry->godot_legacy_engine_config_error="canonical assets/engine.cfb extraction/CRC validation failed";config_entry->analysis_priority=0;}
            else{
                auto cfg=parse_godot_legacy_engine_config(full);config_entry->godot_legacy_engine_config_valid=cfg.valid;config_entry->godot_legacy_engine_config_error=cfg.error;
                if(cfg.valid){out.godot_legacy_config=std::move(cfg);out.godot_legacy_engine_config_valid_count=1;}else config_entry->analysis_priority=0;
            }
        }
        if(out.godot_legacy_config.valid){
            std::map<std::string,std::string>remap;for(const auto&r:out.godot_legacy_config.remaps)remap.emplace(r.source,r.target);
            auto resolved=[&](const std::string&source){auto it=remap.find(source);return it==remap.end()?source:it->second;};
            auto apk_asset=[&](const std::string&resource)->std::string{if(resource.rfind("res://",0)!=0)return{};return "assets/"+resource.substr(6);};
            std::set<std::string>main_targets,autoload_targets;
            auto main_asset=apk_asset(resolved(out.godot_legacy_config.main_scene));if(!main_asset.empty())main_targets.insert(main_asset);
            for(const auto&a:out.godot_legacy_config.autoloads){auto target=apk_asset(resolved(a.path));if(!target.empty())autoload_targets.insert(std::move(target));}
            for(auto&e:out.entries){
                if(e.duplicate_path||!e.safe_path||e.symlink||e.encrypted||!e.supported)continue;
                if(main_targets.count(e.normalized_name))e.analysis_priority=std::max<std::uint8_t>(e.analysis_priority,89);
                if(autoload_targets.count(e.normalized_name))e.analysis_priority=std::max<std::uint8_t>(e.analysis_priority,88);
            }
        }
        // Priority can change after the complete config/remap table is parsed. Recompute
        // candidate accounting from final admitted entries rather than incrementally guessing.
        out.analysis_candidate_bytes=0;out.analysis_candidate_files=0;
        for(const auto&e:out.entries)if(!e.directory&&e.safe_path&&e.supported&&!e.encrypted&&!e.symlink&&!e.duplicate_path&&e.analysis_priority){
            if(out.analysis_candidate_bytes>std::numeric_limits<std::uint64_t>::max()-e.uncompressed_size){out.error="APK analysis-candidate size overflow";return out;}
            out.analysis_candidate_bytes+=e.uncompressed_size;++out.analysis_candidate_files;
        }
    }

    // Reconcile critical Android paths only after the complete central directory is known.
    // A later case/backslash-normalized duplicate invalidates both spellings for confirmation.
    out.validated_dex_count = 0;
    out.validated_native_elf_count = 0;
    out.deep_native_elf_count = 0;
    out.native_dynamic_resolved_count = 0;
    out.native_unwind_resolved_count = 0;
    out.native_jni_onload_count = 0;
    out.native_abi_mismatch_count = 0;
    out.native_deep_skipped_budget_count = 0;
    out.native_import_count = 0;
    out.native_export_count = 0;
    out.native_relocation_count = 0;
    out.native_fde_count = 0;
    std::size_t manifest_entries = 0, resources_entries = 0;
    bool unique_manifest_valid = false, unique_resources_valid = false;
    out.unity_il2cpp_metadata_valid_count = 0;
    out.hermes_integrity_valid_count = 0;
    out.hermes_supported_epoch_count = 0;
    out.hermes_parse_complete_count = 0;
    for (const auto& e : out.entries) {
        if(e.unity_il2cpp_metadata_valid&&!e.duplicate_path)++out.unity_il2cpp_metadata_valid_count;
        if (!e.duplicate_path && e.hermes_integrity_valid) {
            ++out.hermes_integrity_valid_count;
            if (e.hermes_supported_epoch) ++out.hermes_supported_epoch_count;
            if (e.hermes_parse_complete) ++out.hermes_parse_complete_count;
        }
        const auto low = lower_ascii(e.normalized_name);
        if (low == "androidmanifest.xml") {
            ++manifest_entries;
            if (e.duplicate_path) out.manifest_path_ambiguous = true;
            else unique_manifest_valid = e.manifest && e.manifest_binary_xml && out.manifest.valid;
        }
        if (low == "resources.arsc") {
            ++resources_entries;
            if (e.duplicate_path) out.resources_path_ambiguous = true;
            else unique_resources_valid = e.resources_arsc && e.resources_table && out.resource_table.valid;
        }
        if (e.dex) {
            if (e.duplicate_path) out.dex_path_ambiguous = true;
            else if (e.dex_magic) ++out.validated_dex_count;
        }
        if (e.native_library && !e.duplicate_path && e.native_elf) {
            ++out.validated_native_elf_count;
            if (e.native_deep_state == "ELF_VALID") {
                ++out.deep_native_elf_count;
                if (e.native_dynamic_state == "RESOLVED") ++out.native_dynamic_resolved_count;
                if (e.native_unwind_state == "RESOLVED") ++out.native_unwind_resolved_count;
                if (e.jni_onload_export) ++out.native_jni_onload_count;
                if (e.native_abi_consistent_known && !e.native_abi_consistent) ++out.native_abi_mismatch_count;
                out.native_import_count += e.native_import_count;
                out.native_export_count += e.native_export_count;
                out.native_relocation_count += e.native_relocation_count;
                out.native_fde_count += e.native_fde_count;
            } else if (e.native_deep_state == "SKIPPED_BUDGET") ++out.native_deep_skipped_budget_count;
        }
    }
    if (manifest_entries != 1) out.manifest_path_ambiguous = manifest_entries > 1;
    if (resources_entries > 1) out.resources_path_ambiguous = true;
    out.has_manifest = manifest_entries != 0;
    out.manifest_binary_xml = unique_manifest_valid;
    out.resources_table_valid = unique_resources_valid;
    if (out.manifest_path_ambiguous) {
        push_anomaly(out, "duplicate/ambiguous root AndroidManifest.xml path; manifest evidence excluded from confirmation");
        out.manifest.valid = false;
        out.manifest.parse_complete = false;
        out.manifest.error = "ambiguous duplicate AndroidManifest.xml path";
    }
    if (out.resources_path_ambiguous) {
        push_anomaly(out, "duplicate/ambiguous resources.arsc path; resource-table evidence excluded from confirmation");
        out.resource_table.valid = false;
        out.resource_table.parse_complete = false;
        out.resource_table.error = "ambiguous duplicate resources.arsc path";
    }
    if (out.dex_path_ambiguous) {
        push_anomaly(out, "one or more classes*.dex paths collide after cross-platform normalization; colliding DEX entries excluded from confirmation");
    }
    if (out.native_abi_mismatch_count) {
        push_anomaly(out, std::to_string(out.native_abi_mismatch_count) + " native ELF entries disagree with their lib/<abi>/ path architecture; APK confirmation is unchanged");
    }
    out.native_abis.assign(abis.begin(), abis.end());
    {
        constexpr std::size_t kMaxRelations = 4096;
        bool partial = false;
        auto mark_partial = [&](std::string message) {
            partial = true;
            out.jni_relations_limited = true;
            if (out.jni_relations_error.empty()) out.jni_relations_error = std::move(message);
        };
        auto add_relation = [&](ApkJniRelation relation) {
            if (out.jni_relations.size() >= kMaxRelations) {
                mark_partial("APK JNI relation budget exceeded");
                return;
            }
            relation.index = static_cast<std::uint32_t>(out.jni_relations.size());
            out.jni_relations.push_back(std::move(relation));
        };
        auto eligible_dex_entry = [&](std::string_view name) {
            return std::ranges::any_of(out.entries, [&](const ApkEntryInfo& entry) {
                return entry.normalized_name == name && entry.dex && !entry.duplicate_path && entry.dex_magic &&
                       (entry.dex_deep_state == "DEX_VALID" || entry.dex_deep_state == "PARTIAL");
            });
        };
        auto eligible_native_entry = [&](std::string_view name) {
            return std::ranges::any_of(out.entries, [&](const ApkEntryInfo& entry) {
                return entry.normalized_name == name && entry.native_library && !entry.duplicate_path &&
                       entry.native_elf && entry.native_deep_state == "ELF_VALID";
            });
        };
        for (const auto& entry : out.entries) {
            if (entry.duplicate_path && (entry.dex || entry.native_library))
                mark_partial("duplicate APK DEX/native paths were excluded from JNI relation evidence");
            if (!entry.duplicate_path && entry.dex_deep_state == "DEX_VALID") ++out.dex_deep_resolved_count;
            else if (!entry.duplicate_path && (entry.dex_deep_state == "PARTIAL" || entry.dex_deep_state == "SKIPPED_BUDGET" ||
                      entry.dex_deep_state == "FAILED_EXTRACTION" || entry.dex_deep_state == "FAILED_DEX")) {
                ++out.dex_deep_partial_count;
                mark_partial(entry.dex_deep_error.empty() ? "one or more APK child DEX surfaces were not fully analyzed" : entry.dex_deep_error);
            }
            if (entry.native_library && !entry.duplicate_path && entry.native_elf) {
                ++out.jni_packaged_count;
                ApkJniRelation relation;
                relation.state = "PACKAGED";
                relation.evidence_level = "J0_PACKAGED";
                relation.native_entry = entry.normalized_name;
                relation.abi = entry.abi;
                relation.packaged = true;
                relation.abi_consistent = entry.native_abi_consistent_known && entry.native_abi_consistent;
                relation.detail = "validated lib/<abi> ELF member; packaging does not prove loading or execution";
                add_relation(std::move(relation));
            }
            if (entry.native_library && !entry.duplicate_path && entry.native_elf &&
                entry.native_deep_state == "SKIPPED_BUDGET")
                mark_partial("one or more APK child native ELF entries exceeded the deep-analysis budget");
            else if (entry.native_library && !entry.duplicate_path && entry.native_elf &&
                     (entry.native_deep_state == "FAILED_EXTRACTION" || entry.native_deep_state == "FAILED_ELF"))
                mark_partial(entry.native_deep_error.empty() ?
                    "one or more APK child native ELF surfaces were not fully analyzed" : entry.native_deep_error);
            if (entry.native_library && !entry.duplicate_path && entry.native_elf &&
                entry.native_deep_state == "ELF_VALID" &&
                (entry.native_dynamic_state == "FAILED" || entry.native_dynamic_state == "PARTIAL" ||
                 entry.native_dynamic_state == "UNSUPPORTED"))
                mark_partial(entry.native_dynamic_error.empty() ?
                    "one or more APK child native ELF dynamic surfaces were not fully analyzed" :
                    entry.native_dynamic_error);
            if (entry.native_library && !entry.duplicate_path && entry.native_elf &&
                entry.native_deep_state == "ELF_VALID" &&
                (entry.native_unwind_state == "FAILED" || entry.native_unwind_state == "PARTIAL" ||
                 entry.native_unwind_state == "UNSUPPORTED"))
                mark_partial(entry.native_unwind_error.empty() ?
                    "one or more APK child native ELF unwind surfaces were not fully analyzed" :
                    entry.native_unwind_error);
            if (entry.native_library && !entry.duplicate_path && entry.native_elf &&
                entry.native_jni_evidence_limited)
                mark_partial(entry.native_jni_evidence_error.empty() ?
                    "one or more APK child native JNI evidence surfaces were truncated" : entry.native_jni_evidence_error);
        }
        auto sane_library_name = [](std::string_view name) {
            if (name.empty() || name.size() > 255) return false;
            for (const unsigned char c : name) if (c < 0x21 || c > 0x7e || c == '/' || c == '\\') return false;
            return true;
        };
        std::set<std::string> referenced_entries;
        for (const auto& load : dex_loads) {
            if (!eligible_dex_entry(load.entry)) continue;
            if (!sane_library_name(load.load.library_name)) continue;
            for (const auto& entry : out.entries) {
                const auto packaged_name = apk_load_library_name(entry.normalized_name);
                if (!packaged_name || *packaged_name != load.load.library_name || !entry.native_library ||
                    entry.duplicate_path || !entry.native_elf) continue;
                referenced_entries.insert(entry.normalized_name);
                ++out.jni_referenced_count;
                ApkJniRelation relation;
                relation.state = "REFERENCED";
                relation.evidence_level = "J1_STATIC_LOAD_REFERENCE";
                relation.dex_entry = load.entry;
                relation.native_entry = entry.normalized_name;
                relation.abi = entry.abi;
                relation.library_name = load.load.library_name;
                relation.packaged = true;
                relation.load_library_referenced = true;
                relation.abi_consistent = entry.native_abi_consistent_known && entry.native_abi_consistent;
                relation.dex_load_instruction_offset = load.load.instruction_file_offset;
                relation.detail = "reachable DEX const-string immediately supplies java.lang.System.loadLibrary; application startup reachability and actual loading are not inferred";
                add_relation(std::move(relation));
            }
        }
        std::map<std::string, std::size_t> overloads;
        for (const auto& declaration : dex_declarations)
            if (eligible_dex_entry(declaration.entry))
                ++overloads[declaration.method.owner_descriptor + "\n" + declaration.method.name];
        for (const auto& declaration : dex_declarations) {
            if (!eligible_dex_entry(declaration.entry)) continue;
            ++out.jni_declared_count;
            ApkJniRelation declared;
            declared.state = "DECLARED";
            declared.evidence_level = "J2_DEX_NATIVE_DECLARATION";
            declared.dex_entry = declaration.entry;
            declared.class_descriptor = declaration.method.owner_descriptor;
            declared.method_name = declaration.method.name;
            declared.method_descriptor = declaration.method.descriptor;
            declared.native_declared = true;
            declared.dex_method_index = declaration.method.index;
            declared.detail = "strictly parsed defined DEX method carries ACC_NATIVE; no native implementation is inferred";
            add_relation(std::move(declared));
            const auto names = jni_symbol_names(declaration.method);
            if (!names) mark_partial("non-ASCII JNI name mangling is outside the bounded APK JNI relation plane");
            else {
                const bool overloaded = overloads[declaration.method.owner_descriptor + "\n" + declaration.method.name] > 1;
                for (const auto& exported : native_exports) {
                    if (!eligible_native_entry(exported.entry) || !exported.abi_consistent || (exported.symbol.name != names->second &&
                        (overloaded || exported.symbol.name != names->first))) continue;
                    ++out.jni_exported_count;
                    ApkJniRelation relation;
                    relation.state = "EXPORTED";
                    relation.evidence_level = "J3_JNI_MANGLED_EXPORT";
                    relation.dex_entry = declaration.entry;
                    relation.native_entry = exported.entry;
                    relation.abi = exported.abi;
                    relation.class_descriptor = declaration.method.owner_descriptor;
                    relation.method_name = declaration.method.name;
                    relation.method_descriptor = declaration.method.descriptor;
                    relation.jni_symbol = exported.symbol.name;
                    relation.packaged = true;
                    relation.load_library_referenced = referenced_entries.contains(exported.entry);
                    relation.native_declared = true;
                    relation.exported = true;
                    relation.abi_consistent = true;
                    relation.fde_boundary_confirmed = exported.fde_exact;
                    relation.dex_method_index = declaration.method.index;
                    relation.elf_symbol_index = exported.symbol.index;
                    relation.function_va = exported.symbol.value;
                    relation.function_file_offset = exported.symbol.value_file_offset;
                    relation.function_end_va = exported.fde_end_va;
                    relation.detail = exported.fde_exact ?
                        "ABI-consistent dynamic JNI export matches the exact DEX native declaration and an exact file-backed FDE function boundary" :
                        "ABI-consistent dynamic JNI export matches the exact DEX native declaration; an exact FDE boundary was not available";
                    add_relation(std::move(relation));
                }
            }
            for (const auto& registration : native_registrations) {
                if (!eligible_native_entry(registration.entry) ||
                    registration.class_descriptor != declaration.method.owner_descriptor ||
                    registration.method_name != declaration.method.name ||
                    registration.method_descriptor != declaration.method.descriptor || !registration.fde_exact) continue;
                ++out.jni_registration_confirmed_count;
                ApkJniRelation relation;
                relation.state = "REGISTRATION_CONFIRMED";
                relation.evidence_level = "J4_REGISTERNATIVES_TABLE_FDE";
                relation.dex_entry = declaration.entry;
                relation.native_entry = registration.entry;
                relation.abi = registration.abi;
                relation.class_descriptor = registration.class_descriptor;
                relation.method_name = registration.method_name;
                relation.method_descriptor = registration.method_descriptor;
                relation.packaged = true;
                relation.load_library_referenced = referenced_entries.contains(registration.entry);
                relation.native_declared = true;
                relation.registration_confirmed = true;
                relation.abi_consistent = true;
                relation.fde_boundary_confirmed = true;
                relation.dex_method_index = declaration.method.index;
                relation.function_va = registration.function_va;
                relation.function_file_offset = registration.function_file_offset;
                relation.function_end_va = registration.function_end_va;
                relation.detail = registration.abi == "arm64-v8a" ? "AArch64" : "x86-64";
                relation.detail += " JNI_OnLoad exact FDE contains a bounded JNIEnv RegisterNatives call with exact FindClass literal, RELA-backed JNINativeMethod row, matching DEX declaration, and exact target FDE; invocation is not observed";
                add_relation(std::move(relation));
            }
        }
        if (partial) out.jni_relations_state = "PARTIAL";
        else if (!out.jni_relations.empty()) out.jni_relations_state = "RESOLVED";
        else out.jni_relations_state = "NOT_PRESENT";
    }
    resolve_manifest_resources(out.manifest, resource_parse);
    out.signing_block = parse_signing_block(data, out.central_directory_offset);
    for (const auto& a : out.signing_block.anomalies) push_anomaly(out, "APK Signing Block: " + a);
    if (out.signing_block.present && !out.signing_block.valid) {
        push_anomaly(out, "APK Signing Block is structurally malformed: " + out.signing_block.error);
    }
    out.candidate = out.has_manifest || out.dex_count != 0 || out.has_resources_arsc || out.native_library_count != 0;
    const bool payload = out.validated_dex_count != 0 || out.resources_table_valid || out.validated_native_elf_count != 0;
    out.valid = out.zip_valid && out.has_manifest && out.manifest_binary_xml && out.manifest.valid && payload;
    if (out.candidate && !out.valid && out.error.empty()) {
        if (!out.has_manifest) out.error = "APK structure lacks root AndroidManifest.xml";
        else if (out.manifest_path_ambiguous) out.error = "APK has ambiguous duplicate AndroidManifest.xml paths";
        else if (!out.manifest_binary_xml) out.error = "AndroidManifest.xml is not structurally binary Android XML";
        else if (!out.manifest.valid) out.error = out.manifest.error.empty() ? "AndroidManifest.xml failed deep binary XML validation" : out.manifest.error;
        else out.error = "APK lacks an independently validated DEX/resource-table/native-ELF payload";
    }
    {
        auto& im = out.implicit_exec;
        bool partial = false;
        std::string partial_error;
        constexpr std::size_t kMaxFacts = 4096;
        auto add = [&](ImplicitExecutionFact fact) {
            if (im.facts.size() >= kMaxFacts) {
                im.analysis_limited = true;
                partial = true;
                if (partial_error.empty()) partial_error = "APK native implicit execution fact budget exceeded";
                return;
            }
            fact.index = static_cast<std::uint32_t>(im.facts.size());
            if (fact.priority == "HIGH") ++im.high_priority_count;
            else if (fact.priority == "REVIEW") ++im.review_count;
            else ++im.informational_count;
            if (fact.evidence_state == "UNRESOLVED_RUNTIME_SEMANTICS") ++im.unresolved_runtime_semantics;
            im.facts.push_back(std::move(fact));
        };
        for (const auto& e : out.entries) {
            if (!e.native_library || e.duplicate_path || !e.native_elf || e.native_deep_state != "ELF_VALID" ||
                e.native_dynamic_state != "RESOLVED" || !e.jni_onload_export) continue;
            ImplicitExecutionFact f;
            f.format = "ELF (APK child)";
            f.ecosystem = "Android/JNI";
            f.phase = "module_load";
            f.trigger = "ANDROID_JNI_ONLOAD_EXPORT";
            f.relation = "implicit_callback";
            f.source_kind = "APK_CHILD_ELF_DYNSYM";
            f.source_index = e.jni_onload_symbol_index;
            f.source_file_backed = true;
            f.source_file_offset = e.jni_onload_symbol_file_offset;
            f.source_size = e.native_elf64 ? 24 : 16;
            f.target_kind = "jni_onload_function_va";
            f.target_va = e.jni_onload_va;
            f.target_file_backed = e.jni_onload_file_backed;
            f.target_file_offset = e.jni_onload_file_offset;
            f.target_name = e.normalized_name + "!JNI_OnLoad";
            f.evidence_state = e.jni_onload_file_backed ? "EXACT" : "UNRESOLVED_RUNTIME_SEMANTICS";
            f.mutability = "IMMUTABLE_CHILD_ELF_DYNSYM";
            f.execution_condition = "Android VM invokes exported JNI_OnLoad when this specific native library is actually loaded through JNI native-library loading semantics; APK packaging alone does not prove that this library is loaded on the observed application path";
            f.priority = "INFORMATIONAL";
            f.priority_reason = "JNI_OnLoad is an ordinary conditional native module-load callback; exact export presence is not evidence that the APK executes or loads the library";
            std::ostringstream detail;
            detail << "child=" << e.normalized_name << ";offset_basis=child_elf:" << e.normalized_name
                   << ";abi=" << e.abi << ";abi_consistent="
                   << (e.native_abi_consistent_known ? (e.native_abi_consistent ? "true" : "false") : "unknown")
                   << ";dynsym_file_offset=0x" << std::hex << e.jni_onload_symbol_file_offset
                   << ";function_file_offset=";
            if (e.jni_onload_file_backed) detail << "0x" << std::hex << e.jni_onload_file_offset;
            else detail << "unmapped";
            f.detail = detail.str();
            if (!e.jni_onload_file_backed) {
                partial = true;
                if (partial_error.empty()) partial_error = "one or more APK child JNI_OnLoad exports are not directly file-backed";
            }
            add(std::move(f));
        }
        if (im.facts.empty()) im.state = partial ? "PARTIAL" : "NOT_PRESENT";
        else im.state = partial ? "PARTIAL" : "RESOLVED";
        if (partial) im.error = partial_error;
    }
    return out;
}

Finding apk_finding(const ApkInfo& info) {
    Finding f;
    f.kind = "container";
    f.family = "Android APK";
    f.variant = "APK/ZIP";
    if (!info.valid) {
        f.state = "FAILED";
        if (!info.error.empty()) f.negative_evidence.push_back(info.error);
        return f;
    }
    f.state = "CONFIRMED";
    f.evidence.push_back("ZIP central directory and local-header geometry validated");
    f.evidence.push_back("root AndroidManifest.xml passed bounded binary Android XML validation");
    if (info.validated_dex_count) f.evidence.push_back("classes*.dex entries passed DEX header/table geometry routing checks");
    if (info.resources_table_valid) f.evidence.push_back("resources.arsc passed package/typeSpec/type/default-scalar structural validation");
    if (info.validated_native_elf_count) f.evidence.push_back("lib/<abi>/*.so entries passed bounded ELF header validation");
    if (info.jni_referenced_count) f.evidence.push_back("reachable DEX const-string/loadLibrary call sites were related to exact packaged lib/<abi>/libNAME.so members; actual loading was not observed");
    if (info.jni_declared_count) f.evidence.push_back("strict DEX method definitions contain ACC_NATIVE declarations with raw owner/method descriptors");
    if (info.jni_exported_count) f.evidence.push_back("ABI-consistent JNI-mangled dynamic exports were matched to exact DEX native declarations; invocation was not observed");
    if (info.jni_registration_confirmed_count) f.evidence.push_back("bounded x86-64/AArch64 JNI_OnLoad analysis recovered RELA-backed FindClass/RegisterNatives table rows and exact target FDE boundaries; invocation was not observed");
    if (info.signing_block.present && info.signing_block.valid) {
        f.evidence.push_back("APK Signing Block framing and ID-value pair geometry validated; cryptographic signature verification was not performed");
    }
    f.fields["entries"] = std::to_string(info.entry_count);
    f.fields["dex_entries"] = std::to_string(info.dex_count);
    f.fields["validated_dex_entries"] = std::to_string(info.validated_dex_count);
    f.fields["native_libraries"] = std::to_string(info.native_library_count);
    f.fields["validated_native_elf"] = std::to_string(info.validated_native_elf_count);
    f.fields["deep_native_elf"] = std::to_string(info.deep_native_elf_count);
    f.fields["native_dynamic_resolved"] = std::to_string(info.native_dynamic_resolved_count);
    f.fields["native_unwind_resolved"] = std::to_string(info.native_unwind_resolved_count);
    f.fields["native_jni_onload"] = std::to_string(info.native_jni_onload_count);
    f.fields["native_abi_mismatch"] = std::to_string(info.native_abi_mismatch_count);
    f.fields["native_deep_skipped_budget"] = std::to_string(info.native_deep_skipped_budget_count);
    f.fields["dex_deep_resolved"] = std::to_string(info.dex_deep_resolved_count);
    f.fields["dex_deep_partial"] = std::to_string(info.dex_deep_partial_count);
    f.fields["jni_relations_state"] = info.jni_relations_state;
    f.fields["jni_packaged"] = std::to_string(info.jni_packaged_count);
    f.fields["jni_referenced"] = std::to_string(info.jni_referenced_count);
    f.fields["jni_declared"] = std::to_string(info.jni_declared_count);
    f.fields["jni_exported"] = std::to_string(info.jni_exported_count);
    f.fields["jni_registration_confirmed"] = std::to_string(info.jni_registration_confirmed_count);
    f.fields["jni_static_only"] = "true";
    if (!info.jni_relations_error.empty()) f.negative_evidence.push_back(info.jni_relations_error);
    f.fields["godot_legacy_engine_config_candidates"] = std::to_string(info.godot_legacy_engine_config_candidate_count);
    f.fields["godot_legacy_engine_config_valid"] = std::to_string(info.godot_legacy_engine_config_valid_count);
    f.fields["unity_il2cpp_metadata_candidates"] = std::to_string(info.unity_il2cpp_metadata_candidate_count);
    f.fields["unity_il2cpp_metadata_valid"] = std::to_string(info.unity_il2cpp_metadata_valid_count);
    f.fields["unity_il2cpp_metadata_parsed"] = std::to_string(info.unity_il2cpp_metadata_parse_count);
    f.fields["unity_il2cpp_metadata_parse_bytes"] = std::to_string(info.unity_il2cpp_metadata_parse_bytes);
    f.fields["unity_il2cpp_metadata_parse_budget_exhausted"] = info.unity_il2cpp_metadata_parse_budget_exhausted ? "true" : "false";
    f.fields["native_imports"] = std::to_string(info.native_import_count);
    f.fields["hermes_probe_entries"] = std::to_string(info.hermes_probe_entry_count);
    f.fields["hermes_magic_entries"] = std::to_string(info.hermes_magic_count);
    f.fields["hermes_integrity_valid_entries"] = std::to_string(info.hermes_integrity_valid_count);
    f.fields["hermes_supported_epoch_entries"] = std::to_string(info.hermes_supported_epoch_count);
    f.fields["hermes_parse_complete_entries"] = std::to_string(info.hermes_parse_complete_count);
    f.fields["hermes_integrity_failures"] = std::to_string(info.hermes_integrity_failure_count);
    f.fields["hermes_probe_skipped_budget"] = std::to_string(info.hermes_probe_skipped_budget_count);
    f.fields["hermes_probe_budget_exhausted"] = info.hermes_probe_budget_exhausted ? "true" : "false";
    f.fields["hermes_probe_validated_bytes"] = std::to_string(info.hermes_probe_validated_bytes);
    f.fields["hermes_probe_entry_limit"] = std::to_string(kMaxHermesProbeEntries);
    f.fields["hermes_probe_byte_limit"] = std::to_string(kMaxHermesProbeBytes);
    if (info.hermes_integrity_valid_count) f.evidence.push_back("ZIP members with exact Hermes HBC magic passed bounded decompression, CRC32, size, and SHA-256 identity checks");
    f.fields["native_exports"] = std::to_string(info.native_export_count);
    f.fields["native_relocations"] = std::to_string(info.native_relocation_count);
    f.fields["native_fdes"] = std::to_string(info.native_fde_count);
    {
        std::ostringstream samples;std::size_t shown=0;
        for (const auto& e : info.entries) {
            if (!e.jni_onload_export || e.duplicate_path || shown >= 8) continue;
            if (shown++) samples << " | ";
            samples << e.normalized_name << "@elf-va=0x" << std::hex << e.jni_onload_va << std::dec;
            if (e.jni_onload_file_backed) samples << ",elf-file+0x" << std::hex << e.jni_onload_file_offset << std::dec;
        }
        if (shown) f.fields["native_jni_onload_samples"] = samples.str();
    }
    f.fields["assets"] = std::to_string(info.asset_count);
    f.fields["resources"] = std::to_string(info.resource_count);
    f.fields["nested_archives"] = std::to_string(info.nested_archive_count);
    f.fields["uncompressed_bytes"] = std::to_string(info.total_uncompressed);
    f.fields["compressed_bytes"] = std::to_string(info.total_compressed);
    f.fields["offset_space"] = "current_input_file";
    if (!info.manifest.package_name.empty()) f.fields["package"] = info.manifest.package_name;
    if (!info.manifest.version_name.empty()) f.fields["version_name"] = info.manifest.version_name;
    if (info.manifest.version_code_known) f.fields["version_code"] = std::to_string(info.manifest.version_code);
    if (info.manifest.min_sdk_known) f.fields["min_sdk"] = std::to_string(info.manifest.min_sdk);
    if (info.manifest.target_sdk_known) f.fields["target_sdk"] = std::to_string(info.manifest.target_sdk);
    if (info.manifest.debuggable_known) f.fields["debuggable"] = info.manifest.debuggable ? "true" : "false";
    else if (info.manifest.debuggable_reference) {
        std::ostringstream o; o << "@0x" << std::hex << info.manifest.debuggable_reference_id;
        f.fields["debuggable_reference"] = o.str();
    }
    f.fields["permissions"] = std::to_string(info.manifest.permissions.size());
    f.fields["components"] = std::to_string(info.manifest.components.size());
    f.fields["resource_packages"] = std::to_string(info.resource_table.parsed_package_count);
    f.fields["resource_default_scalars"] = std::to_string(info.resource_table.default_scalar_count);
    f.fields["unsafe_paths"] = std::to_string(info.unsafe_path_count);
    f.fields["path_collision_entries"] = std::to_string(info.duplicate_path_entry_count);
    f.fields["encrypted_entries"] = std::to_string(info.encrypted_entry_count);
    f.fields["unsupported_entries"] = std::to_string(info.unsupported_entry_count);
    f.fields["apk_signing_block_present"] = info.signing_block.present ? "true" : "false";
    f.fields["apk_signing_block_valid"] = info.signing_block.valid ? "true" : "false";
    f.fields["apk_signing_crypto_verification"] = "NOT_PERFORMED";
    if (info.has_v1_signature_files) f.fields["v1_signature_files_present"] = "true";
    if (info.signing_block.has_v2) f.fields["signing_scheme_v2_block"] = "present";
    if (info.signing_block.has_v3) f.fields["signing_scheme_v3_block"] = "present";
    if (info.signing_block.has_v31) f.fields["signing_scheme_v31_block"] = "present";
    if (info.signing_block.has_v32) f.fields["signing_scheme_v32_block"] = "present";
    for (const auto& a : info.anomalies) f.negative_evidence.push_back(a);
    if (info.anomaly_samples_truncated) f.negative_evidence.push_back("additional APK anomaly samples omitted; use count fields and entry inventory for scope");
    f.suggested_actions = {
        "extract:apk-analysis-artifacts",
        "inspect classes*.dex and native libraries before low-value resource bulk",
        "review manifest permissions/components/debuggable state and unresolved resource references",
        "treat APK Signing Block IDs as inventory only unless a separate cryptographic verifier confirms signatures"
    };
    return f;
}

ApkExtractResult extract_apk(std::span<const std::uint8_t> data,
                             const ApkInfo& info,
                             const std::filesystem::path& output_dir,
                             std::uint64_t max_output_bytes,
                             std::uint64_t max_files,
                             bool analysis_only) {
    ApkExtractResult out;
    out.output_dir = output_dir;
    out.analysis_only = analysis_only;
    const bool hermes_only_zip = analysis_only && !info.valid && info.zip_valid && info.hermes_integrity_valid_count != 0;
    if (!info.valid && !hermes_only_zip) {
        out.error = "APK/ZIP structure has no validated analysis-child route";
        return out;
    }
    std::vector<const ApkEntryInfo*> selected;
    if (!analysis_only) {
        if (info.extractable_bytes > max_output_bytes || info.extractable_files > max_files) {
            out.budget_exhausted = true;
            out.error = "APK declared output exceeds extraction budget";
            return out;
        }
        for (const auto& e : info.entries) {
            if (!e.directory && e.safe_path && !e.symlink && !e.encrypted && e.supported && !e.duplicate_path) selected.push_back(&e);
        }
    } else {
        std::vector<const ApkEntryInfo*> candidates;
        for (const auto& e : info.entries) {
            const bool selected_route = hermes_only_zip ? e.hermes_integrity_valid : e.analysis_priority != 0;
            if (!e.directory && e.safe_path && !e.symlink && !e.encrypted && e.supported && !e.duplicate_path && selected_route) {
                candidates.push_back(&e);
            }
        }
        std::sort(candidates.begin(), candidates.end(), [](const auto* a, const auto* b) {
            if (a->analysis_priority != b->analysis_priority) return a->analysis_priority > b->analysis_priority;
            return a->index < b->index;
        });
        std::uint64_t chosen_bytes = 0;
        for (const auto* e : candidates) {
            if (selected.size() >= max_files || e->uncompressed_size > max_output_bytes - chosen_bytes) {
                out.budget_exhausted = true;
                continue;
            }
            selected.push_back(e);
            chosen_bytes += e->uncompressed_size;
        }
        if (selected.size() != candidates.size()) {
            out.warnings.push_back("APK analysis-only extraction omitted lower-priority entries due to recursive byte/file budget");
        }
        if (selected.empty() && !candidates.empty()) {
            out.error = "APK analysis-only extraction budget cannot admit any candidate";
            return out;
        }
    }
    mz_zip_archive zip{};
    ZipCloser close{&zip};
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0)) {
        out.error = "cannot initialize APK ZIP reader: " + miniz_error(zip);
        return out;
    }
    std::error_code ec;
    std::filesystem::remove_all(output_dir, ec);
    ec.clear();
    if (!std::filesystem::create_directories(output_dir, ec) && ec) {
        out.error = "cannot create APK extraction directory: " + ec.message();
        return out;
    }
    constexpr std::size_t kChunk = 1u << 20;
    std::vector<std::uint8_t> buffer(kChunk);
    if (!analysis_only) {
        for (const auto& e : info.entries) {
            if (e.directory) continue;
            if (!e.safe_path) out.warnings.push_back("skipped unsafe path: " + e.name);
            else if (e.symlink) out.warnings.push_back("skipped symlink: " + e.name);
            else if (e.duplicate_path) out.warnings.push_back("skipped duplicate path: " + e.name);
            else if (e.encrypted || !e.supported) out.warnings.push_back("skipped unsupported/encrypted entry: " + e.name);
        }
    }
    for (const auto* ep : selected) {
        const auto& e = *ep;
        std::string normalized;
        if (!safe_relative_name(e.name, false, normalized)) {
            out.error = "validated APK path failed extraction-time normalization: " + e.name;
            break;
        }
        const auto dest = output_dir / std::filesystem::path(normalized);
        if (!std::filesystem::create_directories(dest.parent_path(), ec) && ec) {
            out.error = "cannot create APK output parent: " + ec.message();
            break;
        }
        ec.clear();
        auto part = dest;
        part += ".auto-refirst-part";
        std::filesystem::remove(part, ec);
        ec.clear();
        std::ofstream f(part, std::ios::binary | std::ios::trunc);
        if (!f) {
            out.error = "cannot create APK output file: " + part.string();
            break;
        }
        auto* it = mz_zip_reader_extract_iter_new(&zip, e.index, 0);
        if (!it) {
            out.error = "cannot start APK entry extraction: " + e.name + ": " + miniz_error(zip);
            f.close(); std::filesystem::remove(part, ec);
            break;
        }
        std::uint64_t written = 0;
        bool stream_ok = true;
        while (written < e.uncompressed_size) {
            const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), e.uncompressed_size - written));
            const auto got = mz_zip_reader_extract_iter_read(it, buffer.data(), want);
            if (got == 0) { stream_ok = false; break; }
            f.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(got));
            if (!f) { stream_ok = false; break; }
            written += got;
        }
        const bool crc_ok = mz_zip_reader_extract_iter_free(it) != 0;
        f.close();
        if (!stream_ok || !crc_ok || written != e.uncompressed_size) {
            std::filesystem::remove(part, ec);
            out.error = "APK entry decompression/CRC failed: " + e.name;
            break;
        }
        std::filesystem::remove(dest, ec);
        ec.clear();
        std::filesystem::rename(part, dest, ec);
        if (ec) {
            std::filesystem::remove(part, ec);
            out.error = "cannot finalize APK output file: " + dest.string();
            break;
        }
        out.files.push_back(dest);
        ++out.file_count;
        out.output_bytes += written;
    }
    if (!out.error.empty()) {
        std::filesystem::remove_all(output_dir, ec);
        out.files.clear();
        out.file_count = 0;
        out.output_bytes = 0;
        return out;
    }
    out.success = true;
    return out;
}

}  // namespace prts
