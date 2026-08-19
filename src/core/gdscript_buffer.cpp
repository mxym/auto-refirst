#include "prts/gdscript.hpp"
#include "prts/sha256.hpp"
#include "prts/zstd_wrap.h"

#include <algorithm>
#include <cstring>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <vector>

namespace prts {
namespace {
constexpr std::uint32_t kTokenizerVersion100 = 100;
constexpr std::uint32_t kTokenizerVersion101 = 101;
constexpr std::uint32_t kTokenizerTkMax100 = 99;
constexpr std::uint32_t kTokenizerTkMax101 = 100;
constexpr std::uint32_t kVariantMax = 39;
constexpr std::size_t kMaxTableCount = 1u << 20;
constexpr std::size_t kMaxVariantDepth = 128;
constexpr std::size_t kMaxVariantNodes = 1u << 20;

struct TokenizerProfile {
    std::uint32_t version = 0;
    std::size_t payload_header_size = 0;
    std::size_t token_count_offset = 0;
    std::uint32_t token_max = 0;
    std::uint32_t error_token = 0;
};

std::optional<TokenizerProfile> tokenizer_profile(std::uint32_t version) {
    if (version == kTokenizerVersion100) return TokenizerProfile{100,20,16,kTokenizerTkMax100,97};
    if (version == kTokenizerVersion101) return TokenizerProfile{101,16,12,kTokenizerTkMax101,98};
    return std::nullopt;
}

std::uint32_t u32(std::span<const std::uint8_t> d, std::size_t o) {
    if (o + 4 > d.size()) return 0;
    return std::uint32_t(d[o]) | (std::uint32_t(d[o + 1]) << 8) |
           (std::uint32_t(d[o + 2]) << 16) | (std::uint32_t(d[o + 3]) << 24);
}

bool valid_utf8(std::span<const std::uint8_t> s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto lead = s[i++];
        if (lead < 0x80) continue;
        std::uint32_t cp = 0;
        std::size_t continuation = 0;
        if ((lead & 0xe0) == 0xc0) { cp = lead & 0x1f; continuation = 1; if (cp < 2) return false; }
        else if ((lead & 0xf0) == 0xe0) { cp = lead & 0x0f; continuation = 2; }
        else if ((lead & 0xf8) == 0xf0) { cp = lead & 0x07; continuation = 3; if (cp > 4) return false; }
        else return false;
        if (continuation > s.size() - i) return false;
        for (std::size_t n = 0; n < continuation; ++n) {
            const auto b = s[i++];
            if ((b & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (b & 0x3f);
        }
        if ((continuation == 2 && cp < 0x800) || (continuation == 3 && cp < 0x10000)) return false;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
    }
    return true;
}

struct Cursor {
    std::span<const std::uint8_t> bytes;
    std::size_t pos = 0;
    bool take(std::size_t n) {
        if (n > bytes.size() - pos) return false;
        pos += n;
        return true;
    }
    bool read32(std::uint32_t& out) {
        if (bytes.size() - pos < 4) return false;
        out = u32(bytes, pos);
        pos += 4;
        return true;
    }
};

bool variant_string(Cursor& c) {
    std::uint32_t size = 0;
    if (!c.read32(size) || size > c.bytes.size() - c.pos) return false;
    if (!valid_utf8(c.bytes.subspan(c.pos, size))) return false;
    c.pos += size;
    return c.take((4u - (size & 3u)) & 3u);
}

struct VariantFeatureStats {
    std::size_t typed_array_count = 0;
    std::size_t typed_dictionary_count = 0;
    std::size_t class_name_container_count = 0;
    std::size_t script_container_count = 0;
};

bool container_type(Cursor& c, std::uint32_t kind, VariantFeatureStats* stats = nullptr) {
    if (kind == 0) return true;
    if (kind == 1) {
        std::uint32_t type = 0;
        return c.read32(type) && type < kVariantMax;
    }
    if (kind == 2) {
        if (stats) ++stats->class_name_container_count;
        return variant_string(c);
    }
    if (kind == 3) {
        if (stats) ++stats->script_container_count;
        return variant_string(c);
    }
    return false;
}

bool variant(Cursor& c, std::size_t depth, std::size_t& nodes, VariantFeatureStats* stats = nullptr) {
    if (depth > kMaxVariantDepth || ++nodes > kMaxVariantNodes) return false;
    std::uint32_t header = 0;
    if (!c.read32(header)) return false;
    const auto type = header & 0xffu;
    if (type >= kVariantMax) return false;
    constexpr std::uint32_t wide_flag = 1u << 16;
    std::uint32_t allowed = 0;
    switch (type) {
        case 2: case 3: case 5: case 7: case 9: case 11: case 12:
        case 14: case 15: case 16: case 17: case 18: case 19:
        case 24: case 35: case 36: case 38: allowed = wide_flag; break;
        case 27: allowed = 0x000f0000u; break;
        case 28: allowed = 0x00030000u; break;
        default: break;
    }
    if (header & ~(0xffu | allowed)) return false;
    const bool wide = (header & wide_flag) != 0;
    auto fixed = [&](std::size_t n) { return c.take(n); };

    switch (type) {
        case 0: return true;
        case 1: return fixed(4);
        case 2: case 3: return fixed(wide ? 8 : 4);
        case 4: case 21: return variant_string(c);
        case 5: return fixed(wide ? 16 : 8);
        case 6: return fixed(8);
        case 7: return fixed(wide ? 32 : 16);
        case 8: return fixed(16);
        case 9: return fixed(wide ? 24 : 12);
        case 10: return fixed(12);
        case 11: return fixed(wide ? 48 : 24);
        case 12: return fixed(wide ? 32 : 16);
        case 13: return fixed(16);
        case 14: case 15: return fixed(wide ? 32 : 16);
        case 16: return fixed(wide ? 48 : 24);
        case 17: return fixed(wide ? 72 : 36);
        case 18: return fixed(wide ? 96 : 48);
        case 19: return fixed(wide ? 128 : 64);
        case 20: return fixed(16);
        case 22: {
            std::uint32_t names = 0, subnames = 0, flags = 0;
            if (!c.read32(names) || !(names & 0x80000000u) || !c.read32(subnames) || !c.read32(flags)) return false;
            names &= 0x7fffffffu;
            if (flags & ~3u) return false;
            if (flags & 2u) {
                if (subnames == std::numeric_limits<std::uint32_t>::max()) return false;
                ++subnames;
            }
            const std::uint64_t total = std::uint64_t(names) + subnames;
            if (names > kMaxTableCount || subnames > kMaxTableCount || total > kMaxTableCount) return false;
            for (std::uint64_t i = 0; i < total; ++i) if (!variant_string(c)) return false;
            return true;
        }
        case 23: return fixed(8);
        case 24: return wide && fixed(8);
        case 25: return true;
        case 26: return variant_string(c) && fixed(8);
        case 27: {
            const auto key_kind = (header >> 16) & 3u;
            const auto value_kind = (header >> 18) & 3u;
            if (stats && (key_kind || value_kind)) ++stats->typed_dictionary_count;
            if (!container_type(c, key_kind, stats) || !container_type(c, value_kind, stats)) return false;
            std::uint32_t raw = 0;
            if (!c.read32(raw)) return false;
            const auto count = raw & 0x7fffffffu;
            if (count > kMaxTableCount) return false;
            for (std::uint32_t i = 0; i < count; ++i) {
                if (!variant(c, depth + 1, nodes, stats) || !variant(c, depth + 1, nodes, stats)) return false;
            }
            return true;
        }
        case 28: {
            const auto kind = (header >> 16) & 3u;
            if (stats && kind) ++stats->typed_array_count;
            if (!container_type(c, kind, stats)) return false;
            std::uint32_t raw = 0;
            if (!c.read32(raw)) return false;
            const auto count = raw & 0x7fffffffu;
            if (count > kMaxTableCount) return false;
            for (std::uint32_t i = 0; i < count; ++i) if (!variant(c, depth + 1, nodes, stats)) return false;
            return true;
        }
        case 29: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > c.bytes.size() - c.pos || !c.take(count)) return false;
            return c.take((4u - (count & 3u)) & 3u);
        }
        case 30: case 32: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > kMaxTableCount || std::uint64_t(count) * 4 > c.bytes.size() - c.pos) return false;
            return c.take(std::size_t(count) * 4);
        }
        case 31: case 33: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > kMaxTableCount || std::uint64_t(count) * 8 > c.bytes.size() - c.pos) return false;
            return c.take(std::size_t(count) * 8);
        }
        case 34: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > kMaxTableCount) return false;
            for (std::uint32_t i = 0; i < count; ++i) if (!variant_string(c)) return false;
            return true;
        }
        case 35: case 36: case 38: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > kMaxTableCount) return false;
            const std::size_t lanes = type == 35 ? 2 : (type == 36 ? 3 : 4);
            const std::size_t item = lanes * (wide ? 8 : 4);
            if (std::uint64_t(count) * item > c.bytes.size() - c.pos) return false;
            return c.take(std::size_t(count) * item);
        }
        case 37: {
            std::uint32_t count = 0;
            if (!c.read32(count) || count > kMaxTableCount || std::uint64_t(count) * 16 > c.bytes.size() - c.pos) return false;
            return c.take(std::size_t(count) * 16);
        }
        default: return false;
    }
}

bool validate_contents(std::span<const std::uint8_t> contents, GDScriptBufferInfo& out, const TokenizerProfile& profile) {
    if (contents.size() < profile.payload_header_size) {
        out.failure_stage = "table_header";
        out.error = "payload is shorter than the versioned tokenizer table header";
        return false;
    }
    out.identifier_count = u32(contents, 0);
    out.constant_count = u32(contents, 4);
    out.token_line_count = u32(contents, 8);
    out.token_count = u32(contents, profile.token_count_offset);
    if (out.identifier_count > kMaxTableCount || out.constant_count > kMaxTableCount ||
        out.token_line_count > kMaxTableCount || out.token_count > kMaxTableCount ||
        out.token_line_count > out.token_count) {
        out.failure_stage = "table_header";
        out.error = "tokenizer table count is outside bounded official-compatible geometry";
        return false;
    }

    Cursor c{contents, profile.payload_header_size};
    for (std::uint32_t i = 0; i < out.identifier_count; ++i) {
        std::uint32_t chars = 0;
        if (!c.read32(chars) || chars > kMaxTableCount || std::uint64_t(chars) * 4 > c.bytes.size() - c.pos) {
            out.failure_stage = "identifiers";
            out.error = "identifier length escapes the tokenizer payload";
            return false;
        }
        for (std::uint32_t n = 0; n < chars; ++n) {
            const auto cp = u32(c.bytes, c.pos + std::size_t(n) * 4) ^ 0xb6b6b6b6u;
            if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
                out.failure_stage = "identifiers";
                out.error = "identifier UTF-32/XOR plane contains an invalid Unicode scalar";
                return false;
            }
        }
        c.pos += std::size_t(chars) * 4;
    }

    std::size_t nodes = 0;
    for (std::uint32_t i = 0; i < out.constant_count; ++i) {
        if (!variant(c, 0, nodes)) {
            out.failure_stage = "constants";
            out.error = "Godot Variant constant serialization failed structural decoding";
            return false;
        }
    }

    std::set<std::uint32_t> line_keys, column_keys;
    std::vector<std::uint32_t> mapped_lines(out.token_count, 0);
    std::vector<bool> has_mapped_line(out.token_count, false);
    for (std::uint32_t i = 0; i < out.token_line_count; ++i) {
        if (c.bytes.size() - c.pos < 8) {
            out.failure_stage = "lines";
            out.error = "token line map is truncated";
            return false;
        }
        const auto token_index = u32(c.bytes, c.pos);
        const auto line = u32(c.bytes, c.pos + 4);
        c.pos += 8;
        if (token_index >= out.token_count || line > 100000000u || !line_keys.insert(token_index).second) {
            out.failure_stage = "lines";
            out.error = "token line map contains an invalid or duplicate token reference";
            return false;
        }
        mapped_lines[token_index] = line;
        has_mapped_line[token_index] = true;
    }
    for (std::uint32_t i = 0; i < out.token_line_count; ++i) {
        if (c.bytes.size() - c.pos < 8) {
            out.failure_stage = "columns";
            out.error = "token column map is truncated";
            return false;
        }
        const auto token_index = u32(c.bytes, c.pos);
        const auto column = u32(c.bytes, c.pos + 4);
        c.pos += 8;
        if (token_index >= out.token_count || column > 10000000u || !column_keys.insert(token_index).second) {
            out.failure_stage = "columns";
            out.error = "token column map contains an invalid or duplicate token reference";
            return false;
        }
    }
    if (line_keys != column_keys) {
        out.failure_stage = "columns";
        out.error = "official line and column planes do not describe the same token indexes";
        return false;
    }

    for (std::uint32_t i = 0; i < out.token_count; ++i) {
        if (c.pos >= c.bytes.size()) {
            out.failure_stage = "tokens";
            out.error = "token stream is truncated";
            return false;
        }
        const bool wide = (c.bytes[c.pos] & 0x80u) != 0;
        const std::size_t record_size = wide ? 8 : 5;
        if (record_size > c.bytes.size() - c.pos) {
            out.failure_stage = "tokens";
            out.error = "token record escapes the payload";
            return false;
        }
        std::uint32_t type = c.bytes[c.pos] & 0x7fu;
        std::uint32_t data_index = 0;
        std::uint32_t line = 0;
        if (wide) {
            const auto word = u32(c.bytes, c.pos);
            type = word & 0x7fu;
            data_index = word >> 8;
            line = u32(c.bytes, c.pos + 4);
        } else {
            line = u32(c.bytes, c.pos + 1);
        }
        if (type >= profile.token_max || line > 100000000u) {
            out.failure_stage = "tokens";
            out.error = "token type or source line lies outside the official tokenizer version domain";
            return false;
        }
        if (has_mapped_line[i] && line != mapped_lines[i]) {
            out.failure_stage = "tokens";
            out.error = "token record source line disagrees with the sparse line-transition map";
            return false;
        }
        const bool identifier_ref = type == 1 || type == 2;
        const bool constant_ref = type == 3 || type == profile.error_token;
        if ((identifier_ref || constant_ref) && !wide) {
            out.failure_stage = "tokens";
            out.error = "table-referencing token has no encoded table index";
            return false;
        }
        if (identifier_ref && data_index >= out.identifier_count) {
            out.failure_stage = "tokens";
            out.error = "identifier token references outside the identifier table";
            return false;
        }
        if (constant_ref && data_index >= out.constant_count) {
            out.failure_stage = "tokens";
            out.error = "literal/error token references outside the constant table";
            return false;
        }
        if (wide && !identifier_ref && !constant_ref && data_index != 0) {
            out.failure_stage = "tokens";
            out.error = "ordinary token carries unexpected high data bits";
            return false;
        }
        c.pos += record_size;
    }

    if (c.pos != c.bytes.size()) {
        out.failure_stage = "payload_tail";
        out.error = "bytes remain after all official tokenizer tables and token records close";
        return false;
    }
    return true;
}

bool parse_layout_prefix(std::span<const std::uint8_t> contents, GDScriptBufferInfo& out, std::size_t& tail_pos) {
    if (contents.size() < 16) {
        out.failure_stage = "table_header";
        out.error = "payload is shorter than the four tokenizer table counts";
        return false;
    }
    out.identifier_count = u32(contents, 0);
    out.constant_count = u32(contents, 4);
    out.token_line_count = u32(contents, 8);
    out.token_count = u32(contents, 12);
    if (out.identifier_count > kMaxTableCount || out.constant_count > kMaxTableCount ||
        out.token_line_count > kMaxTableCount || out.token_count > kMaxTableCount ||
        out.token_line_count > out.token_count) {
        out.failure_stage = "table_header";
        out.error = "tokenizer table count is outside bounded layout-solver geometry";
        return false;
    }

    Cursor c{contents, 16};
    for (std::uint32_t i = 0; i < out.identifier_count; ++i) {
        std::uint32_t chars = 0;
        if (!c.read32(chars) || chars > kMaxTableCount || std::uint64_t(chars) * 4 > c.bytes.size() - c.pos) {
            out.failure_stage = "identifiers";
            out.error = "identifier length escapes the tokenizer payload";
            return false;
        }
        for (std::uint32_t n = 0; n < chars; ++n) {
            const auto cp = u32(c.bytes, c.pos + std::size_t(n) * 4) ^ 0xb6b6b6b6u;
            if (cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) {
                out.failure_stage = "identifiers";
                out.error = "identifier UTF-32/XOR plane contains an invalid Unicode scalar";
                return false;
            }
        }
        c.pos += std::size_t(chars) * 4;
    }

    std::size_t nodes = 0;
    for (std::uint32_t i = 0; i < out.constant_count; ++i) {
        if (!variant(c, 0, nodes)) {
            out.failure_stage = "constants";
            out.error = "Godot Variant constant serialization failed structural decoding";
            return false;
        }
    }
    tail_pos = c.pos;
    return true;
}

std::uint64_t u64(std::span<const std::uint8_t> d, std::size_t o) {
    if (o + 8 > d.size()) return 0;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= std::uint64_t(d[o + i]) << (i * 8);
    return v;
}

void append_utf8(std::string& out, std::uint32_t cp) {
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

std::string decoded_identifier(std::span<const std::uint8_t> d, std::size_t pos, std::uint32_t chars) {
    std::string out;
    out.reserve(chars);
    for (std::uint32_t i = 0; i < chars; ++i) append_utf8(out, u32(d, pos + std::size_t(i) * 4) ^ 0xb6b6b6b6u);
    return out;
}

const char* variant_type_name(std::uint32_t type) {
    static constexpr const char* names[] = {
        "NIL","BOOL","INT","FLOAT","STRING","VECTOR2","VECTOR2I","RECT2","RECT2I","VECTOR3","VECTOR3I","TRANSFORM2D","VECTOR4","VECTOR4I","PLANE","QUATERNION","AABB","BASIS","TRANSFORM3D","PROJECTION","COLOR","STRING_NAME","NODE_PATH","RID","OBJECT","CALLABLE","SIGNAL","DICTIONARY","ARRAY","PACKED_BYTE_ARRAY","PACKED_INT32_ARRAY","PACKED_INT64_ARRAY","PACKED_FLOAT32_ARRAY","PACKED_FLOAT64_ARRAY","PACKED_STRING_ARRAY","PACKED_VECTOR2_ARRAY","PACKED_VECTOR3_ARRAY","PACKED_COLOR_ARRAY","PACKED_VECTOR4_ARRAY"
    };
    return type < sizeof(names) / sizeof(names[0]) ? names[type] : "UNKNOWN";
}

struct ConstantSummary {
    std::string text;
    bool complete = true;
};

bool append_summary(std::string& out, std::string_view piece) {
    constexpr std::size_t cap = 512;
    if (out.size() + piece.size() <= cap) { out.append(piece); return true; }
    if (out.size() < cap) out.append(piece.substr(0, cap - out.size()));
    out += "...";
    return false;
}

std::string summary_atom(std::span<const std::uint8_t> encoded, const std::optional<ConstantSummary>& summary, bool& complete) {
    const auto type = encoded.size() >= 4 ? (u32(encoded, 0) & 0xffu) : kVariantMax;
    std::string out = type < kVariantMax ? variant_type_name(type) : "UNKNOWN";
    if (summary) {
        out += ":";
        out += summary->text;
        complete = complete && summary->complete;
    } else complete = false;
    return out;
}

std::optional<ConstantSummary> constant_summary(std::span<const std::uint8_t> encoded, std::size_t depth = 0) {
    if (encoded.size() < 4) return std::nullopt;
    const auto header = u32(encoded, 0), type = header & 0xffu;
    const bool wide = (header & (1u << 16)) != 0;
    auto scalar = [](std::string text, bool complete = true) -> std::optional<ConstantSummary> { return ConstantSummary{std::move(text),complete}; };
    auto real_text = [](auto value, int precision) {
        if (std::isnan(value)) return std::string("nan");
        if (std::isinf(value)) return std::string(std::signbit(value) ? "-inf" : "inf");
        std::ostringstream o;
        o << std::setprecision(precision) << value;
        return o.str();
    };
    auto real_lane = [&](std::size_t lane) -> std::optional<std::string> {
        const std::size_t width = wide ? 8u : 4u, pos = 4u + lane * width;
        if (pos + width > encoded.size()) return std::nullopt;
        if (wide) {
            const auto bits = u64(encoded, pos);
            double value = 0;
            std::memcpy(&value, &bits, sizeof(value));
            return real_text(value, 17);
        }
        const auto bits = u32(encoded, pos);
        float value = 0;
        std::memcpy(&value, &bits, sizeof(value));
        return real_text(value, 9);
    };
    auto int_lane = [&](std::size_t lane) -> std::optional<std::string> {
        const std::size_t pos = 4u + lane * 4u;
        if (pos + 4u > encoded.size()) return std::nullopt;
        const auto bits = u32(encoded, pos);
        std::int32_t value = 0;
        std::memcpy(&value, &bits, sizeof(value));
        return std::to_string(value);
    };
    auto lane_list = [&](std::size_t count, bool integral, std::string_view open="(", std::string_view close=")") -> std::optional<std::string> {
        std::string out(open);
        for(std::size_t i=0;i<count;++i){auto v=integral?int_lane(i):real_lane(i);if(!v)return std::nullopt;if(i)out+=",";out+=*v;}
        out+=close;return out;
    };
    auto grouped_real = [&](std::size_t groups, std::size_t lanes) -> std::optional<std::string> {
        std::string out = "[";
        for (std::size_t g = 0; g < groups; ++g) {
            if (g) out += ",";
            out += "(";
            for (std::size_t j = 0; j < lanes; ++j) {
                auto v = real_lane(g * lanes + j);
                if (!v) return std::nullopt;
                if (j) out += ",";
                out += *v;
            }
            out += ")";
        }
        out += "]";
        return out;
    };
    switch (type) {
        case 0: return scalar("null");
        case 1: if(encoded.size()<8)return std::nullopt; return scalar(u32(encoded,4)?"true":"false");
        case 2: {
            if (wide && encoded.size() >= 12) return scalar(std::to_string(static_cast<std::int64_t>(u64(encoded, 4))));
            if (!wide && encoded.size() >= 8) return scalar(std::to_string(static_cast<std::int32_t>(u32(encoded, 4))));
            return std::nullopt;
        }
        case 3: {
            std::ostringstream o;
            if (wide && encoded.size() >= 12) {
                auto bits = u64(encoded, 4); double v = 0; std::memcpy(&v, &bits, sizeof(v)); o << std::setprecision(17) << v;
            } else if (!wide && encoded.size() >= 8) {
                auto bits = u32(encoded, 4); float v = 0; std::memcpy(&v, &bits, sizeof(v)); o << std::setprecision(9) << v;
            } else return std::nullopt;
            return scalar(o.str());
        }
        case 5: { auto v=lane_list(2,false); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 6: { auto v=lane_list(2,true); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 7: {
            auto a=real_lane(0),b=real_lane(1),c=real_lane(2),d=real_lane(3);if(!a||!b||!c||!d)return std::nullopt;return scalar("position=("+*a+","+*b+"),size=("+*c+","+*d+")");
        }
        case 8: {
            auto a=int_lane(0),b=int_lane(1),c=int_lane(2),d=int_lane(3);if(!a||!b||!c||!d)return std::nullopt;return scalar("position=("+*a+","+*b+"),size=("+*c+","+*d+")");
        }
        case 9: { auto v=lane_list(3,false); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 10: { auto v=lane_list(3,true); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 11: {
            auto all=grouped_real(3,2);if(!all)return std::nullopt;return scalar("columns="+*all);
        }
        case 12: { auto v=lane_list(4,false); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 13: { auto v=lane_list(4,true); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 14: {
            auto a=real_lane(0),b=real_lane(1),c=real_lane(2),d=real_lane(3);if(!a||!b||!c||!d)return std::nullopt;return scalar("normal=("+*a+","+*b+","+*c+"),d="+*d);
        }
        case 15: { auto v=lane_list(4,false); if(!v)return std::nullopt; return scalar(std::move(*v)); }
        case 16: {
            auto a=real_lane(0),b=real_lane(1),c=real_lane(2),d=real_lane(3),e=real_lane(4),f=real_lane(5);if(!a||!b||!c||!d||!e||!f)return std::nullopt;return scalar("position=("+*a+","+*b+","+*c+"),size=("+*d+","+*e+","+*f+")");
        }
        case 17: {
            auto all=grouped_real(3,3);if(!all)return std::nullopt;return scalar("rows="+*all);
        }
        case 18: {
            auto basis=grouped_real(3,3);auto x=real_lane(9),y=real_lane(10),z=real_lane(11);if(!basis||!x||!y||!z)return std::nullopt;return scalar("basis_rows="+*basis+",origin=("+*x+","+*y+","+*z+")");
        }
        case 19: {
            auto all=grouped_real(4,4);if(!all)return std::nullopt;return scalar("columns="+*all);
        }
        case 20: {
            if (encoded.size() < 20) return std::nullopt;
            std::string out = "(";
            for (std::size_t i = 0; i < 4; ++i) {
                auto bits=u32(encoded,4+i*4); float v=0; std::memcpy(&v,&bits,sizeof(v));
                if (i) out += ",";
                out += real_text(v, 9);
            }
            out += ")"; return scalar(std::move(out));
        }
        case 4: case 21: {
            if (encoded.size() < 8) return std::nullopt;
            const auto n = u32(encoded, 4);
            if (n > encoded.size() - 8) return std::nullopt;
            std::string x(reinterpret_cast<const char*>(encoded.data() + 8), n);
            const bool complete=x.size()<=512;
            if (!complete) x.resize(512), x += "...";
            return scalar(std::move(x),complete);
        }
        case 22: {
            if (encoded.size() < 16) return std::nullopt;
            const auto raw_names = u32(encoded, 4);
            if (!(raw_names & 0x80000000u)) return std::nullopt;
            const auto name_count = raw_names & 0x7fffffffu;
            auto subname_count = u32(encoded, 8);
            const auto flags = u32(encoded, 12);
            if (flags & ~3u) return std::nullopt;
            if (flags & 2u) { if (subname_count == std::numeric_limits<std::uint32_t>::max()) return std::nullopt; ++subname_count; }
            if (name_count > kMaxTableCount || subname_count > kMaxTableCount || std::uint64_t(name_count)+subname_count > kMaxTableCount) return std::nullopt;
            std::size_t pos=16; std::string out=(flags&1u)?"/":""; bool complete=true;
            const auto total=std::uint64_t(name_count)+subname_count;
            for(std::uint64_t i=0;i<total;++i){
                if(encoded.size()-pos<4)return std::nullopt;
                const auto n=u32(encoded,pos);pos+=4;
                if(n>encoded.size()-pos)return std::nullopt;
                const auto part_bytes=encoded.subspan(pos,n);
                if(!valid_utf8(part_bytes))return std::nullopt;
                std::string part(reinterpret_cast<const char*>(part_bytes.data()),part_bytes.size());pos+=n;
                const auto pad=(4u-(n&3u))&3u;
                if(pad>encoded.size()-pos)return std::nullopt;
                pos+=pad;
                std::string piece;
                if(i<name_count){if(i)piece+="/";piece+=part;}else piece=":"+part;
                if(!append_summary(out,piece)){complete=false;break;}
            }
            if(pos!=encoded.size())complete=false;
            return scalar(std::move(out),complete);
        }
        case 27: case 28: {
            Cursor c{encoded,4};
            if(type==27){const auto key_kind=(header>>16)&3u,value_kind=(header>>18)&3u;if(!container_type(c,key_kind)||!container_type(c,value_kind))return std::nullopt;}
            else {const auto kind=(header>>16)&3u;if(!container_type(c,kind))return std::nullopt;}
            std::uint32_t raw=0;if(!c.read32(raw))return std::nullopt;const auto count=raw&0x7fffffffu;if(count>kMaxTableCount)return std::nullopt;
            if(depth>=8)return scalar("count="+std::to_string(count),false);
            std::string out=type==27?"{":"[";bool complete=true;const auto limit=std::min<std::uint32_t>(count,32);
            for(std::uint32_t i=0;i<limit;++i){
                auto one=[&](std::string&piece)->bool{const auto start=c.pos;Cursor next=c;std::size_t nodes=0;if(!variant(next,0,nodes))return false;auto span=encoded.subspan(start,next.pos-start);auto cs=constant_summary(span,depth+1);piece=summary_atom(span,cs,complete);c=next;return true;};
                std::string piece;if(type==27){std::string key,value;if(!one(key)||!one(value))return std::nullopt;piece=(i?",":"")+key+"=>"+value;}else{if(!one(piece))return std::nullopt;if(i)piece=","+piece;}
                if(!append_summary(out,piece)){complete=false;break;}
            }
            if(count>limit){append_summary(out,",...");complete=false;}
            if(!append_summary(out,type==27?"}":"]"))complete=false;
            if(count<=limit&&c.pos!=encoded.size())complete=false;
            return scalar(std::move(out),complete);
        }
        case 29: case 30: case 31: case 32: case 33: case 34: case 35: case 36: case 37: case 38: {
            if (encoded.size() < 8) return std::nullopt;
            const auto count=u32(encoded,4);
            return scalar("count="+std::to_string(count),count==0);
        }
        default: return std::nullopt;
    }
}

std::string token_type_name(std::uint32_t type, std::uint32_t version) {
    static constexpr const char* names101[] = {
        "EMPTY","ANNOTATION","IDENTIFIER","LITERAL","LESS","LESS_EQUAL","GREATER","GREATER_EQUAL","EQUAL_EQUAL","BANG_EQUAL","AND","OR","NOT","AMPERSAND_AMPERSAND","PIPE_PIPE","BANG","AMPERSAND","PIPE","TILDE","CARET","LESS_LESS","GREATER_GREATER","PLUS","MINUS","STAR","STAR_STAR","SLASH","PERCENT","EQUAL","PLUS_EQUAL","MINUS_EQUAL","STAR_EQUAL","STAR_STAR_EQUAL","SLASH_EQUAL","PERCENT_EQUAL","LESS_LESS_EQUAL","GREATER_GREATER_EQUAL","AMPERSAND_EQUAL","PIPE_EQUAL","CARET_EQUAL","IF","ELIF","ELSE","FOR","WHILE","BREAK","CONTINUE","PASS","RETURN","MATCH","WHEN","AS","ASSERT","AWAIT","BREAKPOINT","CLASS","CLASS_NAME","CONST","ENUM","EXTENDS","FUNC","IN","IS","NAMESPACE","PRELOAD","SELF","SIGNAL","STATIC","SUPER","TRAIT","VAR","VOID","YIELD","BRACKET_OPEN","BRACKET_CLOSE","BRACE_OPEN","BRACE_CLOSE","PARENTHESIS_OPEN","PARENTHESIS_CLOSE","COMMA","SEMICOLON","PERIOD","PERIOD_PERIOD","PERIOD_PERIOD_PERIOD","COLON","DOLLAR","FORWARD_ARROW","UNDERSCORE","NEWLINE","INDENT","DEDENT","CONST_PI","CONST_TAU","CONST_INF","CONST_NAN","VCS_CONFLICT_MARKER","BACKTICK","QUESTION_MARK","ERROR","TK_EOF"
    };
    if (version == kTokenizerVersion100) {
        if (type >= kTokenizerTkMax100) return "CUSTOM_" + std::to_string(type);
        const auto mapped = type <= 82 ? type : type + 1;
        return mapped < sizeof(names101) / sizeof(names101[0]) ? names101[mapped] : "CUSTOM_" + std::to_string(type);
    }
    if (type < sizeof(names101) / sizeof(names101[0])) return names101[type];
    return "CUSTOM_" + std::to_string(type);
}

std::optional<std::string> token_display_text(std::uint32_t type, std::uint32_t version) {
    static constexpr const char* names101[] = {
        "Empty","Annotation","Identifier","Literal","<","<=",">",">=","==","!=","and","or","not","&&","||","!","&","|","~","^","<<",">>","+","-","*","**","/","%","=","+=","-=","*=","**=","/=","%=","<<=",">>=","&=","|=","^=","if","elif","else","for","while","break","continue","pass","return","match","when","as","assert","await","breakpoint","class","class_name","const","enum","extends","func","in","is","namespace","preload","self","signal","static","super","trait","var","void","yield","[","]","{","}","(",")",",",";",".","..","...",":","$","->","_","Newline","Indent","Dedent","PI","TAU","INF","NaN","VCS conflict marker","`","?","Error","End of file"
    };
    static_assert(sizeof(names101) / sizeof(names101[0]) == kTokenizerTkMax101);
    if (version == kTokenizerVersion100) {
        if (type >= kTokenizerTkMax100) return std::nullopt;
        const auto mapped = type <= 82 ? type : type + 1;
        if (mapped >= sizeof(names101) / sizeof(names101[0])) return std::nullopt;
        return std::string(names101[mapped]);
    }
    if (version == kTokenizerVersion101 && type < sizeof(names101) / sizeof(names101[0])) return std::string(names101[type]);
    return std::nullopt;
}

bool decode_analysis_payload(std::span<const std::uint8_t> data, std::size_t max_decompressed_size,
                             std::vector<std::uint8_t>& decoded, std::span<const std::uint8_t>& contents,
                             std::string& error) {
    max_decompressed_size = std::min<std::size_t>(max_decompressed_size, 512u * 1024u * 1024u);
    if (data.size() < 12 || data[0] != 'G' || data[1] != 'D' || data[2] != 'S' || data[3] != 'C') { error = "not a GDSC tokenizer buffer"; return false; }
    if (!tokenizer_profile(u32(data, 4))) { error = "unsupported GDScript tokenizer version"; return false; }
    const auto decompressed_size = u32(data, 8);
    if (!decompressed_size) { contents = data.subspan(12); return true; }
    if (decompressed_size > max_decompressed_size) { error = "declared decompressed size exceeds analysis limit"; return false; }
    unsigned char* buffer = nullptr; std::size_t output_size = 0, frame_size = 0; unsigned long long bound = 0; int limit_hit = 0;
    const auto source = data.subspan(12);
    if (!prts_zstd_decompress_frame_limited(source.data(), source.size(), max_decompressed_size, &buffer, &output_size, &frame_size, &bound, &limit_hit)) { error = limit_hit ? "Zstandard expansion exceeds analysis limit" : "Zstandard frame failed decompression"; return false; }
    decoded.assign(buffer, buffer + output_size); prts_zstd_free(buffer);
    if (frame_size != source.size() || output_size != decompressed_size) { error = "Zstandard frame/decompressed size do not close exactly"; return false; }
    contents = decoded; return true;
}

bool exact_official_v101_tail_geometry(std::span<const std::uint8_t> tail,const GDScriptBufferInfo& common) {
    const std::uint64_t map_bytes=std::uint64_t(common.token_line_count)*16u;
    if(map_bytes>tail.size())return false;
    std::size_t pos=static_cast<std::size_t>(map_bytes);
    for(std::uint32_t i=0;i<common.token_count;++i){
        if(pos>=tail.size())return false;
        const std::size_t record_size=(tail[pos]&0x80u)?8u:5u;
        if(record_size>tail.size()-pos)return false;
        pos+=record_size;
    }
    return pos==tail.size();
}

double ratio(std::size_t good, std::size_t total) {
    return total ? double(good) / double(total) : 1.0;
}

GDScriptLayoutCandidate evaluate_fixed_layout(std::span<const std::uint8_t> tail,
                                               const GDScriptBufferInfo& common,
                                               std::uint32_t token_width,
                                               std::uint32_t line_width) {
    GDScriptLayoutCandidate c;
    c.token_record_size = token_width;
    c.line_record_size = line_width;
    c.identifier_valid = true;
    c.constant_valid = true;
    const std::uint64_t line_bytes = std::uint64_t(common.token_line_count) * line_width;
    const std::uint64_t token_bytes = std::uint64_t(common.token_count) * token_width;
    if (line_bytes > tail.size() || token_bytes > tail.size() || line_bytes + token_bytes != tail.size()) return c;
    c.size_fit = true;

    std::vector<std::uint32_t> mapped_lines(common.token_count, 0);
    std::vector<bool> has_mapped_line(common.token_count, false);
    std::set<std::uint32_t> line_tokens;
    std::size_t line_refs_good = 0, line_monotonic_good = 0, reserved_zero = 0;
    bool line_ranges_ok = true, line_unique = true;
    std::uint32_t previous_line = 0;
    bool have_previous_line = false;
    std::size_t pos = 0;
    for (std::uint32_t i = 0; i < common.token_line_count; ++i) {
        const auto token_index = u32(tail, pos);
        const auto line = u32(tail, pos + 4);
        if (token_index < common.token_count) {
            ++line_refs_good;
            mapped_lines[token_index] = line;
            has_mapped_line[token_index] = true;
        } else line_ranges_ok = false;
        if (!line_tokens.insert(token_index).second) line_unique = false;
        if (line > 100000000u) line_ranges_ok = false;
        if (have_previous_line && line >= previous_line) ++line_monotonic_good;
        previous_line = line;
        have_previous_line = true;
        if (line_width >= 12) {
            const auto column = u32(tail, pos + 8);
            if (column > 10000000u) line_ranges_ok = false;
        }
        if (line_width == 16 && u32(tail, pos + 12) == 0) ++reserved_zero;
        pos += line_width;
    }
    c.line_token_reference_ratio = ratio(line_refs_good, common.token_line_count);
    c.line_monotonic_ratio = ratio(line_monotonic_good, common.token_line_count > 0 ? common.token_line_count - 1 : 0);
    c.reserved_zero_ratio = line_width == 16 ? ratio(reserved_zero, common.token_line_count) : 1.0;
    c.line_references_valid = line_ranges_ok && line_unique && line_refs_good == common.token_line_count;

    std::size_t known_tokens = 0, semantic_good = 0;
    bool token_lines_ok = true;
    for (std::uint32_t i = 0; i < common.token_count; ++i) {
        const auto word = u32(tail, pos);
        const auto type = word & 0xffu;
        const auto data_index = word >> 8;
        if (type < kTokenizerTkMax101) {
            ++known_tokens;
            const bool identifier_ref = type == 1 || type == 2;
            const bool constant_ref = type == 3 || type == 98;
            bool valid = true;
            if (identifier_ref) valid = data_index < common.identifier_count;
            else if (constant_ref) valid = data_index < common.constant_count;
            else valid = data_index == 0;
            if (valid) ++semantic_good;
        } else {
            ++c.custom_token_count;
        }
        if (token_width == 8) {
            const auto token_line = u32(tail, pos + 4);
            if (token_line > 100000000u) token_lines_ok = false;
            if (has_mapped_line[i] && token_line != mapped_lines[i]) token_lines_ok = false;
        }
        pos += token_width;
    }
    c.token_domain_ratio = ratio(known_tokens, common.token_count);
    c.token_reference_ratio = ratio(semantic_good, known_tokens);
    c.known_token_semantics_valid = token_lines_ok && semantic_good == known_tokens;
    c.structurally_valid = c.size_fit && c.line_references_valid && c.known_token_semantics_valid;
    return c;
}

} // namespace

GDScriptBufferInfo validate_gdscript_buffer_versioned(std::span<const std::uint8_t> data,
                                                      std::size_t max_decompressed_size) {
    GDScriptBufferInfo out;
    max_decompressed_size = std::min<std::size_t>(max_decompressed_size, 512u * 1024u * 1024u);
    if (data.size() < 12 || data[0] != 'G' || data[1] != 'D' || data[2] != 'S' || data[3] != 'C') {
        out.failure_stage = "header";
        out.error = "not a GDSC tokenizer buffer";
        return out;
    }
    out.header_valid = true;
    out.tokenizer_version = u32(data, 4);
    out.decompressed_size = u32(data, 8);
    const auto profile = tokenizer_profile(out.tokenizer_version);
    if (!profile) {
        out.failure_stage = "version";
        out.error = "unsupported official GDScript tokenizer version (supported: 100 for Godot 4.3/4.4, 101 for Godot 4.5)";
        return out;
    }

    std::vector<std::uint8_t> decoded;
    std::span<const std::uint8_t> contents;
    if (out.decompressed_size == 0) {
        out.compression = "none";
        out.compression_valid = true;
        contents = data.subspan(12);
    } else {
        if (out.decompressed_size > max_decompressed_size) {
            out.failure_stage = "compression";
            out.error = "declared decompressed size exceeds the validation limit";
            return out;
        }
        unsigned char* buffer = nullptr;
        std::size_t output_size = 0, frame_size = 0;
        unsigned long long bound = 0;
        int limit_hit = 0;
        const auto source = data.subspan(12);
        if (!prts_zstd_decompress_frame_limited(source.data(), source.size(), max_decompressed_size,
                                                &buffer, &output_size, &frame_size, &bound, &limit_hit)) {
            out.failure_stage = "compression";
            out.error = limit_hit ? "Zstandard expansion exceeds the validation limit"
                                  : "Zstandard frame failed decompression";
            return out;
        }
        decoded.assign(buffer, buffer + output_size);
        prts_zstd_free(buffer);
        if (frame_size != source.size() || output_size != out.decompressed_size) {
            out.failure_stage = "compression";
            out.error = "Zstandard frame and decompressed-size geometry do not close exactly";
            return out;
        }
        out.compression = "zstd";
        out.compression_valid = true;
        contents = decoded;
    }

    out.payload_bytes = contents.size();
    if (!validate_contents(contents, out, *profile)) return out;
    out.structurally_valid = true;
    out.official_compatible = true;
    out.failure_stage.clear();
    out.error.clear();
    return out;
}

GDScriptBufferInfo validate_gdscript_buffer(std::span<const std::uint8_t> data,
                                            std::size_t max_decompressed_size) {
    if (data.size() >= 8 && u32(data, 4) != kTokenizerVersion101) {
        GDScriptBufferInfo out;
        out.header_valid = data.size() >= 12 && data[0] == 'G' && data[1] == 'D' && data[2] == 'S' && data[3] == 'C';
        out.tokenizer_version = data.size() >= 8 ? u32(data, 4) : 0;
        out.decompressed_size = data.size() >= 12 ? u32(data, 8) : 0;
        out.failure_stage = out.header_valid ? "version" : "header";
        out.error = out.header_valid ? "default GDScript validator is scoped to official Godot 4.5 tokenizer version 101" : "not a GDSC tokenizer buffer";
        return out;
    }
    return validate_gdscript_buffer_versioned(data, max_decompressed_size);
}

GDScriptLayoutInfo infer_gdscript_layout(std::span<const std::uint8_t> data,
                                         std::size_t max_decompressed_size) {
    GDScriptLayoutInfo out;
    auto official = validate_gdscript_buffer_versioned(data, max_decompressed_size);
    out.tokenizer_version = official.tokenizer_version;
    out.identifier_count = official.identifier_count;
    out.constant_count = official.constant_count;
    out.token_line_count = official.token_line_count;
    out.token_count = official.token_count;
    if (official.structurally_valid) {
        out.state = "CONFIRMED";
        out.variant = "official-compatible";
        out.official_compatible = true;
        return out;
    }

    max_decompressed_size = std::min<std::size_t>(max_decompressed_size, 512u * 1024u * 1024u);
    if (data.size() < 12 || data[0] != 'G' || data[1] != 'D' || data[2] != 'S' || data[3] != 'C') {
        out.error = "not a GDSC tokenizer buffer";
        return out;
    }
    out.tokenizer_version = u32(data, 4);
    if (out.tokenizer_version != kTokenizerVersion101) {
        out.error = "modified-layout inference is intentionally scoped to tokenizer version 101";
        return out;
    }

    const auto decompressed_size = u32(data, 8);
    std::vector<std::uint8_t> decoded;
    std::span<const std::uint8_t> contents;
    if (decompressed_size == 0) {
        contents = data.subspan(12);
    } else {
        if (decompressed_size > max_decompressed_size) {
            out.error = "declared decompressed size exceeds the layout-inference limit";
            return out;
        }
        unsigned char* buffer = nullptr;
        std::size_t output_size = 0, frame_size = 0;
        unsigned long long bound = 0;
        int limit_hit = 0;
        const auto source = data.subspan(12);
        if (!prts_zstd_decompress_frame_limited(source.data(), source.size(), max_decompressed_size,
                                                &buffer, &output_size, &frame_size, &bound, &limit_hit)) {
            out.error = limit_hit ? "Zstandard expansion exceeds the layout-inference limit"
                                  : "Zstandard frame failed decompression";
            return out;
        }
        decoded.assign(buffer, buffer + output_size);
        prts_zstd_free(buffer);
        if (frame_size != source.size() || output_size != decompressed_size) {
            out.error = "Zstandard frame and decompressed-size geometry do not close exactly";
            return out;
        }
        contents = decoded;
    }

    GDScriptBufferInfo common;
    std::size_t tail_pos = 0;
    if (!parse_layout_prefix(contents, common, tail_pos)) {
        out.error = common.failure_stage + ": " + common.error;
        return out;
    }
    out.identifier_count = common.identifier_count;
    out.constant_count = common.constant_count;
    out.token_line_count = common.token_line_count;
    out.token_count = common.token_count;

    const auto tail = contents.subspan(tail_pos);
    if(exact_official_v101_tail_geometry(tail,common)){
        out.error="payload retains exact official tokenizer-v101 line/column/token record geometry; modified-layout fallback refused after official semantic validation failure";
        return out;
    }
    constexpr std::uint32_t token_widths[] = {4, 8};
    constexpr std::uint32_t line_widths[] = {8, 12, 16};
    std::size_t selected_index = 0;
    bool selected = false;
    for (auto token_width : token_widths) {
        for (auto line_width : line_widths) {
            auto candidate = evaluate_fixed_layout(tail, common, token_width, line_width);
            if (candidate.size_fit) ++out.size_fit_candidates;
            if (candidate.structurally_valid) {
                ++out.structurally_valid_candidates;
                if (!selected) {
                    selected_index = out.candidates.size();
                    selected = true;
                }
            }
            out.candidates.push_back(candidate);
        }
    }

    if (out.structurally_valid_candidates == 0) {
        out.error = out.size_fit_candidates ? "fixed-record candidates fit total size but failed line/token semantic closure"
                                            : "no bounded fixed-record candidate matches the remaining payload size";
        return out;
    }
    if (out.structurally_valid_candidates > 1) {
        out.state = "AMBIGUOUS_LAYOUT";
        out.variant = "unknown-variant";
        out.error = "multiple fixed-record layouts remain structurally valid; no layout was selected";
        return out;
    }

    const auto& chosen = out.candidates[selected_index];
    out.state = "CONFIRMED";
    out.variant = chosen.custom_token_count ? "custom-token-layout" : "modified-layout";
    out.token_record_size = chosen.token_record_size;
    out.line_record_size = chosen.line_record_size;
    return out;
}

GDScriptAnalysisInfo analyze_gdscript_buffer(std::span<const std::uint8_t> data,
                                              std::size_t max_decompressed_size) {
    GDScriptAnalysisInfo out;
    const auto layout = infer_gdscript_layout(data, max_decompressed_size);
    out.state = layout.state;
    out.variant = layout.variant;
    out.tokenizer_version = layout.tokenizer_version;
    out.decompressed_size = data.size() >= 12 ? u32(data, 8) : 0;
    out.compression = out.decompressed_size ? "zstd" : "none";
    out.token_record_size = layout.token_record_size;
    out.line_record_size = layout.line_record_size;
    if (layout.state != "CONFIRMED") {
        out.error = layout.error.empty() ? "GDScript layout is not uniquely confirmed" : layout.error;
        return out;
    }
    const auto profile = tokenizer_profile(out.tokenizer_version);
    if (!profile) { out.error = "unsupported GDScript tokenizer profile after layout confirmation"; return out; }

    std::vector<std::uint8_t> decoded;
    std::span<const std::uint8_t> contents;
    if (!decode_analysis_payload(data, max_decompressed_size, decoded, contents, out.error)) return out;
    out.input_bytes = data.size();
    out.input_sha256 = sha256_bytes(data);
    out.payload_bytes = contents.size();
    out.payload_sha256 = sha256_bytes(contents);
    out.analysis_set_id = out.input_sha256 + ":" + out.payload_sha256;
    if (contents.size() < profile->payload_header_size) { out.error = "decompressed payload is shorter than versioned table header"; return out; }
    if (out.tokenizer_version == kTokenizerVersion100) {
        out.payload_reserved_word_present = true;
        out.payload_reserved_word = u32(contents, 12);
    }
    const auto identifier_count = u32(contents, 0), constant_count = u32(contents, 4);
    const auto line_count = u32(contents, 8), token_count = u32(contents, profile->token_count_offset);
    Cursor c{contents, profile->payload_header_size};

    out.identifiers.reserve(identifier_count);
    for (std::uint32_t i = 0; i < identifier_count; ++i) {
        const auto start = c.pos;
        std::uint32_t chars = 0;
        if (!c.read32(chars) || std::uint64_t(chars) * 4 > c.bytes.size() - c.pos) { out.error = "identifier plane changed after layout confirmation"; return out; }
        GDScriptIdentifierInfo row; row.index = i; row.payload_offset = start; row.text = decoded_identifier(contents, c.pos, chars);
        c.pos += std::size_t(chars) * 4; out.identifiers.push_back(std::move(row));
    }

    out.constants.reserve(constant_count);
    std::size_t variant_nodes = 0;
    VariantFeatureStats variant_features;
    for (std::uint32_t i = 0; i < constant_count; ++i) {
        const auto start = c.pos;
        Cursor next = c;
        if (!variant(next, 0, variant_nodes, &variant_features)) { out.error = "constant plane changed after layout confirmation"; return out; }
        const auto size = next.pos - start;
        GDScriptConstantInfo row; row.index = i; row.payload_offset = start; row.encoded_size = size; row.type_id = u32(contents, start) & 0xffu; row.type = variant_type_name(row.type_id);
        if (auto summary = constant_summary(contents.subspan(start, size))) { row.summary_available = true; row.summary_complete=summary->complete; row.summary = std::move(summary->text); }
        out.constants.push_back(std::move(row)); c = next;
    }
    out.typed_array_count = variant_features.typed_array_count;
    out.typed_dictionary_count = variant_features.typed_dictionary_count;
    out.class_name_container_count = variant_features.class_name_container_count;
    out.script_container_count = variant_features.script_container_count;
    if (layout.variant == "official-compatible") {
        if (out.tokenizer_version == kTokenizerVersion100) {
            out.official_version_scope = "Godot 4.3/4.4 official tokenizer profile";
            if (out.typed_dictionary_count) {
                out.official_version_basis = "tokenizer-v100; 4.4-compatible typed Dictionary Variant extension observed, but tokenizer bytes do not prove engine minor";
            } else {
                out.official_version_basis = "tokenizer-v100; engine minor is not distinguishable from tokenizer serialization";
            }
        } else if (out.tokenizer_version == kTokenizerVersion101) {
            out.official_version_scope = "Godot 4.5 official tokenizer profile";
            out.official_version_basis = "tokenizer-v101";
        }
    } else {
        out.official_version_scope = "not-applicable";
        out.official_version_basis = "modified/custom tokenizer-v101 layout; engine minor not inferred";
    }

    if (layout.variant == "official-compatible") {
        out.lines.reserve(line_count);
        for (std::uint32_t i = 0; i < line_count; ++i) {
            if (c.bytes.size() - c.pos < 8) { out.error = "official line plane truncated after layout confirmation"; return out; }
            GDScriptLineInfo row; row.index = i; row.token_index = u32(contents, c.pos); row.line = u32(contents, c.pos + 4); c.pos += 8; out.lines.push_back(row);
        }
        std::vector<std::uint32_t> columns(token_count, 0); std::vector<bool> have_column(token_count, false);
        for (std::uint32_t i = 0; i < line_count; ++i) {
            if (c.bytes.size() - c.pos < 8) { out.error = "official column plane truncated after layout confirmation"; return out; }
            const auto token_index = u32(contents, c.pos), column = u32(contents, c.pos + 4); c.pos += 8;
            if (token_index >= token_count) { out.error = "official column token reference changed after layout confirmation"; return out; }
            columns[token_index] = column; have_column[token_index] = true;
        }
        for (auto& row : out.lines) if (row.token_index < token_count && have_column[row.token_index]) { row.column = columns[row.token_index]; row.has_column = true; }

        out.tokens.reserve(token_count);
        for (std::uint32_t i = 0; i < token_count; ++i) {
            if (c.pos >= c.bytes.size()) { out.error = "official token plane truncated after layout confirmation"; return out; }
            const auto start = c.pos; const bool wide = (c.bytes[c.pos] & 0x80u) != 0; const auto record_size = wide ? 8u : 5u;
            if (record_size > c.bytes.size() - c.pos) { out.error = "official token record escapes payload after layout confirmation"; return out; }
            const auto word = wide ? u32(contents, c.pos) : std::uint32_t(contents[c.pos]);
            GDScriptTokenInfo row; row.index = i; row.payload_offset = start; row.type_id = word & 0x7fu; row.data = wide ? word >> 8 : 0; row.line = wide ? u32(contents, c.pos + 4) : u32(contents, c.pos + 1); row.effective_line=row.line; row.effective_line_known=true; row.effective_line_source="token-record"; row.record_size = record_size; row.custom = false; row.type = token_type_name(row.type_id, out.tokenizer_version);
            out.tokens.push_back(std::move(row)); c.pos += record_size;
        }
    } else {
        out.lines.reserve(line_count);
        for (std::uint32_t i = 0; i < line_count; ++i) {
            if (layout.line_record_size > c.bytes.size() - c.pos) { out.error = "modified line plane truncated after layout confirmation"; return out; }
            GDScriptLineInfo row; row.index = i; row.token_index = u32(contents, c.pos); row.line = u32(contents, c.pos + 4);
            if (layout.line_record_size >= 12) { row.column = u32(contents, c.pos + 8); row.has_column = true; }
            if (layout.line_record_size == 16) { row.unknown = u32(contents, c.pos + 12); row.has_unknown = true; }
            out.lines.push_back(row); c.pos += layout.line_record_size;
        }
        out.tokens.reserve(token_count);
        for (std::uint32_t i = 0; i < token_count; ++i) {
            if (layout.token_record_size > c.bytes.size() - c.pos) { out.error = "modified token plane truncated after layout confirmation"; return out; }
            const auto start = c.pos;
            const auto word = u32(contents, c.pos);
            GDScriptTokenInfo row; row.index = i; row.payload_offset = start; row.type_id = word & 0xffu; row.data = word >> 8; row.line = layout.token_record_size == 8 ? u32(contents, c.pos + 4) : 0; if(layout.token_record_size==8){row.effective_line=row.line;row.effective_line_known=true;row.effective_line_source="token-record";} row.record_size = layout.token_record_size; row.custom = row.type_id >= kTokenizerTkMax101; row.type = token_type_name(row.type_id, kTokenizerVersion101);
            out.tokens.push_back(std::move(row)); c.pos += layout.token_record_size;
        }
    }
    if (c.pos != contents.size()) { out.error = "payload tail remains after confirmed analysis parse"; return out; }
    for (const auto& line_row : out.lines) {
        if (line_row.token_index >= out.tokens.size()) continue;
        auto& token = out.tokens[line_row.token_index];
        token.position_map_present = true;
        token.mapped_line = line_row.line;
        if(!token.effective_line_known){token.effective_line=line_row.line;token.effective_line_known=true;token.effective_line_source="position-map";}
        ++out.position_mapped_token_count;
        if (line_row.has_column) {
            token.mapped_column = line_row.column;
            token.mapped_column_known = true;
            ++out.mapped_column_token_count;
        }
    }
    for(const auto&row:out.tokens){if(row.effective_line_known)++out.effective_line_token_count;else ++out.unknown_line_token_count;}
    for (auto& row : out.tokens) {
        if ((row.type_id == 1 || row.type_id == 2) && row.data < out.identifiers.size()) {
            auto& identifier = out.identifiers[row.data];
            if(!identifier.referenced){identifier.referenced=true;identifier.first_token_index=row.index;}
            identifier.last_token_index=row.index;++identifier.token_reference_count;if(row.type_id==1)++identifier.annotation_reference_count;
            row.reference_kind = "identifier";
            row.reference = identifier.text;
            row.semantic_text_available = true;
            row.semantic_text_complete = true;
            row.semantic_text_source = row.type_id == 1 ? "identifier-table+annotation-marker" : "identifier-table";
            row.semantic_text = row.type_id == 1 ? "@" + row.reference : row.reference;
        } else if ((row.type_id == 3 || row.type_id == profile->error_token) && row.data < out.constants.size()) {
            auto& constant = out.constants[row.data];
            if(!constant.referenced){constant.referenced=true;constant.first_token_index=row.index;}
            constant.last_token_index=row.index;++constant.token_reference_count;if(row.type_id==3)++constant.literal_reference_count;else ++constant.error_reference_count;
            row.reference_kind = "constant";
            row.reference = constant.type;
            if (constant.summary_available) row.reference += ":" + constant.summary;
            row.semantic_text_available = true;
            row.semantic_text_complete = constant.summary_available && constant.summary_complete;
            row.semantic_text_source = "constant-table";
            row.semantic_text = row.reference;
        } else if (!row.custom) {
            const auto display_version = layout.variant == "official-compatible" ? out.tokenizer_version : kTokenizerVersion101;
            if (auto text = token_display_text(row.type_id, display_version)) {
                row.semantic_text_available = true;
                row.semantic_text_complete = true;
                row.semantic_text_source = "official-token-name";
                row.semantic_text = std::move(*text);
            }
        }
        if (row.semantic_text_available) {++out.semantic_text_token_count;if(row.semantic_text_complete)++out.semantic_text_complete_token_count;else ++out.semantic_text_incomplete_token_count;}
    }
    for(std::size_t i=0;i+1<out.tokens.size();++i){
        const auto& keyword=out.tokens[i];auto& name=out.tokens[i+1];
        if(name.type!="IDENTIFIER"||name.data>=out.identifiers.size())continue;
        auto& id=out.identifiers[name.data];bool paired=true;
        if(keyword.type=="FUNC")++id.func_identifier_pair_count;
        else if(keyword.type=="VAR")++id.var_identifier_pair_count;
        else if(keyword.type=="CONST")++id.const_identifier_pair_count;
        else if(keyword.type=="SIGNAL")++id.signal_identifier_pair_count;
        else if(keyword.type=="CLASS_NAME")++id.class_name_identifier_pair_count;
        else if(keyword.type=="CLASS")++id.class_identifier_pair_count;
        else if(keyword.type=="ENUM")++id.enum_identifier_pair_count;
        else if(keyword.type=="EXTENDS")++id.extends_identifier_pair_count;
        else paired=false;
        if(paired){
            name.keyword_identifier_pair_present=true;
            name.keyword_identifier_pair_token_index=keyword.index;
            name.keyword_identifier_pair_keyword=keyword.type;
        }
    }
    // D21 does not attempt a general GDScript AST. It retains one narrow call-provenance
    // shape whose semantics are fixed by the official parser: a unique top-level
    // `extends NativeClass` plus explicit `super.method(` inside a named top-level
    // function block. Nested class scopes and modified/custom token layouts are excluded.
    if(out.variant=="official-compatible"){
        struct ExtendsEvidence{std::string name;std::size_t keyword=0,identifier=0;};
        std::optional<ExtendsEvidence> head_extends;bool extends_ambiguous=false;std::size_t indent_depth=0;bool line_has_class=false;
        for(std::size_t i=0;i<out.tokens.size();++i){
            const auto&t=out.tokens[i];
            if(t.type=="DEDENT"){if(indent_depth) --indent_depth;continue;}
            if(t.type=="INDENT"){++indent_depth;continue;}
            if(t.type=="NEWLINE"){line_has_class=false;continue;}
            if(t.type=="CLASS"){line_has_class=true;continue;}
            if(t.type!="EXTENDS"||indent_depth||line_has_class||i+1>=out.tokens.size())continue;
            const auto&idtok=out.tokens[i+1];if(idtok.type!="IDENTIFIER"||idtok.data>=out.identifiers.size())continue;
            if(i+2<out.tokens.size()&&out.tokens[i+2].type=="PERIOD")continue;
            if(i+2<out.tokens.size()&&out.tokens[i+2].type!="NEWLINE"&&out.tokens[i+2].type!="TK_EOF")continue;
            ExtendsEvidence ev{out.identifiers[idtok.data].text,t.index,idtok.index};
            if(head_extends)extends_ambiguous=true;else head_extends=std::move(ev);
        }
        if(head_extends&&!extends_ambiguous){
            enum class BlockKind{Other,Class,Function};std::vector<BlockKind>blocks;BlockKind pending=BlockKind::Other;bool line_class=false,line_named_func=false;
            auto in_block=[&](BlockKind kind){return std::find(blocks.begin(),blocks.end(),kind)!=blocks.end();};
            for(std::size_t i=0;i<out.tokens.size();++i){
                const auto&t=out.tokens[i];
                if(t.type=="DEDENT"){if(!blocks.empty())blocks.pop_back();continue;}
                if(t.type=="INDENT"){blocks.push_back(pending);pending=BlockKind::Other;continue;}
                if(t.type=="NEWLINE"){pending=line_class?BlockKind::Class:(line_named_func?BlockKind::Function:BlockKind::Other);line_class=false;line_named_func=false;continue;}
                if(t.type=="CLASS")line_class=true;
                if(t.type=="FUNC"&&i+1<out.tokens.size()&&out.tokens[i+1].type=="IDENTIFIER")line_named_func=true;
                if(in_block(BlockKind::Class)||!in_block(BlockKind::Function)||t.type!="SUPER"||i+3>=out.tokens.size())continue;
                const auto&period=out.tokens[i+1];const auto&method=out.tokens[i+2];const auto&open=out.tokens[i+3];
                if(period.type!="PERIOD"||method.type!="IDENTIFIER"||open.type!="PARENTHESIS_OPEN"||method.data>=out.identifiers.size())continue;
                GDScriptNativeSuperCallInfo call;call.base_class=head_extends->name;call.method_name=out.identifiers[method.data].text;call.extends_keyword_token_index=head_extends->keyword;call.extends_identifier_token_index=head_extends->identifier;call.super_token_index=t.index;call.method_identifier_token_index=method.index;call.effective_line=t.effective_line;call.effective_line_known=t.effective_line_known;out.native_super_calls.push_back(std::move(call));
            }
        }
    }
    out.valid = true; out.state = "CONFIRMED"; out.error.clear(); return out;
}

} // namespace prts
