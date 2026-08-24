#include "prts/hermes.hpp"

#include "prts/sha1.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <tuple>

namespace prts {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f};
constexpr std::uint64_t kHeaderSize = 128;
constexpr std::uint64_t kFooterSize = 20;
constexpr std::uint32_t kMaxFunctions = 131072;
constexpr std::uint32_t kMaxStrings = 262144;
constexpr std::uint32_t kMaxStringKinds = 262144;
constexpr std::uint64_t kMaxOpcodeBytes = 64ull * 1024 * 1024;
constexpr std::uint64_t kMaxDecodedStringBytes = 64ull * 1024 * 1024;

struct HermesOpcodeDef {
    std::string_view name;
    std::uint8_t length;
};

#include "hermes_opcodes.inc"

struct EpochLayout {
    std::uint32_t version;
    std::string_view label;
    std::span<const HermesOpcodeDef> opcodes;
    std::uint32_t small_function_header_size;
    std::uint32_t large_function_header_size;
    std::uint32_t debug_header_size;
};

const EpochLayout* layout_for(std::uint32_t version) {
    static const EpochLayout layouts[] = {
        {89, "Hermes legacy HBC v89", kHermesOpcodesV89, 16, 31, 20},
        {96, "Hermes legacy HBC v96", kHermesOpcodesV96, 16, 31, 28},
        {98, "Hermes V1 HBC v98", kHermesOpcodesV98, 12, 37, 16},
    };
    for (const auto& layout : layouts) if (layout.version == version) return &layout;
    return nullptr;
}

std::uint32_t u32(std::span<const std::uint8_t> data, std::uint64_t offset) {
    return std::uint32_t(data[static_cast<std::size_t>(offset)]) |
           (std::uint32_t(data[static_cast<std::size_t>(offset + 1)]) << 8) |
           (std::uint32_t(data[static_cast<std::size_t>(offset + 2)]) << 16) |
           (std::uint32_t(data[static_cast<std::size_t>(offset + 3)]) << 24);
}

std::string hex_bytes(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0f]);
    }
    return out;
}

bool add_size(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (a > std::numeric_limits<std::uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool mul_size(std::uint64_t a, std::uint64_t b, std::uint64_t& out) {
    if (a != 0 && b > std::numeric_limits<std::uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

bool align4(std::uint64_t value, std::uint64_t& out) {
    if (value > std::numeric_limits<std::uint64_t>::max() - 3) return false;
    out = (value + 3) & ~std::uint64_t(3);
    return true;
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

bool valid_utf8(std::span<const std::uint8_t> bytes) {
    for (std::size_t i = 0; i < bytes.size();) {
        const auto c = bytes[i];
        if (c < 0x80) { ++i; continue; }
        std::uint32_t cp = 0, minimum = 0;
        std::size_t width = 0;
        if ((c & 0xe0u) == 0xc0u) { width = 2; cp = c & 0x1fu; minimum = 0x80; }
        else if ((c & 0xf0u) == 0xe0u) { width = 3; cp = c & 0x0fu; minimum = 0x800; }
        else if ((c & 0xf8u) == 0xf0u) { width = 4; cp = c & 0x07u; minimum = 0x10000; }
        else return false;
        if (width > bytes.size() - i) return false;
        for (std::size_t n = 1; n < width; ++n) {
            const auto q = bytes[i + n];
            if ((q & 0xc0u) != 0x80u) return false;
            cp = (cp << 6) | (q & 0x3fu);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return false;
        i += width;
    }
    return true;
}

enum class Utf16DecodeResult { Ok, Malformed, BudgetExceeded };

Utf16DecodeResult decode_utf16(std::span<const std::uint8_t> bytes, std::uint64_t max_output_bytes, std::string& out) {
    if ((bytes.size() & 1u) != 0) return Utf16DecodeResult::Malformed;
    out.clear();
    for (std::size_t i = 0; i < bytes.size(); i += 2) {
        const auto first = std::uint32_t(bytes[i]) | (std::uint32_t(bytes[i + 1]) << 8);
        std::uint32_t cp = first;
        if (first >= 0xd800 && first <= 0xdbff) {
            if (i + 3 >= bytes.size()) return Utf16DecodeResult::Malformed;
            const auto second = std::uint32_t(bytes[i + 2]) | (std::uint32_t(bytes[i + 3]) << 8);
            if (second < 0xdc00 || second > 0xdfff) return Utf16DecodeResult::Malformed;
            cp = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            i += 2;
        } else if (first >= 0xdc00 && first <= 0xdfff) return Utf16DecodeResult::Malformed;
        const std::uint64_t width = cp <= 0x7f ? 1 : (cp <= 0x7ff ? 2 : (cp <= 0xffff ? 3 : 4));
        if (out.size() > max_output_bytes || width > max_output_bytes - out.size()) return Utf16DecodeResult::BudgetExceeded;
        append_utf8(out, cp);
    }
    return Utf16DecodeResult::Ok;
}

std::string csv_quote(const std::string& text) {
    std::string out = "\"";
    for (const auto c : text) { if (c == '"') out.push_back('"'); out.push_back(c); }
    out.push_back('"');
    return out;
}

}  // namespace

HermesInfo parse_hermes_bytecode(std::span<const std::uint8_t> data) {
    HermesInfo out;
    out.file_size = data.size();
    if (data.size() < kMagic.size() || !std::equal(kMagic.begin(), kMagic.end(), data.begin())) return out;
    out.candidate = true;
    if (data.size() < 12) {
        out.error = "Hermes bytecode version field is truncated";
        out.error_offset = 8;
        return out;
    }
    out.version = u32(data, 8);
    const auto* layout = layout_for(out.version);
    if (!layout) {
        out.epoch = "unsupported Hermes HBC epoch";
        out.anomalies.push_back("Hermes magic is exact, but this bytecode version has no audited table/function/opcode adapter");
        return out;
    }
    out.supported_epoch = true;
    out.epoch = std::string(layout->label);

    auto fail = [&](std::uint64_t offset, std::string message) -> HermesInfo {
        out.error_offset = offset;
        out.error = std::move(message);
        out.valid = false;
        out.parse_complete = false;
        return std::move(out);
    };
    if (data.size() < kHeaderSize + kFooterSize) return fail(data.size(), "Hermes bytecode header/footer is truncated");
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) return fail(32, "Hermes bytecode exceeds 32-bit fileLength contract");

    out.source_hash = hex_bytes(data.subspan(12, 20));
    out.declared_file_length = u32(data, 32);
    out.global_code_index = u32(data, 36);
    out.function_count = u32(data, 40);
    out.string_kind_count = u32(data, 44);
    out.identifier_count = u32(data, 48);
    out.string_count = u32(data, 52);
    out.overflow_string_count = u32(data, 56);
    out.string_storage_size = u32(data, 60);
    out.bigint_count = u32(data, 64);
    const auto bigint_storage_size = u32(data, 68);
    out.regexp_count = u32(data, 72);
    const auto regexp_storage_size = u32(data, 76);
    const auto value_buffer_size = u32(data, 80);
    const auto object_key_buffer_size = u32(data, 84);
    const auto third_buffer_count_or_size = u32(data, 88);
    out.cjs_module_count = u32(data, 96 + (out.version == 98 ? 4 : 0));
    out.function_source_count = u32(data, 100 + (out.version == 98 ? 4 : 0));
    const auto debug_offset = u32(data, 104 + (out.version == 98 ? 4 : 0));

    if (out.declared_file_length != data.size()) return fail(32, "Hermes fileLength does not equal the complete input size");
    if (out.function_count == 0 || out.global_code_index >= out.function_count) return fail(36, "Hermes global function index/count geometry is invalid");
    if (out.identifier_count > out.string_count || out.overflow_string_count > out.string_count) return fail(48, "Hermes string-table counts are inconsistent");

    const auto computed_hash = sha1_bytes(data.first(data.size() - kFooterSize));
    out.footer_hash_checked = true;
    out.file_hash = hex_bytes(data.last(kFooterSize));
    out.footer_hash_matches = std::equal(computed_hash.begin(), computed_hash.end(), data.end() - static_cast<std::ptrdiff_t>(kFooterSize));
    if (!out.footer_hash_matches) return fail(data.size() - kFooterSize, "Hermes bytecode footer SHA-1 does not match the preceding file bytes");

    if (out.function_count > kMaxFunctions || out.string_count > kMaxStrings || out.string_kind_count > kMaxStringKinds) {
        out.budget_limited = true;
        out.maps_truncated = true;
        out.anomalies.push_back("Hermes table cardinality exceeds the bounded parser allocation budget");
        return out;
    }

    const auto payload_end = std::uint64_t(data.size() - kFooterSize);
    std::uint64_t cursor = kHeaderSize;
    auto segment = [&](std::uint64_t count, std::uint64_t width, std::uint64_t& start, std::string_view name) -> bool {
        if (!align4(cursor, cursor)) { out.error = "Hermes segment alignment overflow"; return false; }
        start = cursor;
        std::uint64_t bytes = 0;
        if (!mul_size(count, width, bytes) || !add_size(cursor, bytes, cursor) || cursor > payload_end) {
            out.error = "Hermes " + std::string(name) + " exceeds the declared file";
            out.error_offset = start;
            return false;
        }
        return true;
    };
    std::uint64_t unused = 0;
    out.function_table_offset = cursor;
    if (!segment(out.function_count, layout->small_function_header_size, out.function_table_offset, "function table")) return out;
    if (!segment(out.string_kind_count, 4, out.string_kind_table_offset, "string-kind table")) return out;
    if (!segment(out.identifier_count, 4, out.identifier_hash_table_offset, "identifier-hash table")) return out;
    if (!segment(out.string_count, 4, out.string_table_offset, "small-string table")) return out;
    if (!segment(out.overflow_string_count, 8, out.overflow_string_table_offset, "overflow-string table")) return out;
    if (!segment(out.string_storage_size, 1, out.string_storage_offset, "string storage")) return out;
    if (!segment(value_buffer_size, 1, unused, out.version == 98 ? "literal-value buffer" : "array buffer")) return out;
    if (!segment(object_key_buffer_size, 1, unused, "object-key buffer")) return out;
    if (!segment(third_buffer_count_or_size, out.version == 98 ? 8 : 1, unused,
                 out.version == 98 ? "object-shape table" : "object-value buffer")) return out;
    if (!segment(out.bigint_count, 8, unused, "BigInt table")) return out;
    if (!segment(bigint_storage_size, 1, unused, "BigInt storage")) return out;
    if (!segment(out.regexp_count, 8, unused, "RegExp table")) return out;
    if (!segment(regexp_storage_size, 1, unused, "RegExp storage")) return out;
    if (!segment(out.cjs_module_count, 8, unused, "CommonJS module table")) return out;
    if (!segment(out.function_source_count, 8, unused, "function-source table")) return out;
    out.function_bytecode_begin = cursor;

    std::vector<bool> identifiers(out.string_count, false);
    std::uint64_t string_cursor = 0;
    std::uint64_t identifier_total = 0;
    for (std::uint32_t i = 0; i < out.string_kind_count; ++i) {
        const auto word = u32(data, out.string_kind_table_offset + std::uint64_t(i) * 4);
        const auto count = word & 0x7fffffffu;
        const bool identifier = (word & 0x80000000u) != 0;
        if (count == 0 || count > out.string_count - string_cursor) return fail(out.string_kind_table_offset + std::uint64_t(i) * 4, "Hermes string-kind run exceeds stringCount");
        if (identifier) {
            identifier_total += count;
            std::fill(identifiers.begin() + static_cast<std::ptrdiff_t>(string_cursor),
                      identifiers.begin() + static_cast<std::ptrdiff_t>(string_cursor + count), true);
        }
        string_cursor += count;
    }
    if (string_cursor != out.string_count || identifier_total != out.identifier_count) return fail(out.string_kind_table_offset, "Hermes string-kind runs do not exactly reproduce string/identifier counts");

    out.strings.reserve(out.string_count);
    std::uint32_t observed_overflow = 0;
    std::vector<bool> overflow_seen(out.overflow_string_count, false);
    std::uint64_t retained_decoded_bytes = 0;
    for (std::uint32_t i = 0; i < out.string_count; ++i) {
        const auto entry_offset = out.string_table_offset + std::uint64_t(i) * 4;
        const auto word = u32(data, entry_offset);
        const bool utf16 = (word & 1u) != 0;
        std::uint32_t offset = (word >> 1) & 0x7fffffu;
        std::uint32_t length = word >> 24;
        if (length == 0xffu) {
            if (offset >= out.overflow_string_count) return fail(entry_offset, "Hermes overflow-string index is out of range");
            if (overflow_seen[offset]) return fail(entry_offset, "Hermes overflow-string index is referenced more than once");
            overflow_seen[offset] = true;
            const auto overflow_offset = out.overflow_string_table_offset + std::uint64_t(offset) * 8;
            offset = u32(data, overflow_offset);
            length = u32(data, overflow_offset + 4);
            ++observed_overflow;
        }
        const std::uint64_t byte_length = std::uint64_t(length) * (utf16 ? 2u : 1u);
        if (offset > out.string_storage_size || byte_length > out.string_storage_size - offset) return fail(entry_offset, "Hermes string entry exceeds string storage");
        HermesStringInfo entry;
        entry.index = i;
        entry.storage_offset = out.string_storage_offset + offset;
        entry.length = length;
        entry.utf16 = utf16;
        entry.identifier = identifiers[i];
        const auto bytes = data.subspan(static_cast<std::size_t>(entry.storage_offset), static_cast<std::size_t>(byte_length));
        if (retained_decoded_bytes > kMaxDecodedStringBytes) {
            out.budget_limited = true;
            out.maps_truncated = true;
            out.anomalies.push_back("Hermes decoded string/function-name output exceeded the bounded 64 MiB map budget");
            return out;
        }
        const auto decoded_remaining = kMaxDecodedStringBytes - retained_decoded_bytes;
        if (utf16) {
            const auto decoded = decode_utf16(bytes, decoded_remaining, entry.value);
            if (decoded == Utf16DecodeResult::Malformed) return fail(entry_offset, "Hermes UTF-16 string entry is malformed");
            if (decoded == Utf16DecodeResult::BudgetExceeded) {
                out.budget_limited = true;
                out.maps_truncated = true;
                out.anomalies.push_back("Hermes decoded string/function-name output exceeded the bounded 64 MiB map budget");
                return out;
            }
        } else {
            if (!valid_utf8(bytes)) return fail(entry_offset, "Hermes UTF-8 string entry is malformed");
            if (bytes.size() > decoded_remaining) {
                out.budget_limited = true;
                out.maps_truncated = true;
                out.anomalies.push_back("Hermes decoded string/function-name output exceeded the bounded 64 MiB map budget");
                return out;
            }
            entry.value.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        }
        retained_decoded_bytes += entry.value.size();
        out.strings.push_back(std::move(entry));
    }
    if (observed_overflow != out.overflow_string_count) return fail(out.overflow_string_table_offset, "Hermes overflow-string table contains unreferenced or duplicate-index entries");

    struct FunctionRange { std::uint64_t begin, end; std::uint32_t index; };
    std::vector<FunctionRange> ranges;
    ranges.reserve(out.function_count);
    out.functions.reserve(out.function_count);
    std::uint64_t opcode_bytes = 0;
    for (std::uint32_t i = 0; i < out.function_count; ++i) {
        const auto small = out.function_table_offset + std::uint64_t(i) * layout->small_function_header_size;
        HermesFunctionInfo function;
        function.index = i;
        function.header_offset = small;
        std::uint8_t flags = 0;
        if (out.version < 98) {
            const auto w1 = u32(data, small);
            const auto w2 = u32(data, small + 4);
            const auto w3 = u32(data, small + 8);
            flags = data[static_cast<std::size_t>(small + 15)];
            function.overflow_header = (flags & 0x20u) != 0;
            if (function.overflow_header) {
                const auto large = (std::uint64_t(w3 & 0x01ffffffu) << 16) | (w1 & 0xffffu);
                if ((w1 & 0x01ff0000u) != 0 || large + layout->large_function_header_size > payload_end) return fail(small, "Hermes legacy overflow function-header pointer is invalid");
                function.header_offset = large;
                function.bytecode_offset = u32(data, large);
                function.param_count = u32(data, large + 4);
                function.bytecode_size = u32(data, large + 8);
                function.function_name_id = u32(data, large + 12);
                function.info_offset = u32(data, large + 16);
                if (function.info_offset != large) return fail(small, "Hermes legacy overflow function-header pointer/infoOffset binding is inconsistent");
                function.frame_size = u32(data, large + 20);
                function.environment_size = u32(data, large + 24);
                flags = data[static_cast<std::size_t>(large + 30)];
            } else {
                function.bytecode_offset = w1 & 0x01ffffffu;
                function.param_count = w1 >> 25;
                function.bytecode_size = w2 & 0x7fffu;
                function.function_name_id = w2 >> 15;
                function.info_offset = w3 & 0x01ffffffu;
                function.frame_size = w3 >> 25;
                function.environment_size = data[static_cast<std::size_t>(small + 12)];
            }
        } else {
            const auto w1 = u32(data, small);
            const auto w2 = u32(data, small + 4);
            flags = data[static_cast<std::size_t>(small + 11)];
            function.overflow_header = (flags & 0x20u) != 0;
            if (function.overflow_header) {
                const auto large = std::uint64_t(w1 & 0x01ffffffu) | (std::uint64_t((w2 >> 14) & 0xffu) << 24);
                if (large + layout->large_function_header_size > payload_end) return fail(small, "Hermes V1 overflow function-header pointer is invalid");
                function.header_offset = large;
                function.info_offset = large;
                function.bytecode_offset = u32(data, large);
                function.param_count = u32(data, large + 4);
                function.bytecode_size = u32(data, large + 12);
                function.function_name_id = u32(data, large + 16);
                function.frame_size = u32(data, large + 28);
                flags = data[static_cast<std::size_t>(large + 36)];
            } else {
                function.bytecode_offset = w1 & 0x01ffffffu;
                function.param_count = (w1 >> 25) & 0x1fu;
                function.bytecode_size = w2 & 0x3fffu;
                function.function_name_id = (w2 >> 14) & 0xffu;
                function.frame_size = data[static_cast<std::size_t>(small + 8)];
            }
        }
        function.strict_mode = (flags & 0x04u) != 0;
        function.has_exception_handler = (flags & 0x08u) != 0;
        function.has_debug_info = (flags & 0x10u) != 0;
        if (function.function_name_id >= out.strings.size()) return fail(function.header_offset, "Hermes function name string index is out of range");
        const auto& function_name = out.strings[function.function_name_id].value;
        if (retained_decoded_bytes > kMaxDecodedStringBytes ||
            function_name.size() > kMaxDecodedStringBytes - retained_decoded_bytes) {
            out.budget_limited = true;
            out.maps_truncated = true;
            out.anomalies.push_back("Hermes decoded string/function-name output exceeded the bounded 64 MiB map budget");
            return out;
        }
        retained_decoded_bytes += function_name.size();
        function.function_name = function_name;
        std::uint64_t body_end = 0;
        if (!add_size(function.bytecode_offset, function.bytecode_size, body_end) ||
            function.bytecode_offset < out.function_bytecode_begin || body_end > payload_end) {
            return fail(function.header_offset, "Hermes function bytecode range exceeds the function/data area");
        }
        if (function.info_offset != 0 && (function.info_offset < out.function_bytecode_begin || function.info_offset >= payload_end || (function.info_offset & 3u) != 0)) {
            return fail(function.header_offset, "Hermes function info offset is outside the aligned function-info area");
        }
        if (opcode_bytes > kMaxOpcodeBytes || function.bytecode_size > kMaxOpcodeBytes - opcode_bytes) {
            out.budget_limited = true;
        } else opcode_bytes += function.bytecode_size;
        ranges.push_back({function.bytecode_offset, body_end, i});
        out.functions.push_back(std::move(function));
    }
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) {
        return std::tie(a.begin, a.end, a.index) < std::tie(b.begin, b.end, b.index);
    });
    out.function_bytecode_end = out.function_bytecode_begin;
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        out.function_bytecode_end = std::max(out.function_bytecode_end, ranges[i].end);
        if (i == 0 || ranges[i].begin >= ranges[i - 1].end) continue;
        if (ranges[i].begin == ranges[i - 1].begin && ranges[i].end == ranges[i - 1].end) ++out.deduplicated_function_bodies;
        else return fail(ranges[i].begin, "Hermes function bytecode ranges partially overlap");
    }

    for (const auto& function : out.functions) {
        if (function.info_offset == 0) continue;
        if (function.info_offset < out.function_bytecode_end || function.info_offset >= debug_offset) {
            return fail(function.header_offset, "Hermes function info overlaps bytecode or the debug section");
        }
        if (function.overflow_header && function.header_offset + layout->large_function_header_size > debug_offset) {
            return fail(function.header_offset, "Hermes overflow function header overlaps the debug section");
        }
    }

    if (debug_offset == 0 || (debug_offset & 3u) != 0 || debug_offset < out.function_bytecode_end ||
        std::uint64_t(debug_offset) + layout->debug_header_size > payload_end) {
        return fail(104 + (out.version == 98 ? 4 : 0), "Hermes debug-info offset/header geometry is invalid");
    }
    out.debug.present = true;
    out.debug.offset = debug_offset;
    out.debug.filename_count = u32(data, debug_offset);
    out.debug.filename_storage_size = u32(data, debug_offset + 4);
    out.debug.file_region_count = u32(data, debug_offset + 8);
    if (out.version == 89) {
        out.debug.lexical_data_offset = u32(data, debug_offset + 12);
        out.debug.debug_data_size = u32(data, debug_offset + 16);
        if (out.debug.lexical_data_offset > out.debug.debug_data_size) return fail(debug_offset + 12, "Hermes v89 lexical debug offset exceeds debug data");
    } else if (out.version == 96) {
        out.debug.scope_desc_data_offset = u32(data, debug_offset + 12);
        out.debug.textified_callee_offset = u32(data, debug_offset + 16);
        out.debug.string_table_offset = u32(data, debug_offset + 20);
        out.debug.debug_data_size = u32(data, debug_offset + 24);
        if (out.debug.scope_desc_data_offset > out.debug.textified_callee_offset ||
            out.debug.textified_callee_offset > out.debug.string_table_offset ||
            out.debug.string_table_offset > out.debug.debug_data_size) {
            return fail(debug_offset + 12, "Hermes v96 debug subsection offsets are non-monotonic/out of range");
        }
    } else {
        out.debug.lexical_data_offset = u32(data, debug_offset + 12);
        out.debug.debug_data_size = out.debug.lexical_data_offset;
    }
    std::uint64_t debug_size = layout->debug_header_size;
    std::uint64_t amount = 0;
    if (!mul_size(out.debug.filename_count, 8, amount) || !add_size(debug_size, amount, debug_size) ||
        !add_size(debug_size, out.debug.filename_storage_size, debug_size) ||
        !mul_size(out.debug.file_region_count, 12, amount) || !add_size(debug_size, amount, debug_size) ||
        !add_size(debug_size, out.debug.debug_data_size, debug_size) ||
        !add_size(debug_offset, debug_size, out.debug.end_offset) || out.debug.end_offset != payload_end) {
        return fail(debug_offset, "Hermes debug tables do not close exactly at the bytecode footer");
    }
    out.debug.valid = true;

    if (out.budget_limited) {
        out.maps_truncated = true;
        out.anomalies.push_back("Hermes opcode decoding was deferred by the bounded 64 MiB opcode-byte budget");
        out.valid = true;
        return out;
    }

    std::vector<std::uint64_t> aggregate(layout->opcodes.size(), 0);
    for (auto& function : out.functions) {
        std::vector<std::uint32_t> local(layout->opcodes.size(), 0);
        auto cursor2 = function.bytecode_offset;
        const auto end = function.bytecode_offset + function.bytecode_size;
        while (cursor2 < end) {
            const auto opcode = data[static_cast<std::size_t>(cursor2)];
            if (opcode >= layout->opcodes.size()) return fail(cursor2, "Hermes function contains an opcode outside the audited epoch table");
            const auto length = layout->opcodes[opcode].length;
            if (length == 0 || length > end - cursor2) return fail(cursor2, "Hermes opcode operands exceed the declared function bytecode range");
            ++local[opcode];
            ++aggregate[opcode];
            ++function.instruction_count;
            cursor2 += length;
        }
        for (std::size_t opcode = 0; opcode < local.size(); ++opcode) if (local[opcode]) {
            function.opcodes.push_back({static_cast<std::uint16_t>(opcode), std::string(layout->opcodes[opcode].name), local[opcode]});
        }
    }
    for (std::size_t opcode = 0; opcode < aggregate.size(); ++opcode) if (aggregate[opcode]) {
        const auto count = aggregate[opcode] > std::numeric_limits<std::uint32_t>::max()
                               ? std::numeric_limits<std::uint32_t>::max()
                               : static_cast<std::uint32_t>(aggregate[opcode]);
        out.opcodes.push_back({static_cast<std::uint16_t>(opcode), std::string(layout->opcodes[opcode].name), count});
    }
    out.valid = true;
    out.parse_complete = true;
    return out;
}

Finding hermes_finding(const HermesInfo& info) {
    Finding finding;
    finding.kind = "bytecode";
    finding.family = "Hermes bytecode";
    finding.variant = info.epoch.empty() ? "HBC" : info.epoch;
    finding.fields["version"] = std::to_string(info.version);
    finding.fields["offset_space"] = "current_input_file";
    finding.fields["supported_epoch"] = info.supported_epoch ? "true" : "false";
    if (!info.supported_epoch) {
        finding.state = "PARTIAL";
        finding.evidence = {"exact Hermes HBC magic and bytecode version field recovered"};
        finding.negative_evidence = info.anomalies;
        finding.suggested_actions = {"use a matching Hermes compiler/runtime disassembler for this bytecode epoch", "do not infer JavaScript source semantics from an unaudited HBC version"};
        return finding;
    }
    if (!info.valid) {
        finding.state = info.budget_limited ? "PARTIAL" : "FAILED";
        if (!info.error.empty()) {
            std::ostringstream message;
            message << info.error << " at current-file offset 0x" << std::hex << info.error_offset;
            finding.negative_evidence.push_back(message.str());
        }
        for (const auto& anomaly : info.anomalies) finding.negative_evidence.push_back(anomaly);
        return finding;
    }
    finding.state = info.parse_complete ? "CONFIRMED" : "PARTIAL";
    finding.evidence = {
        "Hermes magic/version, complete version-specific table geometry and footer SHA-1 validated",
        "function/string/debug ranges close within the current HBC file without partial overlap",
    };
    if (info.parse_complete) finding.evidence.push_back("every function opcode stream closes exactly under the pinned epoch opcode table");
    finding.fields["file_length"] = std::to_string(info.declared_file_length);
    finding.fields["source_hash"] = info.source_hash;
    finding.fields["footer_sha1"] = info.file_hash;
    finding.fields["functions"] = std::to_string(info.function_count);
    finding.fields["strings"] = std::to_string(info.string_count);
    finding.fields["identifiers"] = std::to_string(info.identifier_count);
    finding.fields["opcodes_used"] = std::to_string(info.opcodes.size());
    finding.fields["debug_info"] = info.debug.valid ? "validated" : "absent";
    finding.fields["javascript_source_recovery_claimed"] = "false";
    finding.fields["runtime_load_claimed"] = "false";
    for (const auto& anomaly : info.anomalies) finding.negative_evidence.push_back(anomaly);
    finding.suggested_actions = {"extract:hermes-function-string-opcode-maps", "inspect named functions and high-frequency control/property opcodes first", "use the exact matching Hermes disassembler for instruction operands and control-flow semantics"};
    return finding;
}

HermesExtractResult extract_hermes_maps(const HermesInfo& info, const std::filesystem::path& functions_csv) {
    HermesExtractResult out;
    if (!info.valid || !info.parse_complete) {
        out.error = "Hermes maps require a completely validated supported HBC epoch";
        return out;
    }
    out.functions_csv = functions_csv;
    out.strings_csv = functions_csv;
    out.strings_csv.replace_filename("strings.csv");
    out.opcodes_csv = functions_csv;
    out.opcodes_csv.replace_filename("opcodes.csv");
    std::ofstream functions(out.functions_csv, std::ios::binary | std::ios::trunc);
    std::ofstream strings(out.strings_csv, std::ios::binary | std::ios::trunc);
    std::ofstream opcodes(out.opcodes_csv, std::ios::binary | std::ios::trunc);
    if (!functions || !strings || !opcodes) {
        out.error = "cannot create Hermes analysis maps";
        return out;
    }
    functions << "function_index,header_offset,bytecode_offset,bytecode_size,param_count,frame_size,function_name_id,function_name,instruction_count,strict_mode,has_exception_handler,has_debug_info,overflow_header\n";
    for (const auto& function : info.functions) {
        functions << function.index << ",0x" << std::hex << function.header_offset << ",0x" << function.bytecode_offset << std::dec << ','
                  << function.bytecode_size << ',' << function.param_count << ',' << function.frame_size << ',' << function.function_name_id << ','
                  << csv_quote(function.function_name) << ',' << function.instruction_count << ',' << (function.strict_mode ? "true" : "false") << ','
                  << (function.has_exception_handler ? "true" : "false") << ',' << (function.has_debug_info ? "true" : "false") << ','
                  << (function.overflow_header ? "true" : "false") << '\n';
    }
    strings << "string_index,storage_offset,length,encoding,identifier,value\n";
    for (const auto& entry : info.strings) {
        strings << entry.index << ",0x" << std::hex << entry.storage_offset << std::dec << ',' << entry.length << ','
                << (entry.utf16 ? "UTF-16LE" : "UTF-8") << ',' << (entry.identifier ? "true" : "false") << ',' << csv_quote(entry.value) << '\n';
    }
    opcodes << "opcode,name,count\n";
    for (const auto& opcode : info.opcodes) opcodes << opcode.opcode << ',' << csv_quote(opcode.name) << ',' << opcode.count << '\n';
    if (!functions || !strings || !opcodes) {
        out.error = "write Hermes analysis maps failed";
        return out;
    }
    out.function_count = info.functions.size();
    out.string_count = info.strings.size();
    out.opcode_count = info.opcodes.size();
    out.success = true;
    return out;
}

}  // namespace prts
