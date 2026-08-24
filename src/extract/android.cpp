#include "prts/android.hpp"
#include "prts/sha1.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iomanip>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace prts {
namespace {

constexpr std::uint32_t kNoIndex = 0xffffffffu;
constexpr std::uint32_t kEndianConstant = 0x12345678u;
constexpr std::uint32_t kReverseEndianConstant = 0x78563412u;
constexpr std::uint32_t kAccStatic = 0x0008u;
constexpr std::uint32_t kAccNative = 0x0100u;
constexpr std::uint32_t kAccAbstract = 0x0400u;

std::uint32_t dex_opcode_width(std::uint8_t op) {
    if(op==0x01||op==0x04||op==0x07||(op>=0x0a&&op<=0x12)||op==0x1d||op==0x1e||
       op==0x21||op==0x27||op==0x28||(op>=0x7b&&op<=0x8f)||(op>=0xb0&&op<=0xcf)) return 1;
    if(op==0x02||op==0x05||op==0x08||op==0x13||op==0x15||op==0x16||op==0x19||
       op==0x1a||op==0x1c||op==0x1f||op==0x20||op==0x22||op==0x23||op==0x29||
       (op>=0x2d&&op<=0x3d)||(op>=0x44&&op<=0x6d)||(op>=0x90&&op<=0xaf)||
       (op>=0xd0&&op<=0xe2)||op==0xfe||op==0xff) return 2;
    if(op==0x03||op==0x06||op==0x09||op==0x14||op==0x17||op==0x1b||op==0x24||
       op==0x25||op==0x26||op==0x2a||op==0x2b||op==0x2c||(op>=0x6e&&op<=0x72)||
       (op>=0x74&&op<=0x78)||op==0xfc||op==0xfd) return 3;
    if(op==0xfa||op==0xfb) return 4;
    if(op==0x18) return 5;
    return 0;
}

constexpr std::uint16_t kTypeHeaderItem = 0x0000;
constexpr std::uint16_t kTypeStringIdItem = 0x0001;
constexpr std::uint16_t kTypeTypeIdItem = 0x0002;
constexpr std::uint16_t kTypeProtoIdItem = 0x0003;
constexpr std::uint16_t kTypeFieldIdItem = 0x0004;
constexpr std::uint16_t kTypeMethodIdItem = 0x0005;
constexpr std::uint16_t kTypeClassDefItem = 0x0006;
constexpr std::uint16_t kTypeCallSiteIdItem = 0x0007;
constexpr std::uint16_t kTypeMethodHandleItem = 0x0008;
constexpr std::uint16_t kTypeMapList = 0x1000;
constexpr std::uint16_t kTypeTypeList = 0x1001;
constexpr std::uint16_t kTypeAnnotationSetRefList = 0x1002;
constexpr std::uint16_t kTypeAnnotationSetItem = 0x1003;
constexpr std::uint16_t kTypeClassDataItem = 0x2000;
constexpr std::uint16_t kTypeCodeItem = 0x2001;
constexpr std::uint16_t kTypeStringDataItem = 0x2002;
constexpr std::uint16_t kTypeDebugInfoItem = 0x2003;
constexpr std::uint16_t kTypeAnnotationItem = 0x2004;
constexpr std::uint16_t kTypeEncodedArrayItem = 0x2005;
constexpr std::uint16_t kTypeAnnotationsDirectoryItem = 0x2006;
constexpr std::uint16_t kTypeHiddenApiClassDataItem = 0xf000;

struct DexParseError final : std::runtime_error {
    DexParseError(std::uint64_t where, std::string what)
        : std::runtime_error(std::move(what)), offset(where) {}
    std::uint64_t offset;
};

[[noreturn]] void bad(std::uint64_t off, std::string msg) {
    throw DexParseError(off, std::move(msg));
}

std::uint32_t adler32(std::span<const std::uint8_t> data) {
    constexpr std::uint32_t mod = 65521;
    std::uint32_t a = 1, b = 0;
    // Small bounded chunks avoid overflow while remaining dependency-free.
    while (!data.empty()) {
        const auto n = std::min<std::size_t>(data.size(), 5552);
        for (std::size_t i = 0; i < n; ++i) {
            a += data[i];
            b += a;
        }
        a %= mod;
        b %= mod;
        data = data.subspan(n);
    }
    return (b << 16) | a;
}

std::string map_type_name(std::uint16_t type) {
    switch (type) {
        case kTypeHeaderItem: return "header_item";
        case kTypeStringIdItem: return "string_id_item";
        case kTypeTypeIdItem: return "type_id_item";
        case kTypeProtoIdItem: return "proto_id_item";
        case kTypeFieldIdItem: return "field_id_item";
        case kTypeMethodIdItem: return "method_id_item";
        case kTypeClassDefItem: return "class_def_item";
        case kTypeCallSiteIdItem: return "call_site_id_item";
        case kTypeMethodHandleItem: return "method_handle_item";
        case kTypeMapList: return "map_list";
        case kTypeTypeList: return "type_list";
        case kTypeAnnotationSetRefList: return "annotation_set_ref_list";
        case kTypeAnnotationSetItem: return "annotation_set_item";
        case kTypeClassDataItem: return "class_data_item";
        case kTypeCodeItem: return "code_item";
        case kTypeStringDataItem: return "string_data_item";
        case kTypeDebugInfoItem: return "debug_info_item";
        case kTypeAnnotationItem: return "annotation_item";
        case kTypeEncodedArrayItem: return "encoded_array_item";
        case kTypeAnnotationsDirectoryItem: return "annotations_directory_item";
        case kTypeHiddenApiClassDataItem: return "hiddenapi_class_data_item";
        default: {
            std::ostringstream o;
            o << "unknown_0x" << std::hex << type;
            return o.str();
        }
    }
}

std::uint32_t fixed_item_size(std::uint16_t type, bool v41) {
    switch (type) {
        case kTypeHeaderItem: return v41 ? 0x78u : 0x70u;
        case kTypeStringIdItem: return 4;
        case kTypeTypeIdItem: return 4;
        case kTypeProtoIdItem: return 12;
        case kTypeFieldIdItem: return 8;
        case kTypeMethodIdItem: return 8;
        case kTypeClassDefItem: return 32;
        case kTypeCallSiteIdItem: return 4;
        case kTypeMethodHandleItem: return 8;
        default: return 0;
    }
}

std::uint32_t fixed_alignment(std::uint16_t type) {
    switch (type) {
        case kTypeHeaderItem:
        case kTypeStringIdItem:
        case kTypeTypeIdItem:
        case kTypeProtoIdItem:
        case kTypeFieldIdItem:
        case kTypeMethodIdItem:
        case kTypeClassDefItem:
        case kTypeCallSiteIdItem:
        case kTypeMethodHandleItem:
        case kTypeMapList:
        case kTypeTypeList:
        case kTypeAnnotationSetRefList:
        case kTypeAnnotationSetItem:
        case kTypeCodeItem:
        case kTypeAnnotationsDirectoryItem:
            return 4;
        default: return 1;
    }
}

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7f) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ff) {
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

std::string utf16_units_to_utf8(const std::vector<std::uint16_t>& units, bool& had_isolated_surrogate) {
    std::string out;
    out.reserve(units.size());
    for (std::size_t i = 0; i < units.size(); ++i) {
        const auto u = units[i];
        if (u >= 0xd800 && u <= 0xdbff) {
            if (i + 1 < units.size() && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
                const auto cp = 0x10000u + ((std::uint32_t(u - 0xd800) << 10) |
                                            std::uint32_t(units[++i] - 0xdc00));
                append_utf8(out, cp);
            } else {
                had_isolated_surrogate = true;
                append_utf8(out, 0xfffd);
            }
        } else if (u >= 0xdc00 && u <= 0xdfff) {
            had_isolated_surrogate = true;
            append_utf8(out, 0xfffd);
        } else {
            append_utf8(out, u);
        }
    }
    return out;
}

std::string descriptor_name(std::string_view descriptor, bool allow_void, bool& ok) {
    ok = false;
    if (descriptor.empty()) return {};
    std::size_t pos = 0, dimensions = 0;
    while (pos < descriptor.size() && descriptor[pos] == '[') {
        ++pos;
        ++dimensions;
    }
    if (dimensions > 255 || pos >= descriptor.size()) return {};
    std::string base;
    switch (descriptor[pos]) {
        case 'V':
            if (!allow_void || dimensions != 0 || pos + 1 != descriptor.size()) return {};
            base = "void";
            ++pos;
            break;
        case 'Z': base = "boolean"; ++pos; break;
        case 'B': base = "byte"; ++pos; break;
        case 'S': base = "short"; ++pos; break;
        case 'C': base = "char"; ++pos; break;
        case 'I': base = "int"; ++pos; break;
        case 'J': base = "long"; ++pos; break;
        case 'F': base = "float"; ++pos; break;
        case 'D': base = "double"; ++pos; break;
        case 'L': {
            const auto end = descriptor.find(';', pos + 1);
            if (end == std::string_view::npos || end != descriptor.size() - 1 || end == pos + 1) return {};
            base.assign(descriptor.substr(pos + 1, end - pos - 1));
            std::replace(base.begin(), base.end(), '/', '.');
            pos = end + 1;
            break;
        }
        default: return {};
    }
    if (pos != descriptor.size()) return {};
    if (dimensions != 0 && base == "void") return {};
    for (std::size_t i = 0; i < dimensions; ++i) base += "[]";
    ok = true;
    return base;
}

char shorty_char(std::string_view descriptor) {
    if (descriptor.empty()) return 0;
    return descriptor[0] == '[' || descriptor[0] == 'L' ? 'L' : descriptor[0];
}

bool is_class_descriptor(std::string_view descriptor) {
    return descriptor.size() >= 3 && descriptor.front() == 'L' && descriptor.back() == ';';
}

bool is_method_definer_descriptor(std::string_view descriptor) {
    return is_class_descriptor(descriptor) || (!descriptor.empty() && descriptor.front() == '[');
}

bool printable_hint(std::string_view s) {
    if (s.size() < 4 || s.size() > 1024) return false;
    std::size_t printable = 0;
    for (unsigned char c : s) {
        if ((c >= 0x20 && c < 0x7f) || c >= 0x80) ++printable;
    }
    return printable * 100 / s.size() >= 85;
}

std::string csv_cell(std::string_view s) {
    bool quote = false;
    for (const char c : s) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') { quote = true; break; }
    }
    if (!quote) return std::string(s);
    std::string out = "\"";
    for (const char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

std::string join_pipe(const std::vector<std::string>& xs) {
    std::string out;
    for (std::size_t i = 0; i < xs.size(); ++i) {
        if (i) out += '|';
        out += xs[i];
    }
    return out;
}

class DexParser {
public:
    explicit DexParser(std::span<const std::uint8_t> bytes) : data_(bytes) {}

    DexInfo run() {
        DexInfo info;
        out_ = &info;
        try {
            parse_magic_and_header();
            if (!info.candidate) {
                out_ = nullptr;
                return info;
            }
            parse_map();
            parse_strings();
            parse_types();
            parse_protos();
            parse_fields();
            parse_methods();
            parse_method_handles();
            parse_call_sites();
            parse_classes();
            validate_map_dynamic_counts();
            build_jni_surfaces();
            build_implicit();
            validate_integrity();
            info.valid = true;
        } catch (const DexParseError& e) {
            info.error = e.what();
            info.error_offset = e.offset;
        } catch (const std::bad_alloc&) {
            info.error = "DEX parser allocation failed";
            info.error_offset = 0;
        }
        out_ = nullptr;
        return info;
    }

private:
    std::span<const std::uint8_t> data_;
    DexInfo* out_ = nullptr;
    bool reverse_ = false;
    std::uint64_t address_limit_ = 0;
    std::vector<std::vector<std::uint16_t>> string_units_;
    std::vector<std::string> type_descriptors_;
    std::vector<std::vector<std::uint16_t>> proto_parameter_type_indices_;
    std::unordered_map<std::uint32_t, std::vector<std::uint16_t>> type_list_cache_;
    std::unordered_set<std::uint32_t> class_data_offsets_;
    std::unordered_set<std::uint32_t> code_offsets_;
    std::unordered_set<std::uint32_t> debug_offsets_;
    std::unordered_set<std::uint32_t> type_list_offsets_;
    std::unordered_set<std::uint32_t> encoded_array_offsets_;

    void need(std::uint64_t off, std::uint64_t size, std::string_view what) const {
        if (off > data_.size() || size > data_.size() - off) {
            bad(off, std::string("truncated DEX ") + std::string(what));
        }
        if (address_limit_ != 0 && (off > address_limit_ || size > address_limit_ - off)) {
            bad(off, std::string("DEX ") + std::string(what) + " exceeds container bounds");
        }
    }

    std::uint16_t raw_u16(std::uint64_t off) const {
        need(off, 2, "ushort");
        return std::uint16_t(data_[off]) | (std::uint16_t(data_[off + 1]) << 8);
    }

    std::uint32_t raw_u32(std::uint64_t off) const {
        need(off, 4, "uint");
        return std::uint32_t(data_[off]) |
               (std::uint32_t(data_[off + 1]) << 8) |
               (std::uint32_t(data_[off + 2]) << 16) |
               (std::uint32_t(data_[off + 3]) << 24);
    }

    std::uint16_t u16(std::uint64_t off) const {
        auto x = raw_u16(off);
        if (reverse_) x = std::uint16_t((x >> 8) | (x << 8));
        return x;
    }

    std::uint32_t u32(std::uint64_t off) const {
        auto x = raw_u32(off);
        if (reverse_) {
            x = ((x & 0x000000ffu) << 24) | ((x & 0x0000ff00u) << 8) |
                ((x & 0x00ff0000u) >> 8) | ((x & 0xff000000u) >> 24);
        }
        return x;
    }

    std::uint32_t read_uleb(std::uint64_t& off, std::string_view what) const {
        std::uint32_t value = 0;
        for (unsigned i = 0; i < 5; ++i) {
            need(off, 1, what);
            const auto b = data_[off++];
            if (i == 4 && (b & 0xf0u) != 0) bad(off - 1, std::string("overflowing DEX ") + std::string(what));
            value |= std::uint32_t(b & 0x7fu) << (i * 7);
            if ((b & 0x80u) == 0) return value;
        }
        bad(off, std::string("unterminated DEX ") + std::string(what));
    }

    std::int32_t read_sleb(std::uint64_t& off, std::string_view what) const {
        std::uint32_t value = 0;
        std::uint8_t b = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 5; ++i) {
            need(off, 1, what);
            b = data_[off++];
            value |= std::uint32_t(b & 0x7fu) << shift;
            shift += 7;
            if ((b & 0x80u) == 0) {
                if (i == 4 && (b & 0x70u) != 0 && (b & 0x70u) != 0x70u) {
                    bad(off - 1, std::string("overflowing DEX ") + std::string(what));
                }
                if (shift < 32 && (b & 0x40u)) value |= (~0u << shift);
                return static_cast<std::int32_t>(value);
            }
        }
        bad(off, std::string("unterminated DEX ") + std::string(what));
    }

    bool in_data(std::uint32_t off) const {
        if (out_->container_v41) return off < out_->container_size;
        if (out_->data_size == 0) return false;
        return off >= out_->data_off && std::uint64_t(off) < std::uint64_t(out_->data_off) + out_->data_size;
    }

    void require_data_offset(std::uint32_t off, std::string_view what, bool allow_zero = false) const {
        if (off == 0 && allow_zero) return;
        if (!in_data(off)) bad(off, std::string(what) + " is outside DEX data section");
    }

    void check_table(std::uint32_t count, std::uint32_t off, std::uint32_t item_size,
                     std::uint32_t alignment, std::string_view what) const {
        if (count == 0) {
            if (off != 0) bad(off, std::string(what) + " offset must be zero when size is zero");
            return;
        }
        if (off == 0) bad(0, std::string(what) + " offset is zero with nonzero size");
        if (alignment > 1 && off % alignment != 0) bad(off, std::string(what) + " offset is misaligned");
        const auto bytes = std::uint64_t(count) * item_size;
        if (bytes > std::numeric_limits<std::uint32_t>::max() && data_.size() <= std::numeric_limits<std::uint32_t>::max()) {
            bad(off, std::string(what) + " size overflows DEX address space");
        }
        need(off, bytes, what);
    }

    void parse_magic_and_header() {
        if (data_.size() < 4 || data_[0] != 'd' || data_[1] != 'e' || data_[2] != 'x' || data_[3] != '\n') return;
        out_->candidate = true;
        need(0, 8, "magic");
        if (!std::isdigit(data_[4]) || !std::isdigit(data_[5]) || !std::isdigit(data_[6]) || data_[7] != 0) {
            bad(4, "invalid DEX version magic");
        }
        out_->version.assign(reinterpret_cast<const char*>(data_.data() + 4), 3);
        static const std::set<std::string> supported = {"035", "037", "038", "039", "040", "041"};
        if (!supported.contains(out_->version)) bad(4, "unsupported DEX version " + out_->version);
        out_->container_v41 = out_->version == "041";

        need(0, out_->container_v41 ? 0x78 : 0x70, "header");
        // endian_tag itself is interpreted from raw little-endian bytes to determine swapping.
        const auto endian_raw = raw_u32(0x28);
        if (endian_raw == kEndianConstant) reverse_ = false;
        else if (endian_raw == kReverseEndianConstant) reverse_ = true;
        else bad(0x28, "invalid DEX endian_tag");
        out_->reverse_endian = reverse_;

        out_->checksum = u32(0x08);
        out_->file_size = u32(0x20);
        out_->header_size = u32(0x24);
        const auto expected_header = out_->container_v41 ? 0x78u : 0x70u;
        if (out_->header_size != expected_header) bad(0x24, "unexpected DEX header_size");
        if (out_->file_size < out_->header_size) bad(0x20, "DEX file_size is smaller than header");

        out_->link_size = u32(0x2c);
        out_->link_off = u32(0x30);
        out_->map_off = u32(0x34);
        out_->string_ids_size = u32(0x38); out_->string_ids_off = u32(0x3c);
        out_->type_ids_size = u32(0x40); out_->type_ids_off = u32(0x44);
        out_->proto_ids_size = u32(0x48); out_->proto_ids_off = u32(0x4c);
        out_->field_ids_size = u32(0x50); out_->field_ids_off = u32(0x54);
        out_->method_ids_size = u32(0x58); out_->method_ids_off = u32(0x5c);
        out_->class_defs_size = u32(0x60); out_->class_defs_off = u32(0x64);
        out_->data_size = u32(0x68); out_->data_off = u32(0x6c);

        if (out_->container_v41) {
            out_->container_size = u32(0x70);
            out_->header_offset = u32(0x74);
            if (out_->header_offset != 0) bad(0x74, "parse_dex expects the first DEX v041 header at physical offset zero");
            if (out_->container_size < out_->file_size || out_->container_size > data_.size()) {
                bad(0x70, "invalid DEX v041 container_size");
            }
            if (out_->container_size != data_.size()) {
                out_->anomalies.push_back("physical input has bytes outside declared DEX v041 container_size");
            }
            address_limit_ = out_->container_size;
        } else {
            out_->container_size = out_->file_size;
            out_->header_offset = 0;
            if (out_->file_size != data_.size()) bad(0x20, "DEX file_size does not match physical input size");
            address_limit_ = out_->file_size;
            if (out_->data_size % 4 != 0) bad(0x68, "DEX data_size is not 4-byte aligned");
            if (out_->data_size != 0) {
                if (out_->data_off % 4 != 0) bad(0x6c, "DEX data_off is not 4-byte aligned");
                need(out_->data_off, out_->data_size, "data section");
            } else if (out_->data_off != 0) {
                bad(0x6c, "DEX data_off must be zero when data_size is zero");
            }
        }

        if (out_->map_off == 0 || out_->map_off % 4 != 0) bad(0x34, "DEX map_off is zero or misaligned");
        require_data_offset(out_->map_off, "DEX map_off");
        if ((out_->link_size == 0) != (out_->link_off == 0)) bad(0x2c, "DEX link_size/link_off zero-state mismatch");
        if (out_->link_size != 0) need(out_->link_off, out_->link_size, "link section");

        if (out_->type_ids_size > 65535) bad(0x40, "DEX type_ids_size exceeds 65535");
        if (out_->proto_ids_size > 65535) bad(0x48, "DEX proto_ids_size exceeds 65535");
        if (out_->class_defs_size > out_->type_ids_size) bad(0x60, "DEX class_defs_size exceeds type_ids_size");

        check_table(out_->string_ids_size, out_->string_ids_off, 4, 4, "string_ids");
        check_table(out_->type_ids_size, out_->type_ids_off, 4, 4, "type_ids");
        check_table(out_->proto_ids_size, out_->proto_ids_off, 12, 4, "proto_ids");
        check_table(out_->field_ids_size, out_->field_ids_off, 8, 4, "field_ids");
        check_table(out_->method_ids_size, out_->method_ids_off, 8, 4, "method_ids");
        check_table(out_->class_defs_size, out_->class_defs_off, 32, 4, "class_defs");
    }

    const DexMapItem* map_item(std::uint16_t type) const {
        const auto it = std::find_if(out_->map_items.begin(), out_->map_items.end(),
                                     [=](const DexMapItem& x) { return x.type == type; });
        return it == out_->map_items.end() ? nullptr : &*it;
    }

    void require_map_matches(std::uint16_t type, std::uint32_t size, std::uint32_t off,
                             std::string_view section) const {
        const auto* m = map_item(type);
        if (size == 0) {
            if (m != nullptr) bad(m->offset, std::string("DEX map contains empty header section ") + std::string(section));
            return;
        }
        if (m == nullptr) bad(out_->map_off, std::string("DEX map missing ") + std::string(section));
        if (m->size != size || m->offset != off) bad(m->offset, std::string("DEX map/header mismatch for ") + std::string(section));
    }

    void parse_map() {
        need(out_->map_off, 4, "map_list size");
        const auto count = u32(out_->map_off);
        if (count == 0 || count > (address_limit_ - out_->map_off - 4) / 12) bad(out_->map_off, "invalid DEX map_list size");
        out_->map_items.reserve(count);
        std::unordered_set<std::uint16_t> seen;
        std::uint32_t previous_offset = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto off = std::uint64_t(out_->map_off) + 4 + std::uint64_t(i) * 12;
            const auto type = u16(off);
            const auto unused = u16(off + 2);
            const auto size = u32(off + 4);
            const auto section_off = u32(off + 8);
            if (unused != 0) bad(off + 2, "nonzero DEX map_item unused field");
            if (size == 0) bad(off + 4, "zero-size DEX map_item");
            if (!seen.insert(type).second) bad(off, "duplicate DEX map_item type");
            if (i != 0 && section_off <= previous_offset) bad(off + 8, "DEX map_item offsets are not strictly increasing");
            if (section_off >= address_limit_) bad(off + 8, "DEX map_item offset is outside container");
            const auto alignment = fixed_alignment(type);
            if (alignment > 1 && section_off % alignment != 0) bad(off + 8, "misaligned DEX map_item section");
            const auto item_size = fixed_item_size(type, out_->container_v41);
            if (item_size != 0) need(section_off, std::uint64_t(item_size) * size, "mapped fixed-size section");
            if (type == kTypeMapList) {
                if (size != 1 || section_off != out_->map_off) bad(off + 4, "invalid DEX map_list self-entry");
                need(section_off, 4 + std::uint64_t(count) * 12, "map_list");
            }
            out_->map_items.push_back({type, size, section_off, map_type_name(type)});
            previous_offset = section_off;
        }
        const auto* header = map_item(kTypeHeaderItem);
        if (header == nullptr || header->size != 1 || header->offset != out_->header_offset) {
            bad(out_->map_off, "DEX map missing or mismatches header_item");
        }
        require_map_matches(kTypeStringIdItem, out_->string_ids_size, out_->string_ids_off, "string_ids");
        require_map_matches(kTypeTypeIdItem, out_->type_ids_size, out_->type_ids_off, "type_ids");
        require_map_matches(kTypeProtoIdItem, out_->proto_ids_size, out_->proto_ids_off, "proto_ids");
        require_map_matches(kTypeFieldIdItem, out_->field_ids_size, out_->field_ids_off, "field_ids");
        require_map_matches(kTypeMethodIdItem, out_->method_ids_size, out_->method_ids_off, "method_ids");
        require_map_matches(kTypeClassDefItem, out_->class_defs_size, out_->class_defs_off, "class_defs");

        // Check exact non-overlap for every fixed-width section against the next mapped section.
        for (std::size_t i = 0; i + 1 < out_->map_items.size(); ++i) {
            const auto& cur = out_->map_items[i];
            const auto& next = out_->map_items[i + 1];
            std::uint64_t end = cur.offset;
            if (const auto fixed = fixed_item_size(cur.type, out_->container_v41); fixed != 0) {
                end += std::uint64_t(fixed) * cur.size;
            } else if (cur.type == kTypeMapList) {
                end += 4 + std::uint64_t(out_->map_items.size()) * 12;
            }
            if (end > cur.offset && end > next.offset) bad(cur.offset, "overlapping fixed-size DEX map sections");
        }
        out_->map_complete = true;
    }

    std::pair<std::string, std::vector<std::uint16_t>> parse_mutf8(std::uint32_t string_data_off) {
        require_data_offset(string_data_off, "string_data_off");
        std::uint64_t off = string_data_off;
        const auto declared_units = read_uleb(off, "string_data utf16_size");
        std::vector<std::uint16_t> units;
        units.reserve(std::min<std::uint32_t>(declared_units, 4096));
        while (true) {
            need(off, 1, "MUTF-8 string");
            const auto c = data_[off++];
            if (c == 0) break;
            if (c < 0x80) {
                units.push_back(c);
                continue;
            }
            if ((c & 0xe0u) == 0xc0u) {
                need(off, 1, "MUTF-8 continuation");
                const auto c2 = data_[off++];
                if ((c2 & 0xc0u) != 0x80u) bad(off - 1, "invalid DEX MUTF-8 continuation");
                const auto u = std::uint16_t(((c & 0x1fu) << 6) | (c2 & 0x3fu));
                if (u == 0) {
                    if (c != 0xc0 || c2 != 0x80) bad(off - 2, "invalid DEX MUTF-8 NUL encoding");
                } else if (u < 0x80) {
                    bad(off - 2, "overlong DEX MUTF-8 two-byte sequence");
                }
                units.push_back(u);
                continue;
            }
            if ((c & 0xf0u) == 0xe0u) {
                need(off, 2, "MUTF-8 continuation");
                const auto c2 = data_[off++], c3 = data_[off++];
                if ((c2 & 0xc0u) != 0x80u || (c3 & 0xc0u) != 0x80u) bad(off - 2, "invalid DEX MUTF-8 continuation");
                const auto u = std::uint16_t(((c & 0x0fu) << 12) | ((c2 & 0x3fu) << 6) | (c3 & 0x3fu));
                if (u < 0x800) bad(off - 3, "overlong DEX MUTF-8 three-byte sequence");
                units.push_back(u);
                continue;
            }
            bad(off - 1, "invalid four-byte or malformed DEX MUTF-8 sequence");
        }
        if (units.size() != declared_units) bad(string_data_off, "DEX MUTF-8 utf16_size mismatch");
        bool isolated = false;
        auto utf8 = utf16_units_to_utf8(units, isolated);
        if (isolated) out_->anomalies.push_back("DEX string contains isolated UTF-16 surrogate code unit");
        return {std::move(utf8), std::move(units)};
    }

    void parse_strings() {
        out_->strings.reserve(out_->string_ids_size);
        string_units_.reserve(out_->string_ids_size);
        std::vector<std::uint32_t> data_offsets;
        data_offsets.reserve(out_->string_ids_size);
        for (std::uint32_t i = 0; i < out_->string_ids_size; ++i) {
            const auto off = out_->string_ids_off + std::uint64_t(i) * 4;
            const auto data_off = u32(off);
            if (data_off == 0) bad(off, "zero DEX string_data_off");
            if (!in_data(data_off)) bad(off, "DEX string_data_off points outside data section");
            const auto [s, units] = parse_mutf8(data_off);
            if (i != 0 && !(string_units_.back() < units)) bad(data_off, "DEX string_ids are unsorted or duplicate");
            if (printable_hint(s)) out_->string_hints.push_back(s);
            out_->strings.push_back(s);
            string_units_.push_back(units);
            data_offsets.push_back(data_off);
        }
        if (const auto* m = map_item(kTypeStringDataItem); out_->string_ids_size != 0) {
            if (m == nullptr || m->size != out_->string_ids_size) bad(out_->map_off, "DEX string_data map count mismatch");
        }
    }

    void parse_types() {
        out_->types.reserve(out_->type_ids_size);
        type_descriptors_.reserve(out_->type_ids_size);
        std::uint32_t previous_descriptor_idx = 0;
        for (std::uint32_t i = 0; i < out_->type_ids_size; ++i) {
            const auto off = out_->type_ids_off + std::uint64_t(i) * 4;
            const auto descriptor_idx = u32(off);
            if (descriptor_idx >= out_->strings.size()) bad(off, "DEX type descriptor_idx out of range");
            if (i != 0 && descriptor_idx <= previous_descriptor_idx) bad(off, "DEX type_ids are unsorted or duplicate");
            previous_descriptor_idx = descriptor_idx;
            const auto& descriptor = out_->strings[descriptor_idx];
            bool ok = false;
            auto name = descriptor_name(descriptor, true, ok);
            if (!ok) {
                out_->descriptor_parse_complete = false;
                bad(off, "invalid DEX type descriptor");
            }
            type_descriptors_.push_back(descriptor);
            out_->types.push_back(std::move(name));
        }
    }

    const std::vector<std::uint16_t>& parse_type_list(std::uint32_t off) {
        static const std::vector<std::uint16_t> empty;
        if (off == 0) return empty;
        if (const auto it = type_list_cache_.find(off); it != type_list_cache_.end()) return it->second;
        require_data_offset(off, "type_list offset");
        if (off % 4 != 0) bad(off, "misaligned DEX type_list");
        need(off, 4, "type_list size");
        const auto count = u32(off);
        if (count > (address_limit_ - off - 4) / 2) bad(off, "invalid DEX type_list size");
        std::vector<std::uint16_t> items;
        items.reserve(count);
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto idx = u16(off + 4 + std::uint64_t(i) * 2);
            if (idx >= out_->types.size()) bad(off + 4 + std::uint64_t(i) * 2, "DEX type_list index out of range");
            if (type_descriptors_[idx] == "V") bad(off + 4 + std::uint64_t(i) * 2, "void type in DEX type_list");
            items.push_back(idx);
        }
        type_list_offsets_.insert(off);
        return type_list_cache_.emplace(off, std::move(items)).first->second;
    }

    void parse_protos() {
        out_->protos.reserve(out_->proto_ids_size);
        proto_parameter_type_indices_.reserve(out_->proto_ids_size);
        std::pair<std::uint32_t, std::vector<std::uint16_t>> previous_key;
        bool have_previous = false;
        std::set<std::string> signatures;
        for (std::uint32_t i = 0; i < out_->proto_ids_size; ++i) {
            const auto off = out_->proto_ids_off + std::uint64_t(i) * 12;
            const auto shorty_idx = u32(off);
            const auto return_idx = u32(off + 4);
            const auto params_off = u32(off + 8);
            if (shorty_idx >= out_->strings.size()) bad(off, "DEX proto shorty_idx out of range");
            if (return_idx >= out_->types.size()) bad(off + 4, "DEX proto return_type_idx out of range");
            if (params_off != 0 && (!in_data(params_off) || params_off % 4 != 0)) bad(off + 8, "DEX proto parameters_off is invalid");
            const auto& pidx = parse_type_list(params_off);
            std::vector<std::uint16_t> indices(pidx.begin(), pidx.end());
            const auto key = std::make_pair(return_idx, indices);
            if (have_previous && !(previous_key < key)) bad(off, "DEX proto_ids are unsorted or duplicate");
            previous_key = key;
            have_previous = true;

            std::string expected_shorty;
            expected_shorty.push_back(shorty_char(type_descriptors_[return_idx]));
            DexProtoInfo p;
            p.index = i;
            p.shorty_idx = shorty_idx;
            p.return_type_idx = return_idx;
            p.parameters_off = params_off;
            p.shorty = out_->strings[shorty_idx];
            p.return_type = out_->types[return_idx];
            std::ostringstream sig;
            sig << '(';
            for (std::size_t z = 0; z < indices.size(); ++z) {
                if (z) sig << ", ";
                p.parameter_types.push_back(out_->types[indices[z]]);
                sig << out_->types[indices[z]];
                expected_shorty.push_back(shorty_char(type_descriptors_[indices[z]]));
            }
            sig << ") -> " << p.return_type;
            p.signature = sig.str();
            p.descriptor = "(";
            for (const auto idx : indices) p.descriptor += type_descriptors_[idx];
            p.descriptor += ")" + type_descriptors_[return_idx];
            if (p.shorty != expected_shorty) bad(off, "DEX proto shorty descriptor mismatch");
            if (!signatures.insert(p.signature).second) bad(off, "duplicate DEX method prototype signature");
            out_->protos.push_back(std::move(p));
            proto_parameter_type_indices_.push_back(std::move(indices));
        }
    }

    void parse_fields() {
        out_->fields.reserve(out_->field_ids_size);
        std::array<std::uint32_t, 3> previous{};
        bool have_previous = false;
        for (std::uint32_t i = 0; i < out_->field_ids_size; ++i) {
            const auto off = out_->field_ids_off + std::uint64_t(i) * 8;
            const auto class_idx = u16(off);
            const auto type_idx = u16(off + 2);
            const auto name_idx = u32(off + 4);
            if (class_idx >= out_->types.size()) bad(off, "DEX field class_idx out of range");
            if (type_idx >= out_->types.size()) bad(off + 2, "DEX field type_idx out of range");
            if (name_idx >= out_->strings.size()) bad(off + 4, "DEX field name_idx out of range");
            if (!is_class_descriptor(type_descriptors_[class_idx])) bad(off, "DEX field definer is not a class type");
            if (type_descriptors_[type_idx] == "V") bad(off + 2, "DEX field has void type");
            const std::array<std::uint32_t, 3> key = {class_idx, name_idx, type_idx};
            if (have_previous && !(previous < key)) bad(off, "DEX field_ids are unsorted or duplicate");
            previous = key;
            have_previous = true;
            DexFieldInfo f;
            f.index = i;
            f.class_idx = class_idx;
            f.type_idx = type_idx;
            f.name_idx = name_idx;
            f.owner = out_->types[class_idx];
            f.name = out_->strings[name_idx];
            f.type = out_->types[type_idx];
            f.signature = f.owner + "::" + f.name + ": " + f.type;
            out_->fields.push_back(std::move(f));
        }
    }

    void parse_methods() {
        out_->methods.reserve(out_->method_ids_size);
        std::array<std::uint32_t, 3> previous{};
        bool have_previous = false;
        for (std::uint32_t i = 0; i < out_->method_ids_size; ++i) {
            const auto off = out_->method_ids_off + std::uint64_t(i) * 8;
            const auto class_idx = u16(off);
            const auto proto_idx = u16(off + 2);
            const auto name_idx = u32(off + 4);
            if (class_idx >= out_->types.size()) bad(off, "DEX method class_idx out of range");
            if (proto_idx >= out_->protos.size()) bad(off + 2, "DEX method proto_idx out of range");
            if (name_idx >= out_->strings.size()) bad(off + 4, "DEX method name_idx out of range");
            if (!is_method_definer_descriptor(type_descriptors_[class_idx])) bad(off, "DEX method definer is not a class or array type");
            const std::array<std::uint32_t, 3> key = {class_idx, name_idx, proto_idx};
            if (have_previous && !(previous < key)) bad(off, "DEX method_ids are unsorted or duplicate");
            previous = key;
            have_previous = true;
            DexMethodInfo m;
            m.index = i;
            m.class_idx = class_idx;
            m.proto_idx = proto_idx;
            m.name_idx = name_idx;
            m.owner = out_->types[class_idx];
            m.name = out_->strings[name_idx];
            m.signature = m.owner + "::" + m.name + out_->protos[proto_idx].signature;
            m.owner_descriptor = type_descriptors_[class_idx];
            m.descriptor = out_->protos[proto_idx].descriptor;
            out_->methods.push_back(std::move(m));
        }
    }

    struct EncodedValueSummary {
        std::uint8_t type = 0;
        std::uint32_t index = 0;
    };

    std::uint32_t encoded_uint(std::uint64_t& cursor, unsigned bytes, std::string_view what) const {
        if (bytes == 0 || bytes > 4) bad(cursor, std::string("invalid DEX ") + std::string(what) + " width");
        need(cursor, bytes, what);
        std::uint32_t value = 0;
        // encoded_value payload bytes are explicitly little-endian regardless of dex byte swapping.
        for (unsigned i = 0; i < bytes; ++i) value |= std::uint32_t(data_[cursor++]) << (i * 8);
        return value;
    }

    std::vector<EncodedValueSummary> parse_encoded_array(std::uint64_t& cursor, unsigned depth) {
        if (depth > 64) bad(cursor, "DEX encoded_value nesting is too deep");
        const auto count_at = cursor;
        const auto count = read_uleb(cursor, "encoded_array size");
        if (count > address_limit_) bad(count_at, "DEX encoded_array size is unreasonable");
        std::vector<EncodedValueSummary> values;
        values.reserve(std::min<std::uint32_t>(count, 4096));
        for (std::uint32_t i = 0; i < count; ++i) values.push_back(parse_encoded_value(cursor, depth + 1));
        return values;
    }

    void parse_encoded_annotation(std::uint64_t& cursor, unsigned depth) {
        if (depth > 64) bad(cursor, "DEX encoded_annotation nesting is too deep");
        const auto type_at = cursor;
        const auto type_idx = read_uleb(cursor, "encoded_annotation type_idx");
        if (type_idx >= out_->types.size() || !is_class_descriptor(type_descriptors_[type_idx])) {
            bad(type_at, "DEX encoded_annotation type_idx is invalid");
        }
        const auto count_at = cursor;
        const auto count = read_uleb(cursor, "encoded_annotation size");
        if (count > out_->strings.size()) bad(count_at, "DEX encoded_annotation element count is unreasonable");
        std::uint32_t previous_name = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto name_at = cursor;
            const auto name_idx = read_uleb(cursor, "annotation_element name_idx");
            if (name_idx >= out_->strings.size()) bad(name_at, "DEX annotation element name_idx out of range");
            if (i != 0 && name_idx <= previous_name) bad(name_at, "DEX annotation elements are unsorted or duplicate");
            previous_name = name_idx;
            (void)parse_encoded_value(cursor, depth + 1);
        }
    }

    EncodedValueSummary parse_encoded_value(std::uint64_t& cursor, unsigned depth) {
        if (depth > 64) bad(cursor, "DEX encoded_value nesting is too deep");
        need(cursor, 1, "encoded_value header");
        const auto at = cursor;
        const auto header = data_[cursor++];
        const auto value_type = std::uint8_t(header & 0x1fu);
        const auto value_arg = std::uint8_t(header >> 5);
        EncodedValueSummary result{value_type, 0};
        auto scalar = [&](unsigned max_arg, std::string_view what) {
            if (value_arg > max_arg) bad(at, std::string("invalid DEX ") + std::string(what) + " value_arg");
            need(cursor, unsigned(value_arg) + 1, what);
            cursor += unsigned(value_arg) + 1;
        };
        auto index = [&](std::size_t limit, std::string_view what) {
            if (value_arg > 3) bad(at, std::string("invalid DEX ") + std::string(what) + " value_arg");
            const auto idx = encoded_uint(cursor, unsigned(value_arg) + 1, what);
            if (idx >= limit) bad(at, std::string("DEX ") + std::string(what) + " index out of range");
            result.index = idx;
        };
        switch (value_type) {
            case 0x00:  // VALUE_BYTE
                if (value_arg != 0) bad(at, "invalid DEX VALUE_BYTE value_arg");
                scalar(0, "VALUE_BYTE");
                break;
            case 0x02: scalar(1, "VALUE_SHORT"); break;
            case 0x03: scalar(1, "VALUE_CHAR"); break;
            case 0x04: scalar(3, "VALUE_INT"); break;
            case 0x06: scalar(7, "VALUE_LONG"); break;
            case 0x10: scalar(3, "VALUE_FLOAT"); break;
            case 0x11: scalar(7, "VALUE_DOUBLE"); break;
            case 0x15: index(out_->protos.size(), "VALUE_METHOD_TYPE"); break;
            case 0x16: index(out_->method_handles.size(), "VALUE_METHOD_HANDLE"); break;
            case 0x17: index(out_->strings.size(), "VALUE_STRING"); break;
            case 0x18: index(out_->types.size(), "VALUE_TYPE"); break;
            case 0x19: index(out_->fields.size(), "VALUE_FIELD"); break;
            case 0x1a: index(out_->methods.size(), "VALUE_METHOD"); break;
            case 0x1b: index(out_->fields.size(), "VALUE_ENUM"); break;
            case 0x1c:
                if (value_arg != 0) bad(at, "invalid DEX VALUE_ARRAY value_arg");
                (void)parse_encoded_array(cursor, depth + 1);
                break;
            case 0x1d:
                if (value_arg != 0) bad(at, "invalid DEX VALUE_ANNOTATION value_arg");
                parse_encoded_annotation(cursor, depth + 1);
                break;
            case 0x1e:
                if (value_arg != 0) bad(at, "invalid DEX VALUE_NULL value_arg");
                break;
            case 0x1f:
                if (value_arg > 1) bad(at, "invalid DEX VALUE_BOOLEAN value_arg");
                result.index = value_arg;
                break;
            default:
                bad(at, "unknown DEX encoded_value type");
        }
        return result;
    }

    std::vector<EncodedValueSummary> parse_encoded_array_item(std::uint32_t off, std::uint64_t ref_off,
                                                               std::string_view what, std::uint64_t* end = nullptr) {
        if (!in_data(off)) bad(ref_off, std::string("DEX ") + std::string(what) + " offset is invalid");
        encoded_array_offsets_.insert(off);
        std::uint64_t cursor = off;
        auto values = parse_encoded_array(cursor, 0);
        if (end != nullptr) *end = cursor;
        return values;
    }

    void parse_method_handles() {
        const auto* map = map_item(kTypeMethodHandleItem);
        if (map == nullptr) return;
        if (out_->version < "038") bad(map->offset, "DEX method_handles require version 038 or newer");
        out_->method_handles.reserve(map->size);
        for (std::uint32_t i = 0; i < map->size; ++i) {
            const auto off = map->offset + std::uint64_t(i) * 8;
            const auto handle_type = u16(off);
            const auto unused1 = u16(off + 2);
            const auto target_idx = u16(off + 4);
            const auto unused2 = u16(off + 6);
            if (handle_type > 8) bad(off, "invalid DEX method_handle_type");
            if (unused1 != 0 || unused2 != 0) bad(off + 2, "nonzero DEX method_handle unused field");
            DexMethodHandleInfo h;
            h.index = i;
            h.handle_type = handle_type;
            h.field_or_method_id = target_idx;
            h.references_field = handle_type <= 3;
            if (h.references_field) {
                if (target_idx >= out_->fields.size()) bad(off + 4, "DEX method_handle field index out of range");
                h.target = out_->fields[target_idx].signature;
            } else {
                if (target_idx >= out_->methods.size()) bad(off + 4, "DEX method_handle method index out of range");
                if (handle_type == 6 && out_->methods[target_idx].name != "<init>") {
                    bad(off + 4, "DEX constructor method_handle does not target <init>");
                }
                h.target = out_->methods[target_idx].signature;
            }
            out_->method_handles.push_back(std::move(h));
        }
    }

    void parse_call_sites() {
        const auto* map = map_item(kTypeCallSiteIdItem);
        if (map == nullptr) return;
        if (out_->version < "038") bad(map->offset, "DEX call_site_ids require version 038 or newer");
        out_->call_sites.reserve(map->size);
        std::uint32_t previous_off = 0;
        for (std::uint32_t i = 0; i < map->size; ++i) {
            const auto id_off = map->offset + std::uint64_t(i) * 4;
            const auto call_site_off = u32(id_off);
            if (i != 0 && call_site_off <= previous_off) bad(id_off, "DEX call_site_ids are unsorted or duplicate");
            previous_off = call_site_off;
            std::uint64_t call_site_end = call_site_off;
            auto values = parse_encoded_array_item(call_site_off, id_off, "call_site_off", &call_site_end);
            if (values.size() < 3) bad(call_site_off, "DEX call_site_item has fewer than three bootstrap arguments");
            if (values[0].type != 0x16 || values[1].type != 0x17 || values[2].type != 0x15) {
                bad(call_site_off, "DEX call_site_item bootstrap argument types are invalid");
            }
            DexCallSiteInfo c;
            c.index = i;
            c.call_site_off = call_site_off;
            c.call_site_size = static_cast<std::uint32_t>(call_site_end - call_site_off);
            c.bootstrap_method_handle_idx = values[0].index;
            c.method_name_idx = values[1].index;
            c.method_type_idx = values[2].index;
            c.extra_argument_count = static_cast<std::uint32_t>(values.size() - 3);
            const auto& bootstrap_handle = out_->method_handles[c.bootstrap_method_handle_idx];
            if (bootstrap_handle.references_field) bad(call_site_off, "DEX call_site bootstrap handle references a field");
            const auto bootstrap_method_idx = bootstrap_handle.field_or_method_id;
            if (bootstrap_method_idx >= out_->methods.size()) bad(call_site_off, "DEX call_site bootstrap method index is invalid");
            const auto& bootstrap_method = out_->methods[bootstrap_method_idx];
            if (out_->protos[bootstrap_method.proto_idx].return_type != "java.lang.invoke.CallSite") {
                bad(call_site_off, "DEX call_site bootstrap method does not return java.lang.invoke.CallSite");
            }
            c.bootstrap_target = bootstrap_handle.target;
            c.method_name = out_->strings[c.method_name_idx];
            c.method_type = out_->protos[c.method_type_idx].signature;
            out_->call_sites.push_back(std::move(c));
        }
    }

    std::uint32_t parameter_word_count(std::uint16_t proto_idx, bool is_static) const {
        std::uint32_t words = is_static ? 0u : 1u;
        for (const auto type_idx : proto_parameter_type_indices_.at(proto_idx)) {
            const auto& d = type_descriptors_[type_idx];
            words += (d == "J" || d == "D") ? 2u : 1u;
        }
        return words;
    }

    void validate_index_p1(std::uint32_t encoded, std::size_t limit, std::uint64_t off,
                           std::string_view what) const {
        if (encoded == 0) return;
        const auto idx = encoded - 1;
        if (idx >= limit) bad(off, std::string("DEX debug ") + std::string(what) + " index out of range");
    }

    void parse_debug_info(DexCodeInfo& code, std::uint16_t proto_idx) {
        if (code.debug_info_off == 0) return;
        require_data_offset(code.debug_info_off, "debug_info_off");
        debug_offsets_.insert(code.debug_info_off);
        std::uint64_t off = code.debug_info_off;
        // R8/D8 uses startLine=0 for synthetic/no-position debug streams. It is
        // harmless as long as no emitted position uses line 0.
        code.debug_line_start = read_uleb(off, "debug line_start");
        const auto parameter_count = read_uleb(off, "debug parameters_size");
        if (parameter_count != proto_parameter_type_indices_[proto_idx].size()) {
            bad(off, "DEX debug parameters_size does not match method prototype");
        }
        code.parameter_names.reserve(parameter_count);
        for (std::uint32_t i = 0; i < parameter_count; ++i) {
            const auto at = off;
            const auto encoded = read_uleb(off, "debug parameter name_idx+1");
            validate_index_p1(encoded, out_->strings.size(), at, "parameter name");
            code.parameter_names.push_back(encoded == 0 ? std::string{} : out_->strings[encoded - 1]);
        }

        std::uint32_t address = 0;
        std::int64_t line = code.debug_line_start;
        std::uint64_t operations = 0;
        while (true) {
            if (++operations > address_limit_) bad(off, "DEX debug opcode stream is unreasonably long");
            need(off, 1, "debug opcode");
            const auto op_at = off;
            const auto op = data_[off++];
            switch (op) {
                case 0x00:  // DBG_END_SEQUENCE
                    ++out_->debug_info_count;
                    return;
                case 0x01: {  // DBG_ADVANCE_PC
                    const auto delta = read_uleb(off, "DBG_ADVANCE_PC");
                    if (delta > std::numeric_limits<std::uint32_t>::max() - address) bad(op_at, "DEX debug address overflow");
                    address += delta;
                    if (address > code.insns_size) bad(op_at, "DEX debug address advances beyond code_item");
                    break;
                }
                case 0x02: {  // DBG_ADVANCE_LINE
                    line += read_sleb(off, "DBG_ADVANCE_LINE");
                    if (line < 0 || line > std::numeric_limits<std::int32_t>::max()) bad(op_at, "DEX debug line register is invalid");
                    break;
                }
                case 0x03: {  // DBG_START_LOCAL
                    const auto reg_at = off;
                    const auto reg = read_uleb(off, "DBG_START_LOCAL register");
                    if (reg >= code.registers_size) bad(reg_at, "DEX debug local register out of range");
                    auto at = off; auto name = read_uleb(off, "DBG_START_LOCAL name_idx+1");
                    validate_index_p1(name, out_->strings.size(), at, "local name");
                    at = off; auto type = read_uleb(off, "DBG_START_LOCAL type_idx+1");
                    validate_index_p1(type, out_->types.size(), at, "local type");
                    break;
                }
                case 0x04: {  // DBG_START_LOCAL_EXTENDED
                    const auto reg_at = off;
                    const auto reg = read_uleb(off, "DBG_START_LOCAL_EXTENDED register");
                    if (reg >= code.registers_size) bad(reg_at, "DEX debug local register out of range");
                    auto at = off; auto name = read_uleb(off, "DBG_START_LOCAL_EXTENDED name_idx+1");
                    validate_index_p1(name, out_->strings.size(), at, "local name");
                    at = off; auto type = read_uleb(off, "DBG_START_LOCAL_EXTENDED type_idx+1");
                    validate_index_p1(type, out_->types.size(), at, "local type");
                    at = off; auto sig = read_uleb(off, "DBG_START_LOCAL_EXTENDED sig_idx+1");
                    validate_index_p1(sig, out_->strings.size(), at, "local signature");
                    break;
                }
                case 0x05:  // DBG_END_LOCAL
                case 0x06: {  // DBG_RESTART_LOCAL
                    const auto reg_at = off;
                    const auto reg = read_uleb(off, op == 0x05 ? "DBG_END_LOCAL register" : "DBG_RESTART_LOCAL register");
                    if (reg >= code.registers_size) bad(reg_at, "DEX debug local register out of range");
                    break;
                }
                case 0x07:  // DBG_SET_PROLOGUE_END
                case 0x08:  // DBG_SET_EPILOGUE_BEGIN
                    break;
                case 0x09: {  // DBG_SET_FILE
                    const auto at = off;
                    const auto name = read_uleb(off, "DBG_SET_FILE name_idx+1");
                    validate_index_p1(name, out_->strings.size(), at, "source file");
                    break;
                }
                default: {
                    // Special opcode: address += adjusted / 15; line += -4 + adjusted % 15.
                    if (op < 0x0a) bad(op_at, "unknown DEX debug opcode");
                    const auto adjusted = std::uint32_t(op - 0x0a);
                    const auto address_delta = adjusted / 15;
                    if (address_delta > std::numeric_limits<std::uint32_t>::max() - address) bad(op_at, "DEX debug address overflow");
                    address += address_delta;
                    line += -4 + static_cast<std::int32_t>(adjusted % 15);
                    if (address >= code.insns_size && code.insns_size != 0) bad(op_at, "DEX debug position points outside code_item");
                    if (line < 0 || line > std::numeric_limits<std::int32_t>::max()) bad(op_at, "DEX debug line register is invalid");
                    if (line == 0 && std::find(out_->anomalies.begin(), out_->anomalies.end(),
                                               "DEX debug stream emits synthetic line 0") == out_->anomalies.end()) {
                        out_->anomalies.push_back("DEX debug stream emits synthetic line 0");
                    }
                    ++code.debug_position_count;
                    break;
                }
            }
        }
    }

    DexCodeInfo parse_code_item(std::uint32_t method_idx, std::uint32_t access_flags,
                                std::uint32_t code_off) {
        if (code_off % 4 != 0) bad(code_off, "misaligned DEX code_item");
        require_data_offset(code_off, "code_off");
        if (!code_offsets_.insert(code_off).second) bad(code_off, "multiple DEX methods reference the same code_item");
        need(code_off, 16, "code_item header");

        DexCodeInfo code;
        code.method_idx = method_idx;
        code.access_flags = access_flags;
        code.code_off = code_off;
        code.registers_size = u16(code_off);
        code.ins_size = u16(code_off + 2);
        code.outs_size = u16(code_off + 4);
        code.tries_size = u16(code_off + 6);
        code.debug_info_off = u32(code_off + 8);
        if (code.debug_info_off != 0 && !in_data(code.debug_info_off)) bad(code_off + 8, "DEX code_item debug_info_off is invalid");
        code.insns_size = u32(code_off + 12);
        if (code.registers_size < code.ins_size) bad(code_off, "DEX code_item registers_size is smaller than ins_size");

        const auto& method = out_->methods[method_idx];
        const auto expected_ins = parameter_word_count(method.proto_idx, (access_flags & kAccStatic) != 0);
        if (code.ins_size != expected_ins) bad(code_off + 2, "DEX code_item ins_size does not match method prototype/access flags");

        const auto insn_bytes = std::uint64_t(code.insns_size) * 2;
        need(std::uint64_t(code_off) + 16, insn_bytes, "code_item instructions");
        std::uint64_t cursor = std::uint64_t(code_off) + 16 + insn_bytes;

        std::vector<std::uint16_t> try_handler_offsets;
        if (code.tries_size != 0) {
            if ((code.insns_size & 1u) != 0) {
                if (u16(cursor) != 0) bad(cursor, "nonzero DEX code_item padding");
                cursor += 2;
            }
            const auto tries_off = cursor;
            need(tries_off, std::uint64_t(code.tries_size) * 8, "try_item array");
            std::uint64_t previous_end = 0;
            try_handler_offsets.reserve(code.tries_size);
            for (std::uint32_t i = 0; i < code.tries_size; ++i) {
                const auto at = tries_off + std::uint64_t(i) * 8;
                const auto start = u32(at);
                const auto count = u16(at + 4);
                const auto handler_off = u16(at + 6);
                if (count == 0 || std::uint64_t(start) + count > code.insns_size) bad(at, "DEX try_item range exceeds code_item");
                if (i != 0 && start < previous_end) bad(at, "DEX try_item ranges overlap or are unsorted");
                previous_end = std::uint64_t(start) + count;
                try_handler_offsets.push_back(handler_off);
            }
            cursor += std::uint64_t(code.tries_size) * 8;
            const auto handlers_start = cursor;
            const auto handler_count = read_uleb(cursor, "encoded_catch_handler_list size");
            if (handler_count == 0) bad(handlers_start, "empty DEX encoded_catch_handler_list with nonzero tries_size");
            std::unordered_set<std::uint32_t> handler_starts;
            handler_starts.reserve(handler_count);
            for (std::uint32_t i = 0; i < handler_count; ++i) {
                const auto relative = cursor - handlers_start;
                if (relative > 0xffffu) bad(cursor, "DEX catch handler offset exceeds try_item representation");
                handler_starts.insert(static_cast<std::uint32_t>(relative));
                const auto typed_count_signed = read_sleb(cursor, "encoded_catch_handler size");
                const auto typed_count = typed_count_signed < 0
                    ? std::uint64_t(-std::int64_t(typed_count_signed))
                    : std::uint64_t(typed_count_signed);
                if (typed_count > out_->types.size()) bad(cursor, "DEX catch handler type count is unreasonable");
                for (std::uint64_t z = 0; z < typed_count; ++z) {
                    const auto type_at = cursor;
                    const auto type_idx = read_uleb(cursor, "catch handler type_idx");
                    if (type_idx >= out_->types.size()) bad(type_at, "DEX catch handler type_idx out of range");
                    const auto addr_at = cursor;
                    const auto addr = read_uleb(cursor, "catch handler address");
                    if (addr >= code.insns_size) bad(addr_at, "DEX catch handler address outside code_item");
                }
                if (typed_count_signed <= 0) {
                    const auto addr_at = cursor;
                    const auto addr = read_uleb(cursor, "catch-all handler address");
                    if (addr >= code.insns_size) bad(addr_at, "DEX catch-all address outside code_item");
                }
            }
            for (const auto handler_off : try_handler_offsets) {
                if (!handler_starts.contains(handler_off)) bad(handlers_start + handler_off, "DEX try_item handler_off is not a catch-handler boundary");
            }
        }
        const auto size = cursor - code_off;
        if (size > std::numeric_limits<std::uint32_t>::max()) bad(code_off, "DEX code_item size overflow");
        code.code_size_bytes = static_cast<std::uint32_t>(size);
        parse_debug_info(code, method.proto_idx);
        ++out_->code_item_count;
        return code;
    }

    void parse_field_list(std::uint64_t& cursor, std::uint32_t count, std::uint32_t class_idx) {
        std::uint32_t current = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto idx_at = cursor;
            const auto diff = read_uleb(cursor, "encoded_field field_idx_diff");
            if (i != 0 && diff == 0) bad(idx_at, "duplicate/unsorted DEX encoded_field index");
            if (diff > std::numeric_limits<std::uint32_t>::max() - current) bad(idx_at, "DEX encoded_field index overflow");
            current += diff;
            if (current >= out_->fields.size()) bad(idx_at, "DEX encoded_field index out of range");
            const auto access_flags = read_uleb(cursor, "encoded_field access_flags");
            auto& field = out_->fields[current];
            if (field.class_idx != class_idx) bad(idx_at, "DEX encoded_field definer does not match class_data_item");
            if (field.defined) bad(idx_at, "DEX field defined more than once");
            field.defined = true;
            field.access_flags = access_flags;
            ++out_->defined_field_count;
        }
    }

    void parse_method_list(std::uint64_t& cursor, std::uint32_t count, std::uint32_t class_idx) {
        std::uint32_t current = 0;
        for (std::uint32_t i = 0; i < count; ++i) {
            const auto idx_at = cursor;
            const auto diff = read_uleb(cursor, "encoded_method method_idx_diff");
            if (i != 0 && diff == 0) bad(idx_at, "duplicate/unsorted DEX encoded_method index");
            if (diff > std::numeric_limits<std::uint32_t>::max() - current) bad(idx_at, "DEX encoded_method index overflow");
            current += diff;
            if (current >= out_->methods.size()) bad(idx_at, "DEX encoded_method index out of range");
            const auto access_flags = read_uleb(cursor, "encoded_method access_flags");
            const auto code_at = cursor;
            const auto code_off = read_uleb(cursor, "encoded_method code_off");
            auto& method = out_->methods[current];
            if (method.class_idx != class_idx) bad(idx_at, "DEX encoded_method definer does not match class_data_item");
            if (method.defined) bad(idx_at, "DEX method defined more than once");
            method.defined = true;
            method.access_flags = access_flags;
            method.code_off = code_off;
            ++out_->defined_method_count;

            const bool no_code_expected = (access_flags & (kAccNative | kAccAbstract)) != 0;
            if (code_off == 0 && !no_code_expected) bad(code_at, "concrete DEX method has zero code_off");
            if (code_off != 0 && no_code_expected) bad(code_at, "native/abstract DEX method unexpectedly has code_off");
            if (code_off != 0) {
                if (!in_data(code_off) || code_off % 4 != 0) bad(code_at, "DEX encoded_method code_off is invalid");
                out_->code_items.push_back(parse_code_item(current, access_flags, code_off));
            }
        }
    }

    void parse_class_data(DexClassInfo& cls) {
        if (cls.class_data_off == 0) return;
        require_data_offset(cls.class_data_off, "class_data_off");
        if (!class_data_offsets_.insert(cls.class_data_off).second) bad(cls.class_data_off, "multiple DEX classes reference one class_data_item");
        std::uint64_t cursor = cls.class_data_off;
        cls.static_field_count = read_uleb(cursor, "class_data static_fields_size");
        cls.instance_field_count = read_uleb(cursor, "class_data instance_fields_size");
        cls.direct_method_count = read_uleb(cursor, "class_data direct_methods_size");
        cls.virtual_method_count = read_uleb(cursor, "class_data virtual_methods_size");
        const auto field_total = std::uint64_t(cls.static_field_count) + cls.instance_field_count;
        const auto method_total = std::uint64_t(cls.direct_method_count) + cls.virtual_method_count;
        if (field_total > out_->fields.size()) bad(cls.class_data_off, "DEX class_data field count exceeds field_ids");
        if (method_total > out_->methods.size()) bad(cls.class_data_off, "DEX class_data method count exceeds method_ids");
        parse_field_list(cursor, cls.static_field_count, cls.class_idx);
        parse_field_list(cursor, cls.instance_field_count, cls.class_idx);
        parse_method_list(cursor, cls.direct_method_count, cls.class_idx);
        parse_method_list(cursor, cls.virtual_method_count, cls.class_idx);
    }

    void parse_classes() {
        out_->classes.reserve(out_->class_defs_size);
        std::unordered_map<std::uint32_t, std::uint32_t> definition_position;
        std::vector<std::uint32_t> annotation_offsets;
        annotation_offsets.reserve(out_->class_defs_size);
        for (std::uint32_t i = 0; i < out_->class_defs_size; ++i) {
            const auto off = out_->class_defs_off + std::uint64_t(i) * 32;
            DexClassInfo cls;
            cls.class_idx = u32(off);
            cls.access_flags = u32(off + 4);
            cls.superclass_idx = u32(off + 8);
            cls.interfaces_off = u32(off + 12);
            cls.source_file_idx = u32(off + 16);
            const auto annotations_off = u32(off + 20);
            cls.class_data_off = u32(off + 24);
            cls.static_values_off = u32(off + 28);
            if (cls.class_idx >= out_->types.size()) bad(off, "DEX class_def class_idx out of range");
            if (!is_class_descriptor(type_descriptors_[cls.class_idx])) bad(off, "DEX class_def class_idx is not a class type");
            if (!definition_position.emplace(cls.class_idx, i).second) bad(off, "duplicate DEX class definition");
            cls.name = out_->types[cls.class_idx];
            if (cls.superclass_idx != kNoIndex) {
                if (cls.superclass_idx >= out_->types.size()) bad(off + 8, "DEX class_def superclass_idx out of range");
                if (!is_class_descriptor(type_descriptors_[cls.superclass_idx])) bad(off + 8, "DEX superclass is not a class type");
                if (cls.superclass_idx == cls.class_idx) bad(off + 8, "DEX class cannot extend itself");
                cls.superclass = out_->types[cls.superclass_idx];
            }
            if (cls.interfaces_off != 0 && (!in_data(cls.interfaces_off) || cls.interfaces_off % 4 != 0)) bad(off + 12, "DEX class_def interfaces_off is invalid");
            const auto& interfaces = parse_type_list(cls.interfaces_off);
            for (const auto idx : interfaces) {
                if (!is_class_descriptor(type_descriptors_[idx])) bad(cls.interfaces_off, "DEX interface type is not a class type");
                cls.interfaces.push_back(out_->types[idx]);
            }
            if (cls.source_file_idx != kNoIndex) {
                if (cls.source_file_idx >= out_->strings.size()) bad(off + 16, "DEX class_def source_file_idx out of range");
                cls.source_file = out_->strings[cls.source_file_idx];
            }
            if (annotations_off != 0 && !in_data(annotations_off)) bad(off + 20, "DEX class_def annotations_off is invalid");
            if (cls.class_data_off != 0 && !in_data(cls.class_data_off)) bad(off + 24, "DEX class_def class_data_off is invalid");
            if (cls.static_values_off != 0 && !in_data(cls.static_values_off)) bad(off + 28, "DEX class_def static_values_off is invalid");
            annotation_offsets.push_back(annotations_off);
            out_->classes.push_back(std::move(cls));
        }

        // Definitions are topologically ordered: any locally defined superclass/interface must precede its user.
        for (std::uint32_t i = 0; i < out_->classes.size(); ++i) {
            const auto& cls = out_->classes[i];
            if (cls.superclass_idx != kNoIndex) {
                if (const auto it = definition_position.find(cls.superclass_idx);
                    it != definition_position.end() && it->second >= i) {
                    bad(out_->class_defs_off + std::uint64_t(i) * 32 + 8,
                        "DEX class definitions violate superclass dependency order");
                }
            }
            const auto& interfaces = parse_type_list(cls.interfaces_off);
            for (const auto idx : interfaces) {
                if (const auto it = definition_position.find(idx); it != definition_position.end() && it->second >= i) {
                    bad(cls.interfaces_off, "DEX class definitions violate interface dependency order");
                }
            }
        }
        for (auto& cls : out_->classes) {
            parse_class_data(cls);
            if (cls.static_values_off != 0) {
                const auto values = parse_encoded_array_item(cls.static_values_off, cls.static_values_off,
                                                             "static_values_off");
                if (values.size() > cls.static_field_count) {
                    bad(cls.static_values_off, "DEX static_values array is larger than static field list");
                }
            }
        }
    }

    void build_jni_surfaces() {
        struct Instruction {
            std::uint32_t pc = 0;
            std::uint32_t width = 0;
            std::uint16_t first = 0;
            std::uint8_t op = 0;
            bool payload = false;
        };
        auto limit = [&](std::string message) {
            out_->jni_surface_scan_complete = false;
            if (out_->jni_surface_scan_error.empty()) out_->jni_surface_scan_error = std::move(message);
        };
        constexpr std::uint64_t kMaxMethodCodeUnits = 262144;
        constexpr std::uint64_t kMaxAggregateCodeUnits = 1048576;
        constexpr std::size_t kMaxLibraryLoads = 4096;
        std::uint64_t aggregate_code_units = 0;
        for (const auto& code : out_->code_items) {
            if (code.insns_size > kMaxMethodCodeUnits || aggregate_code_units > kMaxAggregateCodeUnits - code.insns_size) {
                limit("bounded DEX JNI surface code-unit budget exhausted");
                continue;
            }
            aggregate_code_units += code.insns_size;
            const auto base = std::uint64_t(code.code_off) + 16;
            std::vector<Instruction> ins;
            std::unordered_map<std::uint32_t, std::size_t> by_pc;
            std::uint64_t pc = 0;
            bool supported = true;
            while (pc < code.insns_size) {
                const auto first = u16(base + pc * 2);
                const auto op = static_cast<std::uint8_t>(first & 0xffu);
                std::uint64_t width = 0;
                bool payload = false;
                if (op == 0) {
                    payload = first != 0;
                    if (first == 0) width = 1;
                    else if (first == 0x0100) {
                        if (pc + 2 > code.insns_size) { supported = false; break; }
                        width = 4 + std::uint64_t(u16(base + (pc + 1) * 2)) * 2;
                    } else if (first == 0x0200) {
                        if (pc + 2 > code.insns_size) { supported = false; break; }
                        width = 2 + std::uint64_t(u16(base + (pc + 1) * 2)) * 4;
                    } else if (first == 0x0300) {
                        if (pc + 4 > code.insns_size) { supported = false; break; }
                        const auto element_width = u16(base + (pc + 1) * 2);
                        const auto count = u32(base + (pc + 2) * 2);
                        if (!element_width || count > address_limit_) { supported = false; break; }
                        width = 4 + (std::uint64_t(element_width) * count + 1) / 2;
                    } else { supported = false; break; }
                } else {
                    width = dex_opcode_width(op);
                }
                if (!width || width > code.insns_size - pc || pc > std::numeric_limits<std::uint32_t>::max()) {
                    supported = false;
                    break;
                }
                by_pc.emplace(static_cast<std::uint32_t>(pc), ins.size());
                ins.push_back({static_cast<std::uint32_t>(pc), static_cast<std::uint32_t>(width), first, op, payload});
                pc += width;
            }
            if (!supported || pc != code.insns_size) {
                limit("bounded DEX JNI surface decoder refused an unsupported or truncated instruction stream");
                continue;
            }
            std::vector<std::vector<std::size_t>> edges(ins.size()), predecessors(ins.size());
            auto add_target = [&](std::size_t from, std::int64_t target) -> bool {
                if (target < 0 || target > std::numeric_limits<std::uint32_t>::max()) return false;
                const auto it = by_pc.find(static_cast<std::uint32_t>(target));
                if (it == by_pc.end() || ins[it->second].payload) return false;
                edges[from].push_back(it->second);
                return true;
            };
            for (std::size_t i = 0; i < ins.size() && supported; ++i) {
                const auto& x = ins[i];
                if (x.payload) continue;
                const auto next = std::uint64_t(x.pc) + x.width;
                if ((x.op >= 0x0e && x.op <= 0x11) || x.op == 0x27) continue;
                if (x.op == 0x2b || x.op == 0x2c) {
                    supported = false;
                    break;
                }
                if (x.op == 0x28) {
                    const auto delta = static_cast<std::int8_t>(x.first >> 8);
                    supported = delta != 0 && add_target(i, std::int64_t(x.pc) + delta);
                    continue;
                }
                if (x.op == 0x29) {
                    const auto delta = static_cast<std::int16_t>(u16(base + (x.pc + 1) * 2));
                    supported = delta != 0 && add_target(i, std::int64_t(x.pc) + delta);
                    continue;
                }
                if (x.op == 0x2a) {
                    const auto delta = static_cast<std::int32_t>(u32(base + (x.pc + 1) * 2));
                    supported = delta != 0 && add_target(i, std::int64_t(x.pc) + delta);
                    continue;
                }
                if (next < code.insns_size && !add_target(i, static_cast<std::int64_t>(next))) {
                    supported = false;
                    break;
                }
                if (x.op >= 0x32 && x.op <= 0x3d) {
                    const auto delta = static_cast<std::int16_t>(u16(base + (x.pc + 1) * 2));
                    if (delta == 0 || !add_target(i, std::int64_t(x.pc) + delta)) supported = false;
                }
            }
            if (!supported) {
                limit("bounded DEX JNI surface decoder refused unsupported control flow");
                continue;
            }
            for (std::size_t i = 0; i < edges.size(); ++i) {
                std::sort(edges[i].begin(), edges[i].end());
                edges[i].erase(std::unique(edges[i].begin(), edges[i].end()), edges[i].end());
                for (const auto to : edges[i]) predecessors[to].push_back(i);
            }
            std::vector<bool> reachable(ins.size(), false);
            std::deque<std::size_t> pending;
            if (const auto it = by_pc.find(0); it != by_pc.end()) {
                reachable[it->second] = true;
                pending.push_back(it->second);
            }
            while (!pending.empty()) {
                const auto at = pending.front();
                pending.pop_front();
                for (const auto to : edges[at]) if (!reachable[to]) {
                    reachable[to] = true;
                    pending.push_back(to);
                }
            }
            for (std::size_t i = 0; i < ins.size(); ++i) {
                const auto& call = ins[i];
                if (!reachable[i] || (call.op != 0x71 && call.op != 0x77)) continue;
                const auto target_idx = u16(base + (call.pc + 1) * 2);
                if (target_idx >= out_->methods.size()) continue;
                const auto& target = out_->methods[target_idx];
                if (target.owner_descriptor != "Ljava/lang/System;" || target.name != "loadLibrary" ||
                    target.descriptor != "(Ljava/lang/String;)V") continue;
                std::uint32_t argument = 0;
                if (call.op == 0x71) {
                    const auto count = static_cast<std::uint8_t>(call.first >> 12);
                    if (count != 1) continue;
                    argument = u16(base + (call.pc + 2) * 2) & 0x0fu;
                } else {
                    const auto count = static_cast<std::uint8_t>(call.first >> 8);
                    if (count != 1) continue;
                    argument = u16(base + (call.pc + 2) * 2);
                }
                if (predecessors[i].size() != 1) continue;
                const auto previous_idx = predecessors[i][0];
                const auto& previous = ins[previous_idx];
                if (!reachable[previous_idx] || previous.pc + previous.width != call.pc ||
                    (previous.op != 0x1a && previous.op != 0x1b) ||
                    static_cast<std::uint8_t>(previous.first >> 8) != argument) continue;
                const auto string_idx = previous.op == 0x1a ? u16(base + (previous.pc + 1) * 2)
                                                            : u32(base + (previous.pc + 1) * 2);
                if (string_idx >= out_->strings.size()) continue;
                DexLibraryLoadInfo load;
                load.caller_method_idx = code.method_idx;
                load.target_method_idx = target_idx;
                load.string_idx = string_idx;
                load.pc_code_units = call.pc;
                load.instruction_file_offset = base + std::uint64_t(call.pc) * 2;
                load.library_name = out_->strings[string_idx];
                if (out_->library_loads.size() >= kMaxLibraryLoads) {
                    limit("bounded DEX JNI loadLibrary evidence budget exhausted");
                    continue;
                }
                out_->library_loads.push_back(std::move(load));
            }
        }
    }


    void build_implicit() {
        auto& im = out_->implicit_exec;
        constexpr std::size_t max_facts = 65536;
        bool partial = false;
        std::string partial_error;
        auto add = [&](ImplicitExecutionFact f) -> std::int64_t {
            if (im.facts.size() >= max_facts) {
                im.analysis_limited = true; partial = true;
                if (partial_error.empty()) partial_error = "DEX implicit execution fact budget exceeded";
                return -1;
            }
            f.index = static_cast<std::uint32_t>(im.facts.size());
            if (f.priority == "HIGH") ++im.high_priority_count;
            else if (f.priority == "REVIEW") ++im.review_count;
            else ++im.informational_count;
            if (!f.anomaly_class.empty() && f.anomaly_class != "NONE") ++im.anomaly_count;
            if (f.evidence_state == "UNRESOLVED_RUNTIME_SEMANTICS") ++im.unresolved_runtime_semantics;
            const auto idx = static_cast<std::int64_t>(f.index); im.facts.push_back(std::move(f)); return idx;
        };
        auto code_for = [&](std::uint32_t method_idx) -> const DexCodeInfo* {
            for (const auto& c : out_->code_items) if (c.method_idx == method_idx) return &c;
            return nullptr;
        };
        for (const auto& m : out_->methods) {
            if (!m.defined || m.name != "<clinit>" || !(m.access_flags & kAccStatic) || m.code_off == 0) continue;
            const auto* c = code_for(m.index); if (!c) continue;
            ImplicitExecutionFact f; f.format="DEX"; f.ecosystem="Android/DEX"; f.phase="runtime_initialization";
            f.trigger="DEX_CLASS_INITIALIZATION"; f.relation="implicit_callback"; f.source_kind="code_item";
            f.source_index=m.index; f.source_file_backed=true; f.source_file_offset=std::uint64_t(c->code_off)+16;
            f.source_size=std::uint64_t(c->insns_size)*2; f.target_kind="dex_method"; f.target_function_index=m.index;
            f.target_name=m.signature; f.evidence_state="EXACT"; f.mutability="IMMUTABLE_DEX";
            f.execution_condition="ART/Dalvik invokes <clinit> when this class is initialized before first active use; application startup reachability is not inferred";
            f.priority="INFORMATIONAL"; f.priority_reason="ordinary DEX class initialization surface; not every type initializer runs before application entry";
            add(std::move(f));
        }
        struct Use {std::uint32_t method_idx=0,call_site_idx=0;std::uint64_t file=0,pc=0;};
        std::vector<Use> uses;
        for (const auto& c : out_->code_items) {
            const auto base=std::uint64_t(c.code_off)+16; std::uint64_t pc=0;
            while (pc < c.insns_size) {
                const auto unit=u16(base+pc*2); const auto op=static_cast<std::uint8_t>(unit&0xffu); std::uint64_t w=0;
                if(op==0){const auto ident=unit;if(ident==0)w=1;else if(ident==0x0100){if(pc+2>c.insns_size){partial=true;partial_error="truncated DEX packed-switch payload";break;}const auto n=u16(base+(pc+1)*2);w=4+std::uint64_t(n)*2;}else if(ident==0x0200){if(pc+2>c.insns_size){partial=true;partial_error="truncated DEX sparse-switch payload";break;}const auto n=u16(base+(pc+1)*2);w=2+std::uint64_t(n)*4;}else if(ident==0x0300){if(pc+4>c.insns_size){partial=true;partial_error="truncated DEX fill-array-data payload";break;}const auto ew=u16(base+(pc+1)*2);const auto n=u32(base+(pc+2)*2);if(ew==0||n>address_limit_){partial=true;partial_error="invalid DEX fill-array-data payload";break;}w=4+(std::uint64_t(ew)*n+1)/2;}else{partial=true;if(partial_error.empty())partial_error="unknown DEX payload pseudo-opcode in implicit decoder";break;}}
                else w=dex_opcode_width(op);
                if(w==0){partial=true;if(partial_error.empty())partial_error="unsupported/unused DEX opcode in implicit decoder";break;}
                if(w>c.insns_size-pc){partial=true;if(partial_error.empty())partial_error="truncated DEX instruction in implicit decoder";break;}
                if(op==0xfc||op==0xfd){const auto ci=u16(base+(pc+1)*2);if(ci>=out_->call_sites.size()){partial=true;if(partial_error.empty())partial_error="DEX invoke-custom call_site index out of range";}else uses.push_back({c.method_idx,ci,base+pc*2,pc});}
                pc+=w;
            }
        }
        std::map<std::string,std::uint64_t> target_uses;for(const auto&u:uses)++target_uses[out_->call_sites[u.call_site_idx].bootstrap_target];
        auto standard=[](std::string_view t){
            return t.rfind("java.lang.invoke.LambdaMetafactory::",0)==0 ||
                   t.rfind("java.lang.invoke.StringConcatFactory::",0)==0 ||
                   t.rfind("java.lang.invoke.ConstantBootstraps::",0)==0 ||
                   t.rfind("java.lang.runtime.ObjectMethods::",0)==0 ||
                   t.rfind("java.lang.runtime.SwitchBootstraps::",0)==0;
        };
        std::vector<std::int64_t> callsite_fact(out_->call_sites.size(),-1);
        for(const auto&u:uses){if(callsite_fact[u.call_site_idx]>=0)continue;const auto&cs=out_->call_sites[u.call_site_idx];const auto n=target_uses[cs.bootstrap_target];const bool elevated=!standard(cs.bootstrap_target)&&n>=2&&((n>=4)||(uses.size()>=2&&n*100>=uses.size()*75));ImplicitExecutionFact f;f.format="DEX";f.ecosystem="Android/DEX";f.phase="first_resolution";f.trigger="DEX_CALL_SITE";f.relation="bootstrap_definition";f.source_kind="call_site_item";f.source_index=cs.index;f.source_file_backed=true;f.source_file_offset=cs.call_site_off;f.source_size=cs.call_site_size;f.target_kind="method_handle_target";f.target_token=cs.bootstrap_method_handle_idx;f.target_name=cs.bootstrap_target;f.evidence_state="EXACT";f.mutability="IMMUTABLE_DEX";f.execution_condition="ART/Dalvik may invoke this bootstrap when an invoke-custom instruction referencing the call_site is first linked; linker/bootstrap execution is not simulated";f.priority=elevated?"REVIEW":"INFORMATIONAL";f.anomaly_class=elevated?"NONSTANDARD_DEX_BOOTSTRAP_DOMINATES_INVOKE_CUSTOM":"NONE";f.priority_reason=elevated?"non-JDK bootstrap target governs most/all actual invoke-custom sites":"ordinary DEX call-site linkage; standard JDK bootstrap or low-coverage custom target";f.detail="method_name="+cs.method_name+";method_type="+cs.method_type+";extra_arguments="+std::to_string(cs.extra_argument_count)+";actual_target_uses="+std::to_string(n);callsite_fact[u.call_site_idx]=add(std::move(f));}
        for(const auto&u:uses){const auto&cs=out_->call_sites[u.call_site_idx];const auto n=target_uses[cs.bootstrap_target];const bool elevated=!standard(cs.bootstrap_target)&&n>=2&&((n>=4)||(uses.size()>=2&&n*100>=uses.size()*75));ImplicitExecutionFact f;f.depends_on_fact_index=callsite_fact[u.call_site_idx];f.format="DEX";f.ecosystem="Android/DEX";f.phase="first_resolution";f.trigger="DEX_INVOKE_CUSTOM";f.relation="dynamic_bootstrap_use";f.source_kind="invoke-custom";f.source_index=u.method_idx;f.source_file_backed=true;f.source_file_offset=u.file;f.source_size=6;f.target_kind="call_site";f.target_token=u.call_site_idx;f.target_name=cs.bootstrap_target;f.evidence_state="EXACT";f.mutability="IMMUTABLE_DEX";f.execution_condition="ART/Dalvik links this invoke-custom site on first resolution; bootstrap/linker code is not executed by analysis";f.priority=elevated?"REVIEW":"INFORMATIONAL";f.anomaly_class=elevated?"NONSTANDARD_DEX_BOOTSTRAP_DOMINATES_INVOKE_CUSTOM":"NONE";f.priority_reason=elevated?"actual invoke-custom instruction is governed by a dominant non-JDK bootstrap":"ordinary invoke-custom surface; standard JDK bootstrap or low-coverage custom target";const auto&method=out_->methods[u.method_idx];f.detail="method="+method.signature+";pc_code_units="+std::to_string(u.pc)+";call_site="+std::to_string(u.call_site_idx)+";dynamic_name="+cs.method_name+";dynamic_type="+cs.method_type;add(std::move(f));}
        if(im.facts.empty())im.state=partial?"PARTIAL":"NOT_PRESENT";else im.state=partial?"PARTIAL":"RESOLVED";if(partial)im.error=partial_error;
    }

    void require_dynamic_map_count(std::uint16_t type, std::size_t actual, std::string_view what) const {
        const auto* m = map_item(type);
        if (actual == 0) {
            if (m != nullptr) bad(m->offset, std::string("DEX map contains unused ") + std::string(what));
            return;
        }
        if (m == nullptr) bad(out_->map_off, std::string("DEX map missing ") + std::string(what));
        if (m->size != actual) bad(m->offset, std::string("DEX map count mismatch for ") + std::string(what));
    }

    void validate_map_dynamic_counts() const {
        require_dynamic_map_count(kTypeStringDataItem, out_->strings.size(), "string_data_item");
        require_dynamic_map_count(kTypeTypeList, type_list_offsets_.size(), "type_list");
        require_dynamic_map_count(kTypeClassDataItem, class_data_offsets_.size(), "class_data_item");
        require_dynamic_map_count(kTypeCodeItem, code_offsets_.size(), "code_item");
        require_dynamic_map_count(kTypeDebugInfoItem, debug_offsets_.size(), "debug_info_item");
        require_dynamic_map_count(kTypeEncodedArrayItem, encoded_array_offsets_.size(), "encoded_array_item");
    }

    void validate_integrity() {
        // v041 logical DEX files may share later physical-container data. The AOSP header
        // wording is clear about offsets/container bounds, but treating a single logical
        // file_size as the hash extent would be misleading. Keep integrity explicitly
        // unchecked for v041 until the whole container signature semantics are handled.
        if (out_->container_v41) {
            out_->anomalies.push_back("DEX v041 container parsed structurally; integrity hash not independently checked");
            return;
        }
        out_->checksum_checked = true;
        out_->computed_checksum = adler32(data_.subspan(12, out_->file_size - 12));
        out_->checksum_matches = out_->checksum == out_->computed_checksum;
        if (!out_->checksum_matches) out_->anomalies.push_back("DEX Adler-32 checksum mismatch (modified or corrupted file)");

        out_->signature_checked = true;
        const auto digest = sha1_bytes(data_.subspan(32, out_->file_size - 32));
        out_->signature_matches = std::equal(digest.begin(), digest.end(), data_.begin() + 12);
        if (!out_->signature_matches) out_->anomalies.push_back("DEX SHA-1 signature mismatch (modified or corrupted file)");
    }
};

}  // namespace

DexInfo parse_dex(std::span<const std::uint8_t> data) {
    DexParser parser(data);
    auto info = parser.run();
    // A non-DEX input is not a failed DEX parse. Strong filename routing is handled by
    // the caller when this parser is wired into the top-level report path.
    if (!info.candidate) {
        info.error.clear();
        info.error_offset = 0;
    }
    return info;
}

Finding dex_finding(const DexInfo& info) {
    Finding f;
    f.kind = "bytecode";
    f.family = "Android DEX";
    f.variant = info.version.empty() ? "DEX" : "DEX v" + info.version;
    if (!info.valid) {
        f.state = "FAILED";
        if (!info.error.empty()) {
            std::ostringstream x;
            x << info.error << " at current-file+0x" << std::hex << info.error_offset;
            f.negative_evidence.push_back(x.str());
        }
        return f;
    }
    f.state = "CONFIRMED";
    f.evidence.push_back("DEX magic/version, header tables and map_list geometry validated");
    f.evidence.push_back("string/type/proto/member/class indexes and ordering validated");
    f.evidence.push_back("class_data/code/debug references and bounds validated");
    if (!info.call_sites.empty()) f.evidence.push_back("invoke-custom call sites and bootstrap method handles structurally resolved");
    if (!info.library_loads.empty()) f.evidence.push_back("reachable exact-constant java.lang.System.loadLibrary call sites recovered as static references; loading was not observed");
    f.fields["version"] = info.version;
    f.fields["strings"] = std::to_string(info.strings.size());
    f.fields["types"] = std::to_string(info.types.size());
    f.fields["protos"] = std::to_string(info.protos.size());
    f.fields["fields"] = std::to_string(info.fields.size());
    f.fields["methods"] = std::to_string(info.methods.size());
    f.fields["classes"] = std::to_string(info.classes.size());
    f.fields["defined_methods"] = std::to_string(info.defined_method_count);
    f.fields["code_items"] = std::to_string(info.code_item_count);
    f.fields["method_handles"] = std::to_string(info.method_handles.size());
    f.fields["call_sites"] = std::to_string(info.call_sites.size());
    f.fields["jni_surface_scan_complete"] = info.jni_surface_scan_complete ? "true" : "false";
    f.fields["load_library_references"] = std::to_string(info.library_loads.size());
    if (!info.jni_surface_scan_error.empty()) f.negative_evidence.push_back(info.jni_surface_scan_error);
    f.fields["offset_space"] = "current_input_file";
    if (info.checksum_checked) f.fields["adler32_match"] = info.checksum_matches ? "true" : "false";
    if (info.signature_checked) f.fields["sha1_signature_match"] = info.signature_matches ? "true" : "false";
    for (const auto& a : info.anomalies) f.negative_evidence.push_back(a);
    f.suggested_actions = {"extract:dex-symbol-maps", "inspect defined methods and invoke-custom call sites first", "open current-input DEX in JADX/Ghidra/IDA using reported current-file offsets"};
    return f;
}

DexExtractResult extract_dex_maps(const DexInfo& info, const std::filesystem::path& methods_csv) {
    DexExtractResult r;
    if (!info.valid) {
        r.error = "DEX structure is not valid";
        return r;
    }
    r.methods_csv = methods_csv;
    const auto stem = methods_csv.string().ends_with(".methods.csv")
        ? methods_csv.string().substr(0, methods_csv.string().size() - std::string(".methods.csv").size())
        : methods_csv.string();
    r.classes_csv = stem + ".classes.csv";
    r.fields_csv = stem + ".fields.csv";
    r.callsites_csv = stem + ".callsites.csv";

    std::unordered_map<std::uint32_t, const DexCodeInfo*> code_by_method;
    for (const auto& c : info.code_items) code_by_method.emplace(c.method_idx, &c);

    {
        std::ofstream o(r.methods_csv, std::ios::binary);
        if (!o) { r.error = "cannot create DEX methods CSV"; return r; }
        o << "method_idx,defined,owner,name,signature,access_flags,code_off,code_size_bytes,debug_info_off,registers_size,ins_size,outs_size,tries_size,insns_size,debug_line_start,debug_position_count,parameter_names,offset_space\n";
        for (const auto& m : info.methods) {
            const auto it = code_by_method.find(m.index);
            const DexCodeInfo* c = it == code_by_method.end() ? nullptr : it->second;
            o << m.index << ',' << (m.defined ? 1 : 0) << ',' << csv_cell(m.owner) << ',' << csv_cell(m.name) << ','
              << csv_cell(m.signature) << ",0x" << std::hex << m.access_flags << std::dec << ",0x" << std::hex << m.code_off << std::dec << ',';
            if (c) {
                o << c->code_size_bytes << ",0x" << std::hex << c->debug_info_off << std::dec << ','
                  << c->registers_size << ',' << c->ins_size << ',' << c->outs_size << ',' << c->tries_size << ','
                  << c->insns_size << ',' << c->debug_line_start << ',' << c->debug_position_count << ','
                  << csv_cell(join_pipe(c->parameter_names));
            } else {
                o << "0,0x0,0,0,0,0,0,0,0,";
            }
            o << ",current_input_file\n";
        }
        if (!o) { r.error = "failed writing DEX methods CSV"; return r; }
    }
    {
        std::ofstream o(r.classes_csv, std::ios::binary);
        if (!o) { r.error = "cannot create DEX classes CSV"; return r; }
        o << "class_idx,name,superclass,source_file,access_flags,interfaces_off,class_data_off,static_values_off,static_fields,instance_fields,direct_methods,virtual_methods,interfaces,offset_space\n";
        for (const auto& c : info.classes) {
            o << c.class_idx << ',' << csv_cell(c.name) << ',' << csv_cell(c.superclass) << ',' << csv_cell(c.source_file)
              << ",0x" << std::hex << c.access_flags << ",0x" << c.interfaces_off << ",0x" << c.class_data_off
              << ",0x" << c.static_values_off << std::dec << ',' << c.static_field_count << ',' << c.instance_field_count
              << ',' << c.direct_method_count << ',' << c.virtual_method_count << ',' << csv_cell(join_pipe(c.interfaces))
              << ",current_input_file\n";
        }
        if (!o) { r.error = "failed writing DEX classes CSV"; return r; }
    }
    {
        std::ofstream o(r.fields_csv, std::ios::binary);
        if (!o) { r.error = "cannot create DEX fields CSV"; return r; }
        o << "field_idx,defined,owner,name,type,signature,access_flags\n";
        for (const auto& f : info.fields) {
            o << f.index << ',' << (f.defined ? 1 : 0) << ',' << csv_cell(f.owner) << ',' << csv_cell(f.name) << ','
              << csv_cell(f.type) << ',' << csv_cell(f.signature) << ",0x" << std::hex << f.access_flags << std::dec << "\n";
        }
        if (!o) { r.error = "failed writing DEX fields CSV"; return r; }
    }
    {
        std::ofstream o(r.callsites_csv, std::ios::binary);
        if (!o) { r.error = "cannot create DEX callsites CSV"; return r; }
        o << "callsite_idx,call_site_off,method_name,method_type,bootstrap_handle_idx,bootstrap_target,extra_argument_count,offset_space\n";
        for (const auto& c : info.call_sites) {
            o << c.index << ",0x" << std::hex << c.call_site_off << std::dec << ',' << csv_cell(c.method_name) << ','
              << csv_cell(c.method_type) << ',' << c.bootstrap_method_handle_idx << ',' << csv_cell(c.bootstrap_target) << ','
              << c.extra_argument_count << ",current_input_file\n";
        }
        if (!o) { r.error = "failed writing DEX callsites CSV"; return r; }
    }
    r.method_count = info.methods.size();
    r.class_count = info.classes.size();
    r.field_count = info.fields.size();
    r.callsite_count = info.call_sites.size();
    r.success = true;
    return r;
}

}  // namespace prts
