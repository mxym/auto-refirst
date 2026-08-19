#include "prts/flutter.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <string_view>
#include <utility>
#include <vector>

namespace prts {
namespace {

enum class Kind {
    Null, Boolean, Integer, Double, String, Bytes, Int32List, Int64List,
    Float64List, Float32List, List, Map, LargeInteger
};

struct Value {
    Kind kind = Kind::Null;
    bool boolean = false;
    std::int64_t integer = 0;
    double floating = 0;
    std::string string;
    std::vector<std::uint8_t> bytes;
    std::vector<Value> list;
    std::vector<std::pair<Value, Value>> map;
};

struct DecodeError {
    std::string message;
    std::uint64_t offset = 0;
};

bool valid_utf8(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { ++i; continue; }
        std::uint32_t cp = 0;
        std::size_t need = 0;
        if ((c & 0xe0) == 0xc0) { cp = c & 0x1f; need = 1; if (cp < 2) return false; }
        else if ((c & 0xf0) == 0xe0) { cp = c & 0x0f; need = 2; }
        else if ((c & 0xf8) == 0xf0) { cp = c & 0x07; need = 3; if (cp > 4) return false; }
        else return false;
        if (i + need >= s.size()) return false;
        for (std::size_t z = 1; z <= need; ++z) {
            const auto d = static_cast<unsigned char>(s[i + z]);
            if ((d & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (d & 0x3f);
        }
        if ((need == 2 && cp < 0x800) || (need == 3 && cp < 0x10000)) return false;
        if (cp >= 0xd800 && cp <= 0xdfff) return false;
        if (cp > 0x10ffff) return false;
        i += need + 1;
    }
    return true;
}

class Decoder {
public:
    explicit Decoder(std::span<const std::uint8_t> data) : data_(data) {}

    bool decode(Value& out, DecodeError& error) {
        if (!read_value(out, 0, error)) return false;
        if (pos_ != data_.size()) {
            error = {"trailing bytes after StandardMessageCodec value", pos_};
            return false;
        }
        return true;
    }

    std::uint64_t nodes() const { return nodes_; }
    std::uint64_t string_bytes() const { return string_bytes_; }

private:
    static constexpr std::uint64_t kMaxNodes = 1000000;
    static constexpr std::uint64_t kMaxStringBytes = 64ull * 1024 * 1024;
    static constexpr unsigned kMaxDepth = 64;
    std::span<const std::uint8_t> data_;
    std::uint64_t pos_ = 0;
    std::uint64_t nodes_ = 0;
    std::uint64_t string_bytes_ = 0;

    bool range(std::uint64_t n) const { return pos_ <= data_.size() && n <= data_.size() - pos_; }

    bool align(unsigned n, DecodeError& error) {
        const auto aligned = (pos_ + n - 1) & ~(std::uint64_t(n) - 1);
        if (aligned > data_.size()) { error = {"truncated StandardMessageCodec alignment padding", pos_}; return false; }
        for (auto p = pos_; p < aligned; ++p) {
            if (data_[p] != 0) { error = {"nonzero StandardMessageCodec alignment padding", p}; return false; }
        }
        pos_ = aligned;
        return true;
    }

    bool u8(std::uint8_t& x, DecodeError& error) {
        if (!range(1)) { error = {"truncated StandardMessageCodec byte", pos_}; return false; }
        x = data_[pos_++]; return true;
    }
    bool u16(std::uint16_t& x, DecodeError& error) {
        if (!align(2, error) || !range(2)) { if (error.message.empty()) error={"truncated StandardMessageCodec uint16",pos_}; return false; }
        x = std::uint16_t(data_[pos_]) | (std::uint16_t(data_[pos_ + 1]) << 8); pos_ += 2; return true;
    }
    bool u32(std::uint32_t& x, DecodeError& error) {
        if (!align(4, error) || !range(4)) { if (error.message.empty()) error={"truncated StandardMessageCodec uint32",pos_}; return false; }
        x = std::uint32_t(data_[pos_]) | (std::uint32_t(data_[pos_ + 1]) << 8) |
            (std::uint32_t(data_[pos_ + 2]) << 16) | (std::uint32_t(data_[pos_ + 3]) << 24); pos_ += 4; return true;
    }
    bool u64(std::uint64_t& x, DecodeError& error) {
        if (!align(8, error) || !range(8)) { if (error.message.empty()) error={"truncated StandardMessageCodec uint64",pos_}; return false; }
        x = 0; for (unsigned i=0;i<8;++i) x |= std::uint64_t(data_[pos_+i]) << (i*8); pos_ += 8; return true;
    }

    bool size(std::uint32_t& out, DecodeError& error) {
        std::uint8_t x = 0; if (!u8(x,error)) return false;
        if (x < 254) { out = x; return true; }
        if (x == 254) { std::uint16_t y=0; if(!u16(y,error))return false; out=y; return true; }
        return u32(out,error);
    }

    bool string(std::string& out, DecodeError& error) {
        std::uint32_t n=0; if(!size(n,error))return false;
        if (n > kMaxStringBytes - string_bytes_) { error={"StandardMessageCodec string budget exceeded",pos_}; return false; }
        if(!range(n)){error={"truncated StandardMessageCodec string",pos_};return false;}
        out.assign(reinterpret_cast<const char*>(data_.data()+pos_),n);
        if(!valid_utf8(out)){error={"invalid UTF-8 in StandardMessageCodec string",pos_};return false;}
        pos_+=n; string_bytes_+=n; return true;
    }

    bool read_value(Value& out, unsigned depth, DecodeError& error) {
        if (depth > kMaxDepth) { error={"StandardMessageCodec nesting depth exceeded",pos_}; return false; }
        if (++nodes_ > kMaxNodes) { error={"StandardMessageCodec node budget exceeded",pos_}; return false; }
        const auto tag_off=pos_; std::uint8_t tag=0; if(!u8(tag,error))return false;
        switch(tag){
            case 0: out.kind=Kind::Null; return true;
            case 1: out.kind=Kind::Boolean; out.boolean=true; return true;
            case 2: out.kind=Kind::Boolean; out.boolean=false; return true;
            case 3: { out.kind=Kind::Integer; std::uint32_t x=0;if(!u32(x,error))return false;out.integer=static_cast<std::int32_t>(x);return true; }
            case 4: { out.kind=Kind::Integer; std::uint64_t x=0;if(!u64(x,error))return false;out.integer=static_cast<std::int64_t>(x);return true; }
            case 5: out.kind=Kind::LargeInteger; return string(out.string,error);
            case 6: { out.kind=Kind::Double; std::uint64_t x=0;if(!u64(x,error))return false;std::memcpy(&out.floating,&x,sizeof(x));return std::isfinite(out.floating)?true:(error=DecodeError{"non-finite StandardMessageCodec double",tag_off},false); }
            case 7: out.kind=Kind::String; return string(out.string,error);
            case 8: { out.kind=Kind::Bytes;std::uint32_t n=0;if(!size(n,error))return false;if(!range(n)){error={"truncated StandardMessageCodec uint8 list",pos_};return false;}out.bytes.assign(data_.begin()+static_cast<std::ptrdiff_t>(pos_),data_.begin()+static_cast<std::ptrdiff_t>(pos_+n));pos_+=n;return true; }
            case 9: case 10: case 11: case 14: {
                std::uint32_t n = 0;
                if (!size(n, error)) return false;
                const unsigned width = (tag == 9 || tag == 14) ? 4u : 8u;
                if (!align(width, error)) return false;
                const auto bytes = std::uint64_t(n) * width;
                if (bytes > data_.size() - pos_) {
                    error = {"truncated StandardMessageCodec typed list", pos_};
                    return false;
                }
                pos_ += bytes;
                out.kind = tag == 9 ? Kind::Int32List : tag == 10 ? Kind::Int64List : tag == 11 ? Kind::Float64List : Kind::Float32List;
                return true;
            }
            case 12: {
                out.kind=Kind::List;std::uint32_t n=0;if(!size(n,error))return false;if(n>kMaxNodes-nodes_){error={"StandardMessageCodec list count exceeds node budget",pos_};return false;}out.list.resize(n);for(auto&v:out.list)if(!read_value(v,depth+1,error))return false;return true;
            }
            case 13: {
                out.kind=Kind::Map;std::uint32_t n=0;if(!size(n,error))return false;if(std::uint64_t(n)*2>kMaxNodes-nodes_){error={"StandardMessageCodec map count exceeds node budget",pos_};return false;}out.map.resize(n);for(auto&kv:out.map){if(!read_value(kv.first,depth+1,error)||!read_value(kv.second,depth+1,error))return false;}return true;
            }
            default: error={"unknown StandardMessageCodec type tag",tag_off};return false;
        }
    }
};

bool scalar_metadata(const Value& v) {
    return v.kind==Kind::Null||v.kind==Kind::Boolean||v.kind==Kind::Integer||v.kind==Kind::Double||v.kind==Kind::String;
}

}  // namespace

FlutterAssetManifestInfo parse_flutter_asset_manifest(std::span<const std::uint8_t> data) {
    FlutterAssetManifestInfo out;
    if (data.empty() || data[0] != 13) return out;
    out.candidate = true;
    Value root; DecodeError error; Decoder d(data);
    if(!d.decode(root,error)){
        out.error=error.message;out.error_offset=error.offset;out.decoded_node_count=d.nodes();out.decoded_string_bytes=d.string_bytes();return out;
    }
    out.decoded_node_count=d.nodes();out.decoded_string_bytes=d.string_bytes();
    if(root.kind!=Kind::Map){out.error="Flutter AssetManifest root is not a map";return out;}
    if(root.map.size()>1000000){out.error="Flutter AssetManifest entry count unreasonable";return out;}
    std::set<std::string> keys;
    out.entries.reserve(root.map.size());
    for(const auto&kv:root.map){
        if(kv.first.kind!=Kind::String||kv.first.string.empty()){out.error="Flutter AssetManifest key is not a nonempty string";return out;}
        if(!keys.insert(kv.first.string).second){out.error="duplicate Flutter AssetManifest asset key";return out;}
        if(kv.second.kind!=Kind::List||kv.second.list.empty()){out.error="Flutter AssetManifest value is not a nonempty variant list";return out;}
        FlutterAssetEntry entry;entry.key=kv.first.string;std::set<std::string> variants;
        for(const auto&item:kv.second.list){
            FlutterAssetVariant v;
            if(item.kind==Kind::String){
                if(item.string.empty()){out.error="empty legacy Flutter asset variant";return out;}
                v.asset=item.string;out.legacy_string_variants=true;
            }else if(item.kind==Kind::Map){
                out.modern_metadata_variants=true;bool have_asset=false;std::set<std::string> meta_keys;
                for(const auto&m:item.map){
                    if(m.first.kind!=Kind::String||m.first.string.empty()){out.error="Flutter asset metadata key is not a string";return out;}
                    if(!meta_keys.insert(m.first.string).second){out.error="duplicate Flutter asset metadata key";return out;}
                    if(m.first.string=="asset"){
                        if(m.second.kind!=Kind::String||m.second.string.empty()){out.error="Flutter asset metadata 'asset' is not a nonempty string";return out;}
                        v.asset=m.second.string;have_asset=true;
                    }else if(m.first.string=="dpr"){
                        if(m.second.kind==Kind::Null){}
                        else if(m.second.kind==Kind::Double&&std::isfinite(m.second.floating)&&m.second.floating>0)v.device_pixel_ratio=m.second.floating;
                        else {out.error="Flutter asset metadata 'dpr' is not null or positive finite double";return out;}
                    }else{
                        if(!scalar_metadata(m.second)){out.error="unsupported nested Flutter asset metadata value";return out;}
                        v.unknown_metadata_keys.push_back(m.first.string);++out.unknown_metadata_key_count;
                    }
                }
                if(!have_asset){out.error="Flutter asset metadata variant lacks required 'asset' key";return out;}
            }else{out.error="Flutter AssetManifest variant is neither legacy string nor metadata map";return out;}
            if(!variants.insert(v.asset).second){out.error="duplicate Flutter asset variant path";return out;}
            entry.variants.push_back(std::move(v));++out.variant_count;
        }
        out.entries.push_back(std::move(entry));
    }
    out.entry_count=static_cast<std::uint32_t>(out.entries.size());out.nonempty=!out.entries.empty();
    if(out.legacy_string_variants&&out.modern_metadata_variants)out.anomalies.push_back("AssetManifest mixes legacy string and modern metadata variant encodings");
    if(out.unknown_metadata_key_count)out.anomalies.push_back("AssetManifest contains forward-compatible unknown scalar metadata keys");
    out.valid=true;return out;
}

}  // namespace prts
