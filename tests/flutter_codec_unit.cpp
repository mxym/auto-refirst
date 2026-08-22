#include "prts/flutter.hpp"

#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

class Writer {
public:
    void map(std::uint8_t count) { bytes_.push_back(13); bytes_.push_back(count); }
    void list(std::uint8_t count) { bytes_.push_back(12); bytes_.push_back(count); }
    void null_value() { bytes_.push_back(0); }
    void string(std::string_view value) {
        bytes_.push_back(7);
        bytes_.push_back(static_cast<std::uint8_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }
    const std::vector<std::uint8_t>& bytes() const { return bytes_; }

private:
    std::vector<std::uint8_t> bytes_;
};

bool valid_nested_map_roundtrip() {
    Writer writer;
    writer.map(1);
    writer.string("assets/logo.png");
    writer.list(1);
    writer.map(2);
    writer.string("asset");
    writer.string("assets/logo.png");
    writer.string("dpr");
    writer.null_value();

    const auto parsed = prts::parse_flutter_asset_manifest(writer.bytes());
    return parsed.valid && parsed.nonempty && parsed.modern_metadata_variants &&
           parsed.entry_count == 1 && parsed.variant_count == 1 &&
           parsed.entries.size() == 1 &&
           parsed.entries[0].key == "assets/logo.png" &&
           parsed.entries[0].variants.size() == 1 &&
           parsed.entries[0].variants[0].asset == "assets/logo.png" &&
           !parsed.entries[0].variants[0].device_pixel_ratio.has_value();
}

bool malformed_map_is_rejected() {
    Writer writer;
    writer.map(1);
    writer.string("asset");
    writer.list(1);
    writer.map(1);
    writer.string("asset");
    // The map value is deliberately absent.

    const auto parsed = prts::parse_flutter_asset_manifest(writer.bytes());
    return parsed.candidate && !parsed.valid &&
           parsed.error.find("truncated StandardMessageCodec byte") != std::string::npos;
}

}  // namespace

int main() {
    if (!valid_nested_map_roundtrip() || !malformed_map_is_rejected()) return 1;
    std::cout << "PASS\n";
    return 0;
}
