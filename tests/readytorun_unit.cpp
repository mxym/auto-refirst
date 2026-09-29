#include "prts/readytorun.hpp"

#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void put16(std::vector<std::uint8_t>& data, std::size_t offset, std::uint16_t value) {
    data[offset] = static_cast<std::uint8_t>(value);
    data[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void put32(std::vector<std::uint8_t>& data, std::size_t offset, std::uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) data[offset + i] = static_cast<std::uint8_t>(value >> (8 * i));
}

prts::PeInfo pe() {
    prts::PeInfo out;
    out.valid = true;
    out.pe64 = true;
    out.headers_size = 0x200;
    out.image_size = 0x4000;
    out.clr.present = true;
    out.clr.rva = 0x1100;
    out.clr.size = 0x48;
    out.sections.push_back({".text", 0x1000, 0x800, 0x200, 0x800, 0, 0x60000020u});
    out.sections.push_back({".rrdata", 0x3000, 0x400, 0xa00, 0x400, 0, 0x40000040u});
    return out;
}

std::vector<std::uint8_t> image() {
    auto data = std::vector<std::uint8_t>(0xe00, 0);
    // CLI ManagedNativeHeader data directory at the end of the COR20 header.
    put32(data, 0x300 + 64, 0x3000);
    put32(data, 0x300 + 68, 52);
    const std::size_t header = 0xa00;
    put32(data, header, 0x00525452);
    put16(data, header + 4, 29);
    put16(data, header + 6, 3);
    put32(data, header + 8, 0x00000210u);  // embedded MSIL + stripped IL bodies
    put32(data, header + 12, 3);
    for (unsigned i = 0; i < 3; ++i) {
        const auto row = header + 16 + i * 12;
        put32(data, row, 101 + i);
        put32(data, row + 4, 0x3050u + i * 0x30u);
        put32(data, row + 8, 0x20u);
    }
    return data;
}

bool managed_header() {
    const auto data = image();
    const auto info = prts::detect_ready_to_run(data, pe());
    if (!info.candidate || !info.valid || info.state != "CONFIRMED" ||
        info.source != "CLI_MANAGED_NATIVE_HEADER" || info.header_offset != 0xa00 ||
        info.header_size != 52 || info.section_count != 3 ||
        info.runtime_function_section_count != 1 || info.method_entrypoint_section_count != 1 ||
        !info.embedded_msil || !info.stripped_il_bodies)
        return false;
    const auto finding = prts::ready_to_run_finding(info);
    return finding.family == ".NET ReadyToRun" && finding.state == "CONFIRMED" &&
           finding.ranges.size() == 4 && finding.ranges.front().offset == 0xa00;
}

bool export_header() {
    auto p = pe();
    p.clr.present = false;
    p.exports.push_back({"RTR_HEADER", {}, 0x3000, 1});
    const auto info = prts::detect_ready_to_run(image(), p);
    return info.valid && info.source == "RTR_HEADER_EXPORT" && info.state == "CONFIRMED";
}

bool unique_scan_and_failure() {
    auto p = pe();
    auto data = image();
    put32(data, 0x300 + 64, 0);
    put32(data, 0x300 + 68, 0);
    const auto scanned = prts::detect_ready_to_run(data, p);
    if (!scanned.valid || scanned.state != "LIKELY" || scanned.source != "UNIQUE_RTR_MAGIC_SCAN" ||
        scanned.header_rva != 0x3000)
        return false;
    put32(data, 0xa00 + 12, 0);
    const auto malformed = prts::detect_ready_to_run(data, p);
    if (!malformed.candidate || malformed.valid || malformed.state != "FAILED") return false;
    auto partial = image();
    put32(partial, 0x300 + 68, 0);
    const auto partial_info = prts::detect_ready_to_run(partial, p);
    return partial_info.candidate && !partial_info.valid && partial_info.state == "FAILED";
}

}  // namespace

int main() {
    if (!managed_header() || !export_header() || !unique_scan_and_failure()) return 1;
    std::cout << "PASS\n";
    return 0;
}
