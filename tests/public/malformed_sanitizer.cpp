#include "prts/android.hpp"
#include "prts/elf.hpp"
#include "prts/jvm.hpp"
#include "prts/lua.hpp"
#include "prts/pe.hpp"
#include "prts/wasm.hpp"
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) return 2;
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    const std::span<const std::uint8_t> bytes(data.data(), data.size());
    const auto pe = prts::parse_pe(bytes);
    const auto elf = prts::parse_elf(bytes);
    const auto wasm = prts::parse_wasm(bytes);
    const auto jvm = prts::parse_jvm_class(bytes);
    const auto dex = prts::parse_dex(bytes);
    const auto lua = prts::parse_luac(bytes);
    // Consume results so an optimizing sanitizer build cannot discard parser calls.
    const unsigned observed = unsigned(pe.valid) + unsigned(elf.valid) + unsigned(wasm.valid) +
                              unsigned(jvm.valid) + unsigned(dex.valid) + unsigned(lua.valid);
    return observed > 6 ? 3 : 0;
}
