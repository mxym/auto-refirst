#include "prts/static_scan.hpp"
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string>

namespace {
prts::StaticScanReport scan(const std::string& s) {
    return prts::scan_static(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()),s.size()));
}
[[noreturn]] void fail(const char* msg) { std::cerr << msg << '\n'; std::exit(1); }
}

int main() {
    // Ordinary English substrings and even a standalone UNITY token must not
    // route the expensive Unity parser.
    auto prose=scan("take this opportunity to serve the community in UNITY");
    if(prose.hints.unity) fail("ordinary English unity substring/token routed Unity");

    // Keep route anchors aligned with evidence the Unity parser consumes.
    if(!scan("UnityPlayer.dll").hints.unity) fail("UnityPlayer route lost");
    if(!scan("il2cpp_init").hints.unity) fail("IL2CPP route lost");
    if(!scan("global-metadata.dat").hints.unity) fail("global-metadata route lost");

    std::cout << "PASS\n";
    return 0;
}
