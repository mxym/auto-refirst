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

    // Godot's real engine strings include "encrypted pack directory" and
    // "encrypted pack-referenced". A raw substring match on "encrypted pack"
    // also matches ordinary "encrypted packet" diagnostics (e.g. GnuPG), so
    // route only when the pack phrase closes at an ASCII word boundary.
    auto packet=scan("invalid symkey encrypted packet");
    if(packet.hints.godot) fail("ordinary encrypted packet diagnostic routed Godot");
    if(!scan("Can't open encrypted pack directory.").hints.godot) fail("Godot encrypted-pack directory route lost");
    if(!scan("Can't open encrypted pack-referenced file 'x'.").hints.godot) fail("Godot encrypted-pack referenced-file route lost");
    if(!scan("ENCRYPTED PACK.").hints.godot) fail("case-insensitive Godot encrypted-pack terminal route lost");
    if(scan("unencrypted pack directory").hints.godot) fail("embedded encrypted-pack phrase without left boundary routed Godot");
    if(scan("bigodot").hints.godot) fail("embedded Godot substring in ordinary identifier routed Godot");
    if(!scan("Godot Engine v4").hints.godot) fail("delimited Godot engine route lost");

    prts::PeInfo pe; prts::ElfInfo elf;
    const std::string packet_text="invalid symkey encrypted packet";
    auto packet_findings=prts::detect_common(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(packet_text.data()),packet_text.size()),pe,elf,packet);
    for(const auto&f:packet_findings)if(f.family=="Godot") fail("ordinary encrypted packet diagnostic emitted Godot finding");
    const std::string godot_text="Can't open encrypted pack directory.";
    auto godot_scan=scan(godot_text);
    auto godot_findings=prts::detect_common(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(godot_text.data()),godot_text.size()),pe,elf,godot_scan);
    bool saw_godot=false;
    for(const auto&f:godot_findings)if(f.family=="Godot"){saw_godot=true;if(f.state!="SUSPECTED")fail("string-only Godot evidence was promoted above SUSPECTED");}
    if(!saw_godot)fail("delimited Godot encrypted-pack string finding lost");

    // PYZ magic is a route candidate only. The dedicated PyInstaller parser
    // must validate CArchive/PYZ geometry before confidence is raised.
    const std::string pyz_text("xxxxPYZ\0junk",12);
    auto pyz_scan=scan(pyz_text);
    if(!pyz_scan.hints.pyinstaller)fail("raw PYZ marker no longer routes PyInstaller validation");
    auto pyz_findings=prts::detect_common(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(pyz_text.data()),pyz_text.size()),pe,elf,pyz_scan);
    bool saw_pyz=false;for(const auto&f:pyz_findings)if(f.family=="PyInstaller"){saw_pyz=true;if(f.state!="SUSPECTED"||f.kind!="container_hint")fail("raw PYZ marker was promoted above route-only SUSPECTED");}
    if(!saw_pyz)fail("raw PYZ marker route-only finding lost");

    const std::string pyinstaller_text="PyInstaller pyimod bootstrap bait";
    auto pyinstaller_scan=scan(pyinstaller_text);
    if(!pyinstaller_scan.hints.pyinstaller)fail("PyInstaller string route lost");
    auto pyinstaller_findings=prts::detect_common(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(pyinstaller_text.data()),pyinstaller_text.size()),pe,elf,pyinstaller_scan);
    bool saw_pyinstaller_string=false;for(const auto&f:pyinstaller_findings)if(f.family=="PyInstaller"){saw_pyinstaller_string=true;if(f.state!="SUSPECTED")fail("string-only PyInstaller evidence was promoted above SUSPECTED");}
    if(!saw_pyinstaller_string)fail("PyInstaller string route-only finding lost");

    if(pyz_scan.embedded.size()!=1||pyz_scan.embedded[0].kind!="PYZ"||pyz_scan.embedded[0].state!="SUSPECTED")fail("raw PYZ embedded marker retained high-confidence state");
    const std::string gdpc_text="xxxxGDPCjunk";
    auto gdpc_scan=scan(gdpc_text);
    if(!gdpc_scan.hints.godot||gdpc_scan.embedded.size()!=1||gdpc_scan.embedded[0].kind!="GodotPCK"||gdpc_scan.embedded[0].state!="SUSPECTED")fail("raw GDPC embedded marker retained high-confidence state");

    std::cout << "PASS\n";
    return 0;
}
