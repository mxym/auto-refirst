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

    // Bare _MEI is too broad: READ_MEID and similar ordinary identifiers
    // occur in system libraries. Preserve concrete historical/current
    // PyInstaller bootloader identifiers instead.
    if(scan("READ_MEID").hints.pyinstaller)fail("ordinary READ_MEID identifier routed PyInstaller");
    if(!scan("_MEIXXXXXX").hints.pyinstaller)fail("historical POSIX _MEIXXXXXX route lost");
    if(!scan("_MEI%08xXXXXXX").hints.pyinstaller)fail("Windows/current _MEI format route lost");
    if(!scan("_MEIPASS2").hints.pyinstaller)fail("legacy _MEIPASS2 route lost");
    if(!scan("sys._MEIPASS").hints.pyinstaller)fail("sys._MEIPASS route lost");
    if(!scan("_PYI_APPLICATION_HOME_DIR").hints.pyinstaller)fail("current _PYI application-home route lost");

    if(pyz_scan.embedded.size()!=1||pyz_scan.embedded[0].kind!="PYZ"||pyz_scan.embedded[0].state!="SUSPECTED"||pyz_scan.embedded[0].size!=4)fail("raw PYZ marker lost its exact magic range");
    const std::string gdpc_text="xxxxGDPCjunk";
    auto gdpc_scan=scan(gdpc_text);
    if(!gdpc_scan.hints.godot||gdpc_scan.embedded.size()!=1||gdpc_scan.embedded[0].kind!="GodotPCK"||gdpc_scan.embedded[0].state!="SUSPECTED"||gdpc_scan.embedded[0].size!=4)fail("raw GDPC marker lost its exact magic range");

    // The four-byte ELF ident marker alone is not enough to claim a validated
    // child: a truncated/otherwise malformed payload must stay route-only
    // until the bounded nested-ELF validator closes its geometry and extent.
    std::string elf_candidate("xx",2);
    elf_candidate.push_back(char(0x7f));
    elf_candidate.append("ELF",3);
    elf_candidate.push_back(char(2));
    elf_candidate.push_back(char(1));
    elf_candidate.push_back(char(1));
    elf_candidate.push_back(char(0));
    elf_candidate.append(56,'\0');
    const auto elf_scan=scan(elf_candidate);
    if(elf_scan.embedded.size()!=1||elf_scan.embedded[0].kind!="ELF"||elf_scan.embedded[0].state!="SUSPECTED"||elf_scan.embedded[0].validated||elf_scan.embedded[0].size!=4)fail("raw ELF marker was promoted above route-only candidate state");

    // Likewise, a marker with a plausible section table but no PE optional
    // header must remain a candidate until the full nested validator runs.
    std::string pe_candidate(0x300,'\0');
    pe_candidate[2]='M'; pe_candidate[3]='Z';
    pe_candidate[2+0x3c]=0x40;
    pe_candidate[2+0x40]='P'; pe_candidate[2+0x41]='E';
    pe_candidate[2+0x46]=1; // one section
    pe_candidate[2+0x58+16]=0x10; // section raw size
    pe_candidate[2+0x58+20]=char(0x80); // section raw offset
    const auto pe_scan=scan(pe_candidate);
    if(pe_scan.embedded.size()!=1||pe_scan.embedded[0].kind!="PE"||pe_scan.embedded[0].state!="SUSPECTED"||pe_scan.embedded[0].validated)fail("raw PE marker was promoted above route-only candidate state");

    std::cout << "PASS\n";
    return 0;
}
