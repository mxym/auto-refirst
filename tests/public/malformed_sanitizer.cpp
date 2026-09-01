#include "prts/android.hpp"
#include "prts/elf.hpp"
#include "prts/hermes.hpp"
#include "prts/jvm.hpp"
#include "prts/lua.hpp"
#include "prts/pe.hpp"
#include "prts/wasm.hpp"
#include "unity_engine_version.hpp"
#include "unity_registration_profile.hpp"
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <vector>


namespace {
void put64(std::vector<std::uint8_t>& data,std::size_t off,std::uint64_t value) {
    if (off+8>data.size()) return;
    for (std::size_t i=0;i<8;++i) data[off+i]=static_cast<std::uint8_t>(value>>(i*8));
}
std::size_t unity_raw(const prts::PeInfo& pe,std::uint64_t va) {
    return static_cast<std::size_t>(0x200+(va-(pe.image_base+0x1000)));
}
bool unity_profile_sanitizer_contract() {
    prts::PeInfo pe;pe.valid=true;pe.pe64=true;pe.machine=0x8664;pe.image_base=0x140000000ull;pe.headers_size=0x200;pe.image_size=0x3000;
    prts::PeSection sec;sec.name=".data";sec.rva=0x1000;sec.vsize=0x1000;sec.raw_offset=0x200;sec.raw_size=0x1000;sec.characteristics=0xC0000040u;pe.sections.push_back(sec);
    std::vector<std::uint8_t> image(0x1200);
    const auto tail=pe.image_base+0x1100,table=pe.image_base+0x1200,slot=pe.image_base+0x1300;
    put64(image,unity_raw(pe,tail),1);put64(image,unity_raw(pe,tail)+8,table);put64(image,unity_raw(pe,table),slot);put64(image,unity_raw(pe,slot),(1u<<29));
    auto strong=prts::probe_unity_metadata_registration_tail(image,pe,tail,4,4,4,4);
    if(strong.evidence!=prts::UnityMetadataRegistrationTailEvidence::StrongExtended)return false;
    put64(image,unity_raw(pe,slot),std::uint64_t(1)<<40);
    auto malformed=prts::probe_unity_metadata_registration_tail(image,pe,tail,4,4,4,4);
    if(malformed.evidence!=prts::UnityMetadataRegistrationTailEvidence::Unresolved)return false;
    const auto edge=pe.image_base+0x1ff8;
    auto truncated=prts::probe_unity_metadata_registration_tail(image,pe,edge,4,4,4,4);
    return truncated.evidence==prts::UnityMetadataRegistrationTailEvidence::NotFileBacked;
}
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) return 2;
    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    const std::span<const std::uint8_t> bytes(data.data(), data.size());
    const auto pe = prts::parse_pe(bytes);
    const auto elf = prts::parse_elf(bytes);
    const auto wasm = prts::parse_wasm(bytes);
    const auto hermes = prts::parse_hermes_bytecode(bytes);
    const auto jvm = prts::parse_jvm_class(bytes);
    const auto dex = prts::parse_dex(bytes);
    const auto lua = prts::parse_luac(bytes);
    if (!unity_profile_sanitizer_contract()) return 4;
    // Also feed the malformed corpus through the profile probe using a synthetic writable section.
    // Small/truncated inputs should simply classify as non-file-backed or unresolved without UB/OOB.
    prts::PeInfo probe_pe;probe_pe.valid=true;probe_pe.pe64=true;probe_pe.machine=0x8664;probe_pe.image_base=0x180000000ull;
    prts::PeSection probe_sec;probe_sec.name=".data";probe_sec.rva=0x1000;probe_sec.vsize=static_cast<std::uint32_t>(std::min<std::size_t>(data.size(),std::numeric_limits<std::uint32_t>::max()));probe_sec.raw_size=probe_sec.vsize;probe_sec.characteristics=0xC0000040u;probe_pe.sections.push_back(probe_sec);
    (void)prts::probe_unity_metadata_registration_tail(bytes,probe_pe,probe_pe.image_base+0x1000,16,16,16,16);
    (void)prts::probe_unity_globalgamemanagers(bytes,bytes.size());
    (void)prts::probe_unityfs(bytes,bytes.size());
    // Consume results so an optimizing sanitizer build cannot discard parser calls.
    const unsigned observed = unsigned(pe.valid) + unsigned(elf.valid) + unsigned(wasm.valid) +
                              unsigned(hermes.valid) + unsigned(jvm.valid) + unsigned(dex.valid) +
                              unsigned(lua.valid);
    return observed > 7 ? 3 : 0;
}
