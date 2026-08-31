#include "prts/nuitka.hpp"
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
void append_text(std::vector<std::uint8_t>& out, std::string_view s) {
    out.insert(out.end(), s.begin(), s.end());
}
void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (unsigned i=0;i<4;++i) out.push_back(static_cast<std::uint8_t>(v>>(i*8)));
}
void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (unsigned i=0;i<8;++i) out.push_back(static_cast<std::uint8_t>(v>>(i*8)));
}
void append_name(std::vector<std::uint8_t>& out, std::string_view s) {
    append_text(out,s); out.push_back(0);
}
[[noreturn]] void fail(const char* msg) { std::cerr << msg << '\n'; std::exit(1); }
}

int main() {
    prts::PeInfo pe;
    prts::ElfInfo elf;

    // Generic CPython APIs and literal ecosystem names are not structural proof.
    std::vector<std::uint8_t> bait;
    append_text(bait,"PyByteArray_FromStringAndSize Nuitka __nuitka__ constant_bin_data");
    auto weak=prts::detect_nuitka(bait,pe,elf);
    if(weak.valid) fail("string/API-only Nuitka bait was promoted to valid");

    // A bounded KAX member stream is a structural onefile closure.
    std::vector<std::uint8_t> kax={'K','A','X'};
    append_name(kax,"main.bin"); append_u64(kax,3); append_text(kax,"abc"); kax.push_back(0);
    auto onefile=prts::detect_nuitka(kax,pe,elf);
    if(!onefile.valid || !onefile.onefile || onefile.entries.size()!=1 || onefile.variant.rfind("onefile-KAX-raw",0)!=0)
        fail("synthetic KAX archive did not validate");

    // Constant tag encodings changed across Nuitka generations. The directory
    // geometry itself is the identity gate; tag decoding may remain partial.
    std::vector<std::uint8_t> constants;
    append_name(constants,".bytecode"); append_u32(constants,1025); constants.insert(constants.end(),1025,0x72);
    append_name(constants,"__main__"); append_u32(constants,8); constants.insert(constants.end(),8,0);
    auto standalone=prts::detect_nuitka(constants,pe,elf);
    if(!standalone.valid || standalone.onefile || standalone.constant_blocks.size()!=2 || standalone.variant!="standalone-constant-blob")
        fail("synthetic Nuitka constant directory did not validate");

    auto finding=prts::nuitka_finding(standalone);
    if(finding.state!="CONFIRMED") fail("validated constant directory was not CONFIRMED");
    if(finding.fields["decode_failures"]!="2") fail("legacy/unknown constant tags were not retained as partial decode evidence");

    std::cout << "PASS\n";
    return 0;
}
