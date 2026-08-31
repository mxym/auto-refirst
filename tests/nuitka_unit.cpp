#include "prts/nuitka.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace {
void append_text(std::vector<std::uint8_t>& out, std::string_view s) {
    out.insert(out.end(), s.begin(), s.end());
}
void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    for (unsigned i=0;i<2;++i) out.push_back(static_cast<std::uint8_t>(v>>(i*8)));
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
std::vector<std::uint8_t> constant_directory_with_main(const std::vector<std::uint8_t>& main) {
    std::vector<std::uint8_t> bytecode;
    append_u16(bytecode,1);
    bytecode.push_back('B');
    append_u32(bytecode,1017);
    bytecode.insert(bytecode.end(),1017,'x');
    bytecode.push_back('.');

    std::vector<std::uint8_t> out;
    append_name(out,".bytecode"); append_u32(out,static_cast<std::uint32_t>(bytecode.size())); out.insert(out.end(),bytecode.begin(),bytecode.end());
    append_name(out,"__main__"); append_u32(out,static_cast<std::uint32_t>(main.size())); out.insert(out.end(),main.begin(),main.end());
    return out;
}
std::vector<std::uint8_t> legacy_constant_directory(bool long64, bool trailing=false) {
    std::vector<std::uint8_t> main;
    append_u16(main,5);
    main.push_back('u'); append_name(main,"legacy");
    main.push_back('l');
    if(long64) append_u64(main,42); else append_u32(main,42);
    main.push_back('q'); append_u64(main,0xffffffffffffffd5ull);
    main.push_back('G');
    main.push_back('u'); append_name(main,"origin");
    main.push_back('u'); append_name(main,"args");
    main.push_back('g'); main.push_back('-'); append_u32(main,1); append_u64(main,123);
    main.push_back('.');
    if(trailing) main.push_back(0);
    return constant_directory_with_main(main);
}
[[noreturn]] void fail(const char* msg) { std::cerr << msg << '\n'; std::exit(1); }

void put_u32(std::vector<std::uint8_t>& b, std::size_t o, std::uint32_t v) {
    if (b.size()<o+4) b.resize(o+4);
    for (unsigned i=0;i<4;++i) b[o+i]=static_cast<std::uint8_t>(v>>(i*8));
}
void put_u64(std::vector<std::uint8_t>& b, std::size_t o, std::uint64_t v) {
    if (b.size()<o+8) b.resize(o+8);
    for (unsigned i=0;i<8;++i) b[o+i]=static_cast<std::uint8_t>(v>>(i*8));
}
void put_cstr(std::vector<std::uint8_t>& b, std::size_t o, std::string_view s) {
    if (b.size()<o+s.size()+1) b.resize(o+s.size()+1);
    std::memcpy(b.data()+o,s.data(),s.size()); b[o+s.size()]=0;
}
void emit(std::vector<std::uint8_t>& b, std::size_t& o, std::initializer_list<std::uint8_t> bytes) {
    if (b.size()<o+bytes.size()) b.resize(o+bytes.size());
    for(auto x:bytes)b[o++]=x;
}
void emit_call(std::vector<std::uint8_t>& b, std::size_t& o, std::uint64_t code_va, std::uint64_t target) {
    const auto ip=code_va+o; emit(b,o,{0xe8,0,0,0,0});
    const auto disp=static_cast<std::int64_t>(target)-static_cast<std::int64_t>(ip+5);
    put_u32(b,o-4,static_cast<std::uint32_t>(static_cast<std::int32_t>(disp)));
}
void emit_lea_rip(std::vector<std::uint8_t>& b, std::size_t& o, std::uint64_t code_va, std::uint8_t modrm, std::uint64_t target) {
    const auto ip=code_va+o; emit(b,o,{0x48,0x8d,modrm,0,0,0,0});
    const auto disp=static_cast<std::int64_t>(target)-static_cast<std::int64_t>(ip+7);
    put_u32(b,o-4,static_cast<std::uint32_t>(static_cast<std::int32_t>(disp)));
}
struct VersionFixture { std::vector<std::uint8_t> bytes; prts::ElfInfo elf; std::size_t desc_name_off=0,field0_off=0,third_call_off=0; };
VersionFixture version_fixture() {
    VersionFixture f;f.bytes.resize(0x1800);constexpr std::uint64_t XVA=0x400000,DVA=0x500000;
    f.elf.valid=true;f.elf.elf64=true;f.elf.little_endian=true;f.elf.machine=62;f.elf.dynamic.state="RESOLVED";
    f.elf.segments.push_back({1,5,0,XVA,0x800,0x800,0x1000,0,0});
    f.elf.segments.push_back({1,4,0x1000,DVA,0x800,0x800,0x1000,0,0});
    constexpr std::uint64_t INIT=XVA+0x500,NEW=XVA+0x510,PYLONG=XVA+0x520,UNICODE=XVA+0x530;
    auto sym=[&](std::string n,std::uint64_t va){prts::ElfDynamicSymbol x;x.name=std::move(n);x.value=va;x.value_file_backed=true;x.exported=true;f.elf.dynamic.symbols.push_back(std::move(x));};
    sym("PyStructSequence_InitType",INIT);sym("PyStructSequence_New",NEW);sym("PyLong_FromLong",PYLONG);sym("PyUnicode_FromString",UNICODE);
    const auto desc=DVA+0x100,fields=DVA+0x180,name=DVA+0x300,doc=DVA+0x330,release=DVA+0x390;
    const std::array<std::string_view,4> names={"major","minor","micro","releaselevel"};
    put_u64(f.bytes,0x1100,name);put_u64(f.bytes,0x1108,doc);put_u64(f.bytes,0x1110,fields);put_u32(f.bytes,0x1118,6);
    f.desc_name_off=0x1300;put_cstr(f.bytes,f.desc_name_off,"__nuitka_version__");put_cstr(f.bytes,0x1330,"__compiled__\\n\\nVersion information as a named tuple.");put_cstr(f.bytes,0x1390,"release");
    for(std::size_t i=0;i<names.size();++i){auto sva=DVA+0x400+i*0x30;put_u64(f.bytes,0x1180+i*16,sva);put_u64(f.bytes,0x1188+i*16,DVA+0x600+i*0x20);put_cstr(f.bytes,0x1400+i*0x30,names[i]);put_cstr(f.bytes,0x1600+i*0x20,"doc");}
    // remaining descriptor fields are structurally irrelevant but valid pointers.
    put_u64(f.bytes,0x11c0,DVA+0x4c0);put_u64(f.bytes,0x11c8,DVA+0x680);put_cstr(f.bytes,0x14c0,"standalone");put_cstr(f.bytes,0x1680,"doc");
    put_u64(f.bytes,0x11d0,DVA+0x4f0);put_u64(f.bytes,0x11d8,DVA+0x6a0);put_cstr(f.bytes,0x14f0,"onefile");put_cstr(f.bytes,0x16a0,"doc");
    std::size_t o=0x100;emit_lea_rip(f.bytes,o,XVA,0x35,desc);emit_call(f.bytes,o,XVA,INIT);emit_call(f.bytes,o,XVA,NEW);emit(f.bytes,o,{0x49,0x89,0xc4});
    auto version=[&](std::uint32_t v,std::uint8_t slot){emit(f.bytes,o,{0xbf,0,0,0,0});put_u32(f.bytes,o-4,v);if(slot==0x28)f.third_call_off=o;emit_call(f.bytes,o,XVA,PYLONG);emit(f.bytes,o,{0x49,0x89,0x44,0x24,slot});};
    version(4,0x18);version(2,0x20);version(0,0x28);emit_lea_rip(f.bytes,o,XVA,0x3d,release);emit_call(f.bytes,o,XVA,UNICODE);emit(f.bytes,o,{0x49,0x89,0x44,0x24,0x30,0xc3});
    f.field0_off=0x1400;return f;
}
VersionFixture imported_version_fixture() {
    auto f=version_fixture();constexpr std::uint64_t XVA=0x400000,DVA=0x500000;
    const std::array<std::pair<std::string,std::uint64_t>,4> api={{{"PyStructSequence_InitType",XVA+0x500},{"PyStructSequence_New",XVA+0x510},{"PyLong_FromLong",XVA+0x520},{"PyUnicode_FromString",XVA+0x530}}};
    f.elf.dynamic.symbols.clear();f.elf.dynamic.relocations.clear();
    for(std::size_t i=0;i<api.size();++i){
        prts::ElfDynamicSymbol sym;sym.index=static_cast<std::uint32_t>(i);sym.name=api[i].first;sym.imported=true;f.elf.dynamic.symbols.push_back(sym);
        const auto got=DVA+0x700+i*8,plt=api[i].second;const auto off=static_cast<std::size_t>(plt-XVA);std::size_t q=off;emit(f.bytes,q,{0xff,0x25,0,0,0,0});
        const auto disp=static_cast<std::int64_t>(got)-static_cast<std::int64_t>(plt+6);put_u32(f.bytes,off+2,static_cast<std::uint32_t>(static_cast<std::int32_t>(disp)));
        prts::ElfRelocation rel;rel.symbol_index=static_cast<std::uint32_t>(i);rel.target_va=got;rel.plt=true;f.elf.dynamic.relocations.push_back(rel);
    }
    prts::ElfDynamicSymbol init;init.index=static_cast<std::uint32_t>(f.elf.dynamic.symbols.size());init.name="PyInit_sample";init.value=XVA+0x600;init.value_file_backed=true;init.exported=true;f.elf.dynamic.symbols.push_back(init);
    return f;
}
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

    // The real onefile bootstrap reads filenames into filename_char_t[1024].
    // Incidental KAX bytes followed by a longer printable run must therefore
    // fail before random zero bytes can close a fake zero-length entry.
    std::vector<std::uint8_t> long_name_kax={'K','A','X'};
    long_name_kax.insert(long_name_kax.end(),1024,'a');long_name_kax.push_back(0);
    long_name_kax.push_back(0);append_u64(long_name_kax,0);long_name_kax.push_back(0);
    if(prts::detect_nuitka(long_name_kax,pe,elf).valid)fail("overlong onefile filename unexpectedly validated");

    // Nuitka before 2.0 used native fixed-width counts and C-long values. Both
    // 64-bit and 32-bit C-long profiles must close through declared count and
    // the final END tag before semantic output is accepted.
    for(bool long64:std::array<bool,2>{true,false}){
        auto legacy_bytes=legacy_constant_directory(long64);
        auto legacy=prts::detect_nuitka(legacy_bytes,pe,elf);
        if(!legacy.valid||legacy.constant_blocks.size()!=2||legacy.decoded_blocks.size()!=2) fail("legacy fixed-width constant directory did not validate");
        if(!legacy.decoded_blocks[0].success||!legacy.decoded_blocks[1].success) fail("legacy fixed-width constant stream did not decode");
        const auto& values=legacy.decoded_blocks[1].values;
        if(values.size()!=5||values[0]!="\"legacy\""||values[1]!="42"||values[2]!="-43"||values[3]!="GenericAlias(\"origin\", \"args\")"||values[4]!="-bigint[1 parts]") fail("legacy fixed-width constant semantics were not recovered");
        auto legacy_finding=prts::nuitka_finding(legacy);
        if(legacy_finding.fields["decoded_blocks"]!="2"||legacy_finding.fields["decode_failures"]!="0") fail("legacy fixed-width decode accounting was not complete");
    }
    auto trailing_legacy=prts::detect_nuitka(legacy_constant_directory(true,true),pe,elf);
    auto trailing_finding=prts::nuitka_finding(trailing_legacy);
    if(trailing_finding.fields["decode_failures"]!="1") fail("legacy constant stream trailing bytes did not fail closed");

    // A byte sequence can be syntactically complete under both the modern
    // varint and legacy fixed32 profiles while representing different values.
    // Such cross-profile semantic ambiguity must be withheld rather than guessed.
    std::vector<std::uint8_t> ambiguous_main;
    append_u16(ambiguous_main,1); ambiguous_main.push_back('l');
    ambiguous_main.insert(ambiguous_main.end(),{0x81,0x80,0x80,0x00}); ambiguous_main.push_back('.');
    auto ambiguous=prts::detect_nuitka(constant_directory_with_main(ambiguous_main),pe,elf);
    if(ambiguous.decoded_blocks.size()!=2||ambiguous.decoded_blocks[1].success||ambiguous.decoded_blocks[1].error!="constant stream encoding profile ambiguous") fail("cross-profile constant semantics did not fail closed");

    std::vector<std::uint8_t> huge_main;
    append_u16(huge_main,1); huge_main.push_back('T'); append_u32(huge_main,0xffffffffu); huge_main.push_back('.');
    auto huge=prts::detect_nuitka(constant_directory_with_main(huge_main),pe,elf);
    if(huge.decoded_blocks.size()!=2||huge.decoded_blocks[1].success) fail("unreasonable legacy/modern sequence count unexpectedly decoded");

    // Malformed/unknown constant streams must not weaken the structural
    // directory identity gate; semantic decoding may remain partial.
    std::vector<std::uint8_t> constants;
    append_name(constants,".bytecode"); append_u32(constants,1025); constants.insert(constants.end(),1025,0x72);
    append_name(constants,"__main__"); append_u32(constants,8); constants.insert(constants.end(),8,0);
    auto standalone=prts::detect_nuitka(constants,pe,elf);
    if(!standalone.valid || standalone.onefile || standalone.constant_blocks.size()!=2 || standalone.variant!="standalone-constant-blob")
        fail("synthetic Nuitka constant directory did not validate");

    auto finding=prts::nuitka_finding(standalone);
    if(finding.state!="CONFIRMED") fail("validated constant directory was not CONFIRMED");
    if(finding.fields["decode_failures"]!="2") fail("legacy/unknown constant tags were not retained as partial decode evidence");

    // The compiled-version plane is a separate structural closure: the exact
    // Nuitka PyStructSequence descriptor plus three consecutive integer tuple
    // initializers and a validated releaselevel string.
    auto vf=version_fixture();auto cv=prts::detect_nuitka_compiled_version(vf.bytes,vf.elf);
    if(!cv.valid||cv.major!=4||cv.minor!=2||cv.micro!=0||cv.releaselevel!="release") fail("synthetic __compiled__ version tuple did not validate");
    if(cv.profile!="ELF64_X86_64_PYSTRUCTSEQUENCE_PYLONG_DIRECT") fail("synthetic version tuple used unexpected profile");
    auto imported=imported_version_fixture();auto imported_cv=prts::detect_nuitka_compiled_version(imported.bytes,imported.elf);
    if(!imported_cv.valid||imported_cv.major!=4||imported_cv.minor!=2||imported_cv.micro!=0||imported_cv.releaselevel!="release") fail("synthetic imported-PLT __compiled__ tuple did not validate");
    if(imported_cv.profile!="ELF64_X86_64_PYSTRUCTSEQUENCE_PYLONG_PLT_IMPORT") fail("synthetic imported-PLT tuple used unexpected profile");
    auto candidate=vf;put_cstr(candidate.bytes,0x1390,"candidate");auto candidate_cv=prts::detect_nuitka_compiled_version(candidate.bytes,candidate.elf);
    if(!candidate_cv.valid||candidate_cv.releaselevel!="candidate") fail("Nuitka candidate releaselevel did not validate");
    auto alpha=vf;put_cstr(alpha.bytes,0x1390,"alpha");if(prts::detect_nuitka_compiled_version(alpha.bytes,alpha.elf).valid) fail("non-emitted alpha releaselevel unexpectedly validated");
    auto bad_import=imported;bad_import.elf.dynamic.symbols[0].name="PyStructSequence_InitType_bait";if(prts::detect_nuitka_compiled_version(bad_import.bytes,bad_import.elf).valid) fail("mismatched imported CPython symbol unexpectedly validated");
    auto imported_identity=prts::detect_nuitka(imported.bytes,pe,imported.elf);
    if(!imported_identity.valid||imported_identity.onefile||imported_identity.variant!="module-compiled-version-structseq"||!imported_identity.compiled_version.valid) fail("compiled-version structseq did not independently confirm synthetic Nuitka module");
    auto imported_finding=prts::nuitka_finding(imported_identity);if(imported_finding.state!="CONFIRMED") fail("structurally validated synthetic Nuitka module was not CONFIRMED");
    auto bad_name=vf;bad_name.bytes[bad_name.desc_name_off]='X';if(prts::detect_nuitka_compiled_version(bad_name.bytes,bad_name.elf).valid) fail("mutated Nuitka descriptor name did not fail closed");
    auto bad_field=vf;bad_field.bytes[bad_field.field0_off]='M';if(prts::detect_nuitka_compiled_version(bad_field.bytes,bad_field.elf).valid) fail("mutated Nuitka descriptor field order did not fail closed");
    auto bad_ctor=vf;bad_ctor.bytes[bad_ctor.third_call_off]=0xe8;put_u32(bad_ctor.bytes,bad_ctor.third_call_off+1,0);if(prts::detect_nuitka_compiled_version(bad_ctor.bytes,bad_ctor.elf).valid) fail("mixed integer constructor provenance did not fail closed");

    // Malformed geometry must remain fail-closed under the same parser used by
    // ASan/UBSan CI builds. Exercise truncation, overflowing address spaces,
    // bogus descriptor pointers, conflicting symbols, and instruction damage.
    for(std::size_t cut:std::array<std::size_t,8>{0,1,0x100,0x105,0x200,0x1000,0x1120,0x1400}){
        auto x=prts::detect_nuitka_compiled_version(std::span<const std::uint8_t>(vf.bytes.data(),cut),vf.elf);
        if(x.valid) fail("truncated Nuitka version fixture unexpectedly validated");
    }
    auto bad_exec=vf;bad_exec.elf.segments[0].offset=std::numeric_limits<std::uint64_t>::max();bad_exec.elf.segments[0].file_size=std::numeric_limits<std::uint64_t>::max();
    if(prts::detect_nuitka_compiled_version(bad_exec.bytes,bad_exec.elf).valid) fail("overflowing executable segment unexpectedly validated");
    auto bad_va=vf;bad_va.elf.segments[0].address=std::numeric_limits<std::uint64_t>::max()-2;
    if(prts::detect_nuitka_compiled_version(bad_va.bytes,bad_va.elf).valid) fail("overflowing executable VA unexpectedly validated");
    auto bad_name_ptr=vf;put_u64(bad_name_ptr.bytes,0x1100,std::numeric_limits<std::uint64_t>::max());
    if(prts::detect_nuitka_compiled_version(bad_name_ptr.bytes,bad_name_ptr.elf).valid) fail("overflowing descriptor name pointer unexpectedly validated");
    auto bad_fields_ptr=vf;put_u64(bad_fields_ptr.bytes,0x1110,std::numeric_limits<std::uint64_t>::max()-8);
    if(prts::detect_nuitka_compiled_version(bad_fields_ptr.bytes,bad_fields_ptr.elf).valid) fail("overflowing descriptor fields pointer unexpectedly validated");
    auto duplicate_symbol=vf;duplicate_symbol.elf.dynamic.symbols.front().value+=1;prts::ElfDynamicSymbol duplicate=duplicate_symbol.elf.dynamic.symbols.front();duplicate.value-=1;duplicate_symbol.elf.dynamic.symbols.push_back(std::move(duplicate));
    if(prts::detect_nuitka_compiled_version(duplicate_symbol.bytes,duplicate_symbol.elf).valid) fail("conflicting CPython symbol addresses unexpectedly validated");
    auto over_budget=vf;over_budget.elf.segments[0].file_size=65ull*1024ull*1024ull;auto budget=prts::detect_nuitka_compiled_version(over_budget.bytes,over_budget.elf);
    if(budget.valid||budget.error.empty()) fail("oversized executable scan geometry did not fail with a bounded diagnostic");
    for(std::size_t off=0x100;off<0x180;++off){auto damaged=vf;damaged.bytes[off]^=0x5a;(void)prts::detect_nuitka_compiled_version(damaged.bytes,damaged.elf);}

    std::cout << "PASS\n";
    return 0;
}
