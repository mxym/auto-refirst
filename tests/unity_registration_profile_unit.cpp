#include "unity_registration_profile.hpp"
#include <cstdlib>
#include <iostream>
#include <vector>
#include <string>

namespace {
void need(bool value, const char* message) {
    if (!value) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}
using E = prts::UnityMetadataRegistrationTailEvidence;
using H = prts::UnityMetadataRegistrationEngineHint;
void put64(std::vector<std::uint8_t>&d,std::size_t off,std::uint64_t v){
    need(off+8<=d.size(),"put64 bounds");
    for(std::size_t i=0;i<8;++i)d[off+i]=static_cast<std::uint8_t>(v>>(i*8));
}
std::size_t raw(const prts::PeInfo&pe,std::uint64_t va){return static_cast<std::size_t>(0x200+(va-(pe.image_base+0x1000)));}
prts::PeInfo synthetic_pe(){
    prts::PeInfo pe;pe.valid=true;pe.pe64=true;pe.machine=0x8664;pe.image_base=0x140000000ull;pe.headers_size=0x200;pe.image_size=0x3000;
    prts::PeSection sec;sec.name=".data";sec.rva=0x1000;sec.vsize=0x1000;sec.raw_offset=0x200;sec.raw_size=0x1000;sec.characteristics=0xC0000040u;pe.sections.push_back(sec);return pe;
}
}

int main() {
    {
        prts::UnityEngineVersionValue v{6000,6,0,5,'a'};
        need(prts::unity_metadata_registration_engine_hint(106,v)==H::Traditional106,"v106 before 6000.6.0a6 maps to 106");
        v.channel_number=6;need(prts::unity_metadata_registration_engine_hint(106,v)==H::Extended1061,"v106 6000.6.0a6 maps to 106.1");
        v={6000,6,0,1,'b'};need(prts::unity_metadata_registration_engine_hint(106,v)==H::Extended1061,"v106 beta sorts after alpha threshold");
        v={6000,5,1,1,'f'};need(prts::unity_metadata_registration_engine_hint(107,v)==H::Traditional106,"v107 Unity 6.5 backport maps to 106");
        v={6000,6,0,1,'a'};need(prts::unity_metadata_registration_engine_hint(107,v)==H::Extended1061,"v107 Unity 6.6 maps to 106.1");
        need(prts::unity_metadata_registration_engine_hint(105,v)==H::None,"unrelated declared version has no 106 hint");
    }
    {
        auto d = prts::decide_unity_metadata_registration_profile(105, E::NotApplicable);
        need(d.state == "RESOLVED" && d.profile == "traditional-8pair" && d.normalized_variant == "105" && d.role_count == 8 && !d.include_always_init,
             "v105 traditional profile");
    }
    for (int declared : {106, 107}) {
        auto traditional = prts::decide_unity_metadata_registration_profile(declared, E::NotFileBacked);
        need(traditional.state == "RESOLVED" && traditional.profile == "traditional-8pair" && traditional.normalized_variant == "106" && traditional.role_count == 8,
             "106/107 traditional positive boundary evidence");
        auto extended = prts::decide_unity_metadata_registration_profile(declared, E::StrongExtended);
        need(extended.state == "RESOLVED" && extended.profile == "extended-9pair" && extended.normalized_variant == "106.1" && extended.role_count == 9 && extended.include_always_init,
             "106/107 strong extended profile");
        auto zero = prts::decide_unity_metadata_registration_profile(declared, E::ZeroPair);
        need(zero.state == "AMBIGUOUS" && zero.normalized_variant == "106|106.1" && zero.role_count == 8 && !zero.include_always_init,
             "106/107 zero tail remains ambiguous");
        auto unresolved = prts::decide_unity_metadata_registration_profile(declared, E::Unresolved);
        need(unresolved.state == "AMBIGUOUS" && unresolved.normalized_variant == "106|106.1" && unresolved.role_count == 8 && !unresolved.include_always_init,
             "106/107 malformed or unproven tail remains ambiguous");
    }
    for (int declared : {106,107}) {
        auto t0=prts::decide_unity_metadata_registration_profile(declared,E::ZeroPair,H::Traditional106);
        need(t0.state=="RESOLVED"&&t0.normalized_variant=="106"&&t0.role_count==8&&!t0.include_always_init,"engine 106 resolves zero tail as traditional");
        auto tu=prts::decide_unity_metadata_registration_profile(declared,E::Unresolved,H::Traditional106);
        need(tu.state=="RESOLVED"&&tu.normalized_variant=="106"&&!tu.include_always_init,"engine 106 treats unresolved post-prefix bytes as outside 8-pair struct");
        auto tc=prts::decide_unity_metadata_registration_profile(declared,E::StrongExtended,H::Traditional106);
        need(tc.state=="CONFLICT"&&tc.normalized_variant=="106|106.1"&&tc.role_count==8&&!tc.include_always_init,"engine 106 conflicts with strong 106.1 structure");
        auto ez=prts::decide_unity_metadata_registration_profile(declared,E::ZeroPair,H::Extended1061);
        need(ez.state=="RESOLVED"&&ez.normalized_variant=="106.1"&&ez.role_count==9&&ez.include_always_init,"engine 106.1 resolves zero extension");
        auto es=prts::decide_unity_metadata_registration_profile(declared,E::StrongExtended,H::Extended1061);
        need(es.state=="RESOLVED"&&es.normalized_variant=="106.1"&&es.role_count==9&&es.include_always_init,"engine and strong 106.1 structure corroborate");
        auto ei=prts::decide_unity_metadata_registration_profile(declared,E::Unresolved,H::Extended1061);
        need(ei.state=="INVALID"&&ei.role_count==8&&!ei.include_always_init,"engine 106.1 cannot wash malformed ninth pair");
        auto eb=prts::decide_unity_metadata_registration_profile(declared,E::NotFileBacked,H::Extended1061);
        need(eb.state=="INVALID"&&eb.role_count==8&&!eb.include_always_init,"engine 106.1 requires file-backed ninth pair");
    }
    {
        auto d = prts::decide_unity_metadata_registration_profile(108, E::StrongExtended);
        need(d.state == "RESOLVED" && d.profile == "v108 compact-7pair" && d.normalized_variant == "108" && d.role_count == 7 && d.include_always_init,
             "v108 compact profile");
    }
    {
        auto pe=synthetic_pe();std::vector<std::uint8_t> image(0x1200);const auto tail_va=pe.image_base+0x1100;
        auto probe=prts::probe_unity_metadata_registration_tail(image,pe,tail_va,5,5,5,5);
        need(probe.evidence==E::ZeroPair,"PE probe zero pair ambiguity evidence");
        const auto table_va=pe.image_base+0x1200,slot0=pe.image_base+0x1300,slot1=pe.image_base+0x1308;
        put64(image,raw(pe,tail_va),2);put64(image,raw(pe,tail_va)+8,table_va);
        put64(image,raw(pe,table_va),slot0);put64(image,raw(pe,table_va)+8,slot1);
        put64(image,raw(pe,slot0),(1u<<29)|(0u<<1));
        put64(image,raw(pe,slot1),(4u<<29)|(1u<<1));
        probe=prts::probe_unity_metadata_registration_tail(image,pe,tail_va,5,5,5,5);
        need(probe.evidence==E::StrongExtended && probe.count==2 && probe.pointer_va==table_va,"PE probe strong 106.1 extended evidence");
        put64(image,raw(pe,slot1),(4u<<29)|(5u<<1));
        probe=prts::probe_unity_metadata_registration_tail(image,pe,tail_va,5,5,5,5);
        need(probe.evidence==E::Unresolved,"PE probe rejects out-of-range always-init source");
        put64(image,raw(pe,slot1),(4u<<29)|(1u<<1));
        pe.sections[0].characteristics&=~0x80000000u;
        probe=prts::probe_unity_metadata_registration_tail(image,pe,tail_va,5,5,5,5);
        need(probe.evidence==E::Unresolved,"PE probe requires writable always-init slots");
        pe.sections[0].characteristics|=0x80000000u;
        const auto boundary_va=pe.image_base+0x1ff8;
        probe=prts::probe_unity_metadata_registration_tail(image,pe,boundary_va,5,5,5,5);
        need(probe.evidence==E::NotFileBacked,"PE probe recognizes ninth-pair file-backed boundary");
    }
    need(prts::decide_unity_metadata_registration_profile(109, E::NotApplicable).state == "UNSUPPORTED", "future version unsupported");
    need(prts::unity_code_registration_layout_profile(106) == "106-compatible", "v106 CodeRegistration not overclaimed as 106.1");
    need(prts::unity_code_registration_layout_profile(107) == "106-compatible", "v107 CodeRegistration normalized to source-compatible layout");
    need(prts::unity_code_registration_layout_profile(108) == "108", "v108 CodeRegistration label");
    auto enc=[](std::uint32_t raw,std::uint32_t source){return (raw<<29)|(source<<1);};
    {
        const std::uint32_t slots[]={enc(1,0),enc(2,1),enc(4,2),enc(5,3),enc(6,4)};
        need(prts::unity_validate_1061_always_init_encoded_slots(slots,5,5,5,5),"106.1 shifted usage kinds and source bounds");
    }
    {
        const std::uint32_t bad_kind[]={enc(7,0)};
        need(!prts::unity_validate_1061_always_init_encoded_slots(bad_kind,5,5,5,5),"106.1 removed-kind overflow rejected");
        const std::uint32_t bad_method[]={enc(2,5)};
        need(!prts::unity_validate_1061_always_init_encoded_slots(bad_method,5,5,5,5),"106.1 method source bound rejected");
        const std::uint32_t bad_string[]={enc(4,5)};
        need(!prts::unity_validate_1061_always_init_encoded_slots(bad_string,5,5,5,5),"106.1 string source bound rejected");
    }
    std::cout << "PASS\n";
    return 0;
}
