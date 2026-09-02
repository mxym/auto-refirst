#include "prts/android.hpp"
#include "prts/elf.hpp"
#include "prts/hermes.hpp"
#include "prts/jvm.hpp"
#include "prts/lua.hpp"
#include "prts/pe.hpp"
#include "prts/wasm.hpp"
#include "unity_engine_version.hpp"
#include "unity_generic_class_profile.hpp"
#include "unity_metadata_usage_codec.hpp"
#include "unity_method_dispatch_profile.hpp"
#include "unity_rgctx_profile.hpp"
#include "unity_registration_profile.hpp"
#include <array>
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
    put64(image,unity_raw(pe,tail),1);put64(image,unity_raw(pe,tail)+8,table);put64(image,unity_raw(pe,table),slot);put64(image,unity_raw(pe,slot),(1u<<29)|1u);
    auto strong=prts::probe_unity_metadata_registration_tail(image,pe,tail,4);
    if(strong.evidence!=prts::UnityMetadataRegistrationTailEvidence::StrongExtended)return false;
    put64(image,unity_raw(pe,slot),std::uint64_t(1)<<40);
    auto malformed=prts::probe_unity_metadata_registration_tail(image,pe,tail,4);
    if(malformed.evidence!=prts::UnityMetadataRegistrationTailEvidence::Unresolved)return false;
    const auto edge=pe.image_base+0x1ff8;
    auto truncated=prts::probe_unity_metadata_registration_tail(image,pe,edge,4);
    if(truncated.evidence!=prts::UnityMetadataRegistrationTailEvidence::NotFileBacked)return false;
    prts::UnityEngineVersionValue old_branch{6000,5,0,6,'a'},new_branch{6000,6,0,6,'a'};
    const auto old_hint=prts::unity_metadata_registration_engine_hint(106,old_branch);
    const auto new_hint=prts::unity_metadata_registration_engine_hint(106,new_branch);
    if(old_hint!=prts::UnityMetadataRegistrationEngineHint::Traditional106||new_hint!=prts::UnityMetadataRegistrationEngineHint::Extended1061)return false;
    const auto old_decision=prts::decide_unity_metadata_registration_profile(106,prts::UnityMetadataRegistrationTailEvidence::Unresolved,old_hint);
    const auto conflict_decision=prts::decide_unity_metadata_registration_profile(106,prts::UnityMetadataRegistrationTailEvidence::StrongExtended,old_hint);
    const auto new_decision=prts::decide_unity_metadata_registration_profile(106,prts::UnityMetadataRegistrationTailEvidence::Unresolved,new_hint);
    const auto compact_method=prts::decode_unity_encoded_method((2u<<29)|(17u<<1)|1u,prts::UnityMetadataUsageKindProfile::Compact);
    const auto invalid_method=prts::decode_unity_encoded_method(7u,prts::UnityMetadataUsageKindProfile::Compact);
    const auto bad_invalid_method=prts::decode_unity_encoded_method(11u,prts::UnityMetadataUsageKindProfile::Compact);
    const auto rgctx_profile=prts::unity_module_rgctx_profile(106,"106.1");
    const auto gclass_old=prts::unity_generic_class_layout_profile(106,"106");
    const auto gclass_new=prts::unity_generic_class_layout_profile(106,"106.1");
    const auto gclass_v108=prts::unity_generic_class_layout_profile(108,"108");
    const auto gclass_ambiguous=prts::unity_generic_class_layout_profile(106,"106|106.1");
    const std::array<std::uint32_t,2> dispatch_tokens{0x06000001u,0x06000002u};
    const std::array<std::int32_t,2> dispatch_invokers{0,-1};
    const std::array<std::uint32_t,1> dispatch_adjustors{0x06000002u};
    const auto dispatch_contract=prts::validate_unity_pre108_method_dispatch_tables(106,"106.1",dispatch_tokens,2,dispatch_invokers,1,dispatch_adjustors);
    return old_decision.state=="RESOLVED"&&old_decision.normalized_variant=="106"&&!old_decision.include_always_init&&
           conflict_decision.state=="CONFLICT"&&!conflict_decision.include_always_init&&
           new_decision.state=="INVALID"&&new_decision.normalized_variant=="106|106.1"&&!new_decision.include_always_init&&
           compact_method.valid&&!compact_method.invalid_usage&&compact_method.kind==3&&compact_method.source_index==17&&
           invalid_method.valid&&invalid_method.invalid_usage&&invalid_method.source_index==3&&
           !bad_invalid_method.valid&&bad_invalid_method.invalid_usage&&
           rgctx_profile&&*rgctx_profile==prts::UnityModuleRgctxProfile::CompactInline8&&
           prts::unity_module_rgctx_record_size(*rgctx_profile)==8&&
           prts::unity_module_rgctx_kind_name(*rgctx_profile,5)[0]!=0&&
           prts::unity_module_rgctx_kind_name(*rgctx_profile,4)[0]==0&&
           gclass_old&&*gclass_old==prts::UnityGenericClassLayoutProfile::Context32&&
           prts::unity_generic_class_record_size(*gclass_old)==32&&prts::unity_generic_class_cached_class_offset(*gclass_old)==24&&prts::unity_generic_class_has_method_inst(*gclass_old)&&
           gclass_new&&*gclass_new==prts::UnityGenericClassLayoutProfile::Compact24&&
           prts::unity_generic_class_record_size(*gclass_new)==24&&prts::unity_generic_class_cached_class_offset(*gclass_new)==16&&!prts::unity_generic_class_has_method_inst(*gclass_new)&&
           gclass_v108&&*gclass_v108==prts::UnityGenericClassLayoutProfile::Compact24&&!gclass_ambiguous&&
           dispatch_contract.valid&&dispatch_contract.invoker_resolved==1&&dispatch_contract.invoker_missing==1;
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
    (void)prts::probe_unity_metadata_registration_tail(bytes,probe_pe,probe_pe.image_base+0x1000,16);
    (void)prts::probe_unity_globalgamemanagers(bytes,bytes.size());
    (void)prts::probe_unityfs(bytes,bytes.size());
    // Consume results so an optimizing sanitizer build cannot discard parser calls.
    const unsigned observed = unsigned(pe.valid) + unsigned(elf.valid) + unsigned(wasm.valid) +
                              unsigned(hermes.valid) + unsigned(jvm.valid) + unsigned(dex.valid) +
                              unsigned(lua.valid);
    return observed > 7 ? 3 : 0;
}
