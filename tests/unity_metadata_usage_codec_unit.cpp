#include "unity_metadata_usage_codec.hpp"
#include "unity_rgctx_profile.hpp"
#include <cstdlib>
#include <iostream>
#include <string>

namespace {
void need(bool value,const char*message){if(!value){std::cerr<<"FAIL: "<<message<<'\n';std::exit(1);}}
std::uint32_t token(std::uint32_t raw,std::uint32_t source,bool low=true){return (raw<<29)|(source<<1)|(low?1u:0u);}
}

int main(){
    using K=prts::UnityMetadataUsageKindProfile;
    using I=prts::UnityMetadataUsageIndexProfile;
    need(prts::unity_metadata_usage_kind_profile(106,"106")==K::Traditional,"declared 106 normalized 106 selects traditional");
    need(prts::unity_metadata_usage_kind_profile(106,"106.1")==K::Compact,"declared 106 normalized 106.1 selects compact");
    need(prts::unity_metadata_usage_kind_profile(107,"106")==K::Traditional,"declared 107 backport selects traditional");
    need(prts::unity_metadata_usage_kind_profile(107,"106.1")==K::Compact,"declared 107 Unity 6.6 selects compact");
    need(prts::unity_metadata_usage_kind_profile(108,"108")==K::Compact,"v108 selects compact");
    need(!prts::unity_metadata_usage_kind_profile(106,"106|106.1"),"ambiguous transitional profile has no codec");
    need(prts::unity_metadata_usage_runtime_kind_compare_limit(K::Traditional)==6&&prts::unity_metadata_usage_runtime_kind_compare_limit(K::Compact)==5,"runtime kind compare limits");
    auto em_traditional=prts::decode_unity_encoded_method(token(3,17),K::Traditional);
    need(em_traditional.valid&&!em_traditional.invalid_usage&&em_traditional.kind==3&&em_traditional.source_index==17,"traditional encoded MethodDef");
    auto em_compact_def=prts::decode_unity_encoded_method(token(2,17),K::Compact);
    need(em_compact_def.valid&&em_compact_def.kind==3&&em_compact_def.source_index==17,"compact encoded MethodDef");
    auto em_compact_ref=prts::decode_unity_encoded_method(token(5,23),K::Compact);
    need(em_compact_ref.valid&&em_compact_ref.kind==6&&em_compact_ref.source_index==23,"compact encoded MethodRef");
    auto em_invalid=prts::decode_unity_encoded_method(7,K::Compact);
    need(em_invalid.valid&&em_invalid.invalid_usage&&em_invalid.kind==0&&em_invalid.source_index==3,"encoded invalid entrypoint sentinel");
    auto em_bad_invalid=prts::decode_unity_encoded_method((5u<<1)|1u,K::Compact);
    need(!em_bad_invalid.valid&&em_bad_invalid.invalid_usage,"unknown encoded invalid sentinel rejected");
    need(std::string(prts::unity_encoded_method_invalid_name(0))=="NO_DATA"&&std::string(prts::unity_encoded_method_invalid_name(3))=="ENTRY_POINT_NOT_FOUND"&&!prts::unity_encoded_method_invalid_name(5)[0],"encoded invalid sentinel names");
    auto em_even=prts::decode_unity_encoded_method((2u<<29)|(17u<<1),K::Compact);
    need(em_even.valid&&!em_even.low_bit_set&&em_even.source_index==17,"encoded-method decoder mirrors runtime mask without low-bit gate");
    auto em_wrong_kind=prts::decode_unity_encoded_method(token(3,4),K::Compact);
    need(!em_wrong_kind.valid&&em_wrong_kind.kind==4,"compact non-method usage rejected as EncodedMethodIndex");
    using R=prts::UnityModuleRgctxProfile;
    need(prts::unity_module_rgctx_profile(24,"")==R::LegacyIndex8&&prts::unity_module_rgctx_record_size(R::LegacyIndex8)==8,"legacy RGCTX profile");
    need(prts::unity_module_rgctx_profile(106,"106")==R::TraditionalHandle16&&prts::unity_module_rgctx_record_size(R::TraditionalHandle16)==16,"traditional v106 RGCTX profile");
    need(prts::unity_module_rgctx_profile(106,"106.1")==R::CompactInline8&&prts::unity_module_rgctx_record_size(R::CompactInline8)==8,"106.1 compact inline RGCTX profile");
    need(prts::unity_module_rgctx_profile(107,"106")==R::TraditionalHandle16&&prts::unity_module_rgctx_profile(107,"106.1")==R::CompactInline8,"declared v107 RGCTX normalization");
    need(!prts::unity_module_rgctx_profile(106,"106|106.1")&&!prts::unity_module_rgctx_profile(108,"108"),"ambiguous/v108 do not select per-module RGCTX profile");
    need(std::string(prts::unity_module_rgctx_kind_name(R::CompactInline8,5))=="CONSTRAINED_CALL_TYPE"&&std::string(prts::unity_module_rgctx_kind_name(R::CompactInline8,6))=="CONSTRAINED_CALL_METHOD","106.1 constrained RGCTX pair kinds");
    need(!prts::unity_module_rgctx_kind_name(R::CompactInline8,4)[0],"106.1 ARRAY kind remains fail-closed because matching runtime switch does not handle it");
    auto traditional=prts::decode_unity_metadata_usage(token(2,17),K::Traditional,I::RuntimeToken);
    need(traditional.valid&&traditional.raw_kind==2&&traditional.kind==2&&traditional.source_index==17&&traditional.low_bit_set,"traditional runtime token");
    auto compact=prts::decode_unity_metadata_usage(token(2,17),K::Compact,I::RuntimeToken);
    need(compact.valid&&compact.raw_kind==2&&compact.kind==3&&compact.source_index==17,"compact removes old kind 2");
    auto field_rva=prts::decode_unity_metadata_usage(token(6,3),K::Compact,I::RuntimeToken);
    need(field_rva.valid&&field_rva.kind==7&&field_rva.source_index==3,"compact FieldRva mapping");
    auto removed_overflow=prts::decode_unity_metadata_usage(token(7,0),K::Compact,I::RuntimeToken);
    need(!removed_overflow.valid,"compact raw kind 7 rejected");
    auto initialized=prts::decode_unity_metadata_usage(token(1,2,false),K::Compact,I::RuntimeToken);
    need(!initialized.valid&&!initialized.low_bit_set,"runtime slot requires encoded-token low bit");
    auto direct=prts::decode_unity_metadata_usage((3u<<29)|19u,K::Traditional,I::Direct);
    need(direct.valid&&direct.kind==3&&direct.source_index==19,"legacy direct source index");
    need(std::string(prts::unity_metadata_usage_kind_name(1))=="TYPE_INFO"&&std::string(prts::unity_metadata_usage_kind_name(7))=="FIELD_RVA"&&!prts::unity_metadata_usage_kind_name(0)[0],"kind names");
    std::cout<<"PASS\n";
    return 0;
}
