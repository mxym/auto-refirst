#include "unity_metadata_usage_codec.hpp"
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
