#include "prts/upx.hpp"
#include "prts/x86_semantic.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <set>
#include <string_view>
namespace prts { namespace {
bool contains(std::span<const std::uint8_t>d,std::string_view s){return std::search(d.begin(),d.end(),s.begin(),s.end())!=d.end();}
const PeSection* section_for_rva(const PeInfo&pe,std::uint32_t rva){for(const auto&s:pe.sections){auto n=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+n)return &s;}return nullptr;}
bool imported(const PeInfo&pe,std::string_view name){for(const auto&m:pe.imports)for(const auto&f:m.functions)if(f.name==name)return true;return false;}
struct UpxSemanticReference { const char* label; std::uint16_t machine; const std::uint64_t* hashes; std::size_t count; std::uint64_t digest; };
#include "../reference/upx_refs.inc"
void semantic_reference(std::span<const std::uint8_t>d,const PeInfo&pe,UpxInfo&u){
    if(!u.candidate||!pe.valid||(pe.machine!=0x8664&&pe.machine!=0x14c))return;
    auto cfg=build_x86_cfg(d,pe,pe.entry_rva);
    if(!cfg.valid){u.negative_evidence.push_back("semantic stub CFG decode failed: "+cfg.error);return;}
    u.semantic_cfg_valid=true;auto digest=semantic_cfg_digest(cfg);double best=-1.0;SemanticDiff bestdiff;const UpxSemanticReference* bestref=nullptr;
    for(const auto&r:kUpxSemanticReferences){if(r.machine!=pe.machine)continue;if(r.count==cfg.blocks.size()&&r.digest==digest){u.reference_state="REFERENCE_MATCH";u.reference_label=r.label;u.reference_similarity=1.0;u.reference_matched_blocks=u.reference_blocks=u.target_blocks=static_cast<std::uint32_t>(r.count);u.evidence.push_back(std::string("normalized unpack stub exactly matches official semantic reference ")+r.label);return;}std::vector<std::uint64_t> hs(r.hashes,r.hashes+r.count);auto diff=compare_semantic_cfg(cfg,hs);if(diff.block_similarity>best){best=diff.block_similarity;bestdiff=std::move(diff);bestref=&r;}}
    if(!bestref){u.reference_state="NO_REFERENCE";return;}u.reference_label=bestref->label;u.reference_similarity=best;u.reference_matched_blocks=bestdiff.matched_blocks;u.reference_blocks=bestdiff.reference_blocks;u.target_blocks=bestdiff.target_blocks;
    if(best>=0.70){u.reference_state="REFERENCE_DIFF";u.reference_changed_ranges=std::move(bestdiff.changed_ranges);std::ostringstream e;e<<"unpack stub is semantically close to "<<bestref->label<<" but differs in "<<u.reference_changed_ranges.size()<<" normalized target block(s), similarity="<<std::fixed<<std::setprecision(3)<<best;u.negative_evidence.push_back(e.str());if(best>=0.90){if(!u.confidence||*u.confidence<.95)u.confidence=.95;}}
    else{u.reference_state="NO_REFERENCE";std::ostringstream e;e<<"no embedded UPX semantic reference is close enough; best="<<bestref->label<<" similarity="<<std::fixed<<std::setprecision(3)<<best;u.negative_evidence.push_back(e.str());}
}
}
UpxInfo detect_upx(std::span<const std::uint8_t>d,const PeInfo&pe,const ElfInfo&elf){
    UpxInfo u;
    u.standard_marker=contains(d,"UPX!");
    int named=0;
    if(pe.valid)for(const auto&s:pe.sections)if(s.name.rfind("UPX",0)==0)++named;
    if(elf.valid)for(const auto&s:elf.sections)if(s.name.rfind("UPX",0)==0)++named;
    u.standard_sections=named>=2;
    if(pe.valid){
        const auto*ep=section_for_rva(pe,pe.entry_rva);
        if(ep&&ep->raw_size>=4096&&ep->entropy>=7.25&&(ep->characteristics&0x20000000)){
            u.ep_in_packed_section=true;
            u.evidence.push_back("entry point lies in a high-entropy executable packed-data section");
        }
        if(ep){
            for(const auto&s:pe.sections){
                if(s.raw_size!=0||s.vsize<16384||!(s.characteristics&0x20000000))continue;
                if(s.rva>=ep->rva)continue;
                const auto gap=std::int64_t(ep->rva)-std::int64_t(s.rva+s.vsize);
                if(gap>=-0x1000&&gap<=0x3000){u.empty_exec_before_packed=true;u.evidence.push_back("large raw-empty executable section immediately precedes packed entry section");break;}
            }
        }
        const bool vp=imported(pe,"VirtualProtect")||imported(pe,"VirtualProtectEx");
        const bool gp=imported(pe,"GetProcAddress");
        const bool ll=imported(pe,"LoadLibraryA")||imported(pe,"LoadLibraryW");
        std::size_t funcs=0;for(const auto&m:pe.imports)funcs+=m.functions.size();
        if(vp&&gp&&ll&&funcs<=64){u.resolver_imports=true;u.evidence.push_back("sparse import table contains classic unpacker resolver APIs (VirtualProtect/GetProcAddress/LoadLibrary)");}
        if(pe.sections.size()>=2&&pe.sections.size()<=6&&u.ep_in_packed_section&&u.empty_exec_before_packed){u.layout_match=true;u.evidence.push_back("compact PE section geometry matches UPX unpack-to-empty-section layout");}
        if(u.standard_marker){u.structural_score+=3;u.evidence.push_back("UPX! marker present");}else u.negative_evidence.push_back("UPX! marker absent");
        if(u.standard_sections){u.structural_score+=3;u.evidence.push_back("multiple UPX-named sections present");}else u.negative_evidence.push_back("UPX section names absent/renamed");
        if(u.layout_match)u.structural_score+=4;
        if(u.resolver_imports)u.structural_score+=2;
        if(u.ep_in_packed_section)u.structural_score+=2;
        if(u.empty_exec_before_packed)u.structural_score+=2;
        // Family markers are labels, never proof. A marker/name-only fake must not produce
        // a packer finding; independent loader/materialization structure is mandatory.
        const bool independent_structure=u.layout_match||(u.ep_in_packed_section&&u.empty_exec_before_packed)||(u.ep_in_packed_section&&u.resolver_imports);
        u.candidate=independent_structure&&u.structural_score>=8;
        if(u.candidate){
            if(u.standard_marker&&u.standard_sections&&u.layout_match){u.state="LIKELY";u.confidence=.98;}
            else if(u.structural_score>=10){u.state="LIKELY";u.confidence=.92;}
            else if(u.structural_score>=8){u.state="LIKELY";u.confidence=.84;}
            else {u.state="SUSPECTED";u.confidence=.70;}
        }
        semantic_reference(d,pe,u);
    }else if(elf.valid){
        const ElfSegment* epseg=nullptr;std::vector<const ElfSegment*> loads;
        for(const auto&s:elf.segments){if(s.type!=1)continue;loads.push_back(&s);if(elf.entry>=s.address&&elf.entry<s.address+s.memory_size&&(s.flags&1))epseg=&s;}
        u.elf_load_segments=static_cast<std::uint32_t>(loads.size());
        u.elf_sectionless=!elf.section_table_present||elf.section_header_count==0;
        if(epseg&&epseg->file_size>=4096&&epseg->entropy>=6.85){u.elf_entry_in_packed_segment=true;u.evidence.push_back("ELF entry point lies in a high-entropy executable PT_LOAD segment");u.structural_score+=3;}
        for(const auto*s:loads){if(!(s->flags&2)||s->memory_size<=s->file_size)continue;const auto gap=s->memory_size-s->file_size;if(gap>=0x2000&&s->memory_size>=s->file_size*2){u.elf_materialization_gap=true;u.elf_materialization_bytes=std::max(u.elf_materialization_bytes,gap);}}
        if(u.elf_materialization_gap){std::ostringstream e;e<<"writable PT_LOAD reserves 0x"<<std::hex<<u.elf_materialization_bytes<<std::dec<<" more memory than file bytes (materialization/BSS gap)";u.evidence.push_back(e.str());u.structural_score+=3;}
        u.elf_compact_load_geometry=loads.size()>=2&&loads.size()<=3;
        if(u.elf_compact_load_geometry){u.evidence.push_back("compact ELF loader geometry uses only "+std::to_string(loads.size())+" PT_LOAD segments");u.structural_score+=1;}
        for(std::size_t i=0;i<loads.size();++i)for(std::size_t j=i+1;j<loads.size();++j)if(loads[i]->file_size&&loads[j]->file_size&&loads[i]->offset==loads[j]->offset){u.elf_shared_file_mapping=true;break;}
        if(u.elf_shared_file_mapping){u.evidence.push_back("multiple PT_LOAD segments map from the same file offset, consistent with a compact self-loader image");u.structural_score+=2;}
        if(u.elf_sectionless){u.evidence.push_back("ELF section-header table is absent; loader-visible program headers remain valid");u.structural_score+=1;}
        u.elf_static_stub=elf.interpreter.empty();
        if(u.elf_static_stub){u.evidence.push_back("packed-image stub has no PT_INTERP and is self-contained at process entry");u.structural_score+=1;}
        if(u.standard_marker){u.evidence.push_back("UPX! marker present (family label only)");u.structural_score+=1;}else u.negative_evidence.push_back("UPX! marker absent/modified");
        if(u.standard_sections){u.evidence.push_back("UPX-named ELF sections present (family label only)");u.structural_score+=1;}else u.negative_evidence.push_back("UPX section names absent/renamed");
        const bool independent_structure=u.elf_entry_in_packed_segment&&u.elf_materialization_gap&&u.elf_compact_load_geometry&&(u.elf_shared_file_mapping||u.elf_sectionless);
        u.candidate=independent_structure&&u.structural_score>=8;
        if(u.candidate){
            if(u.standard_marker&&u.structural_score>=11){u.state="LIKELY";u.confidence=.96;}
            else if(u.elf_shared_file_mapping&&u.structural_score>=10){u.state="LIKELY";u.confidence=.88;}
            else {u.state="SUSPECTED";u.confidence=.78;}
        }
    }
    return u;
}
Finding upx_finding(const UpxInfo&i){Finding f;f.kind="packer";f.family="UPX-like";if(!i.candidate){f.state="FAILED";return f;}f.state=i.state;f.confidence=i.confidence;f.variant=i.elf_load_segments?(i.standard_marker?"structural-elf+standard-marker":"structural-elf+modified-marker"):((i.standard_marker&&i.standard_sections)?"standard-or-lightly-modified":"modified-candidate");f.evidence=i.evidence;f.negative_evidence=i.negative_evidence;f.fields["structural_score"]=std::to_string(i.structural_score);if(i.elf_load_segments){f.fields["elf_load_segments"]=std::to_string(i.elf_load_segments);f.fields["elf_materialization_bytes"]=std::to_string(i.elf_materialization_bytes);f.fields["elf_sectionless"]=i.elf_sectionless?"true":"false";f.fields["elf_shared_file_mapping"]=i.elf_shared_file_mapping?"true":"false";}if(i.semantic_cfg_valid){f.fields["stub_reference_state"]=i.reference_state;f.fields["stub_reference"]=i.reference_label;std::ostringstream x;x<<std::fixed<<std::setprecision(3)<<i.reference_similarity;f.fields["stub_similarity"]=x.str();f.fields["stub_blocks"]=std::to_string(i.target_blocks);f.fields["stub_reference_blocks"]=std::to_string(i.reference_blocks);f.fields["stub_matched_blocks"]=std::to_string(i.reference_matched_blocks);for(const auto&r:i.reference_changed_ranges)f.ranges.push_back(r);}f.suggested_actions={"unpack:generic-runtime"};if(i.reference_state=="REFERENCE_DIFF")f.suggested_actions.push_back("inspect semantic-diff RVA ranges before/after failed unpack stage");return f;}
}
