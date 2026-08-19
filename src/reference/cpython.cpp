#include "prts/cpython.hpp"
#include "prts/sha256.hpp"
#include "prts/x86_semantic.hpp"
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iterator>
#include <cmath>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace prts { namespace {
struct CPythonReference {
    const char* version;
    std::uint32_t version_hex;
    std::uint16_t machine;
    std::uint64_t size;
    const char* sha256;
    const char* sections; // name,vsize,raw;...
    const char* exports;  // newline separated
};
#include "cpython_refs.inc"
struct CPythonPycMagicReference { std::uint32_t version_hex; const char* version; std::array<std::uint8_t,4> magic; };
#include "cpython_pyc_magic.inc"
struct CPythonSemanticReference {
    std::uint32_t version_hex;
    std::uint16_t machine;
    const char* name;
    const std::uint64_t* hashes;
    std::size_t count;
    std::uint64_t digest;
};
#include "cpython_semantic_refs.inc"
struct CPythonTextReference {
    std::uint32_t version_hex;
    std::uint16_t machine;
    const char* version;
    std::uint32_t text_rva,text_virtual,text_raw,text_meaningful;
    const std::uint64_t* hashes;
    std::size_t count;
};
#include "cpython_text_refs.inc"

std::optional<std::size_t> rva_off(const PeInfo&pe,std::uint32_t rva,std::size_t size){
    if(rva<pe.headers_size&&rva<size)return std::size_t(rva);
    for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&std::uint64_t(rva)<std::uint64_t(s.rva)+span){auto delta=std::uint64_t(rva)-s.rva;if(delta>=s.raw_size)return{};auto o=std::uint64_t(s.raw_offset)+delta;if(o<size)return std::size_t(o);}}
    return{};
}
std::uint32_t u32le(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);}
std::string version_string(std::uint32_t v){if(!v)return{};return std::to_string(v>>24)+"."+std::to_string((v>>16)&255)+"."+std::to_string((v>>8)&255);}
std::set<std::string> split_lines(const char*s){std::set<std::string>r;std::istringstream in(s?s:"");std::string x;while(std::getline(in,x))if(!x.empty())r.insert(x);return r;}
struct RS{std::uint64_t v=0,r=0;};
std::map<std::string,RS> parse_sections(const char*s){std::map<std::string,RS>r;std::istringstream all(s?s:"");std::string item;while(std::getline(all,item,';')){auto a=item.find(','),b=a==std::string::npos?a:item.find(',',a+1);if(a==std::string::npos||b==std::string::npos)continue;try{r[item.substr(0,a)]={std::stoull(item.substr(a+1,b-a-1)),std::stoull(item.substr(b+1))};}catch(...){} }return r;}
const CPythonReference* find_ref(std::uint32_t v,std::uint16_t machine){for(const auto&r:kCPythonReferences)if(r.version_hex==v&&r.machine==machine)return&r;return nullptr;}
std::uint32_t fallback_version(std::span<const std::uint8_t>d){
    // Exact standalone numeric versions such as "3.13.1\0". Prefer the first plausible 3.x version.
    for(std::size_t i=0;i+5<d.size();++i){if(d[i]!='3'||d[i+1]!='.')continue;std::size_t p=i+2;unsigned minor=0,digs=0;while(p<d.size()&&d[p]>='0'&&d[p]<='9'&&digs<3){minor=minor*10+d[p++]-'0';++digs;}if(!digs||p>=d.size()||d[p++]!='.')continue;unsigned micro=0;digs=0;while(p<d.size()&&d[p]>='0'&&d[p]<='9'&&digs<3){micro=micro*10+d[p++]-'0';++digs;}if(!digs||minor>30||micro>255)continue;if(p<d.size()&&(d[p]==0||d[p]==' '||d[p]=='\r'||d[p]=='\n'))return (3u<<24)|(minor<<16)|(micro<<8)|0xf0u;}
    return 0;
}
const PeExport* find_export(const PeInfo&pe,std::string_view name){auto it=std::find_if(pe.exports.begin(),pe.exports.end(),[&](const PeExport&e){return e.name==name;});return it==pe.exports.end()?nullptr:&*it;}
std::uint64_t fnv64(std::span<const std::uint8_t>b){std::uint64_t h=1469598103934665603ull;for(auto x:b){h^=x;h*=1099511628211ull;}return h;}
const CPythonTextReference* find_text_ref(std::uint32_t v,std::uint16_t machine){for(const auto&r:kCPythonTextReferences)if(r.version_hex==v&&r.machine==machine)return &r;return nullptr;}
void push_region(std::vector<CPythonRegionDiff>&v,std::string kind,std::string sec,std::uint32_t rva,std::uint64_t size,std::string detail){if(!size)return;if(!v.empty()){auto&b=v.back();if(b.kind==kind&&b.section==sec&&std::uint64_t(b.rva)+b.size==rva){b.size+=size;return;}}v.push_back({std::move(kind),std::move(sec),rva,size,std::move(detail)});}
void compare_text_regions(std::span<const std::uint8_t>d,const PeInfo&pe,const CPythonReference&struct_ref,CPythonInfo&out){
    if(out.semantic_reference_status=="REFERENCE_MATCH"){out.text_reference_status="MATCH";out.text_chunk_match_ratio=1.0;return;}
    if(out.semantic_reference_status!="COMPARABLE"){out.text_reference_status=out.semantic_reference_status=="BUILD_INCOMPARABLE"?"SKIPPED_INCOMPARABLE":"NO_REFERENCE";return;}
    auto tr=find_text_ref(out.version_hex,pe.machine);if(!tr){out.text_reference_status="NO_REFERENCE";return;}
    auto it=std::find_if(pe.sections.begin(),pe.sections.end(),[](const PeSection&s){return s.name==".text";});if(it==pe.sections.end()){out.text_reference_status="DIFF";out.region_diffs.push_back({"MISSING_TEXT",".text",0,tr->text_meaningful,"target .text section missing"});return;}
    auto meaningful=std::min<std::uint64_t>(it->vsize,it->raw_size);out.text_chunks_reference=static_cast<std::uint32_t>(tr->count);out.text_chunks_target=static_cast<std::uint32_t>((meaningful+kCPythonTextBlockSize-1)/kCPythonTextBlockSize);std::size_t compared=0;
    for(std::size_t i=0;i<tr->count;i++){auto rel=std::uint64_t(i)*kCPythonTextBlockSize;auto ref_len=std::min<std::uint64_t>(kCPythonTextBlockSize,tr->text_meaningful>rel?tr->text_meaningful-rel:0);if(!ref_len)break;if(rel>=meaningful){push_region(out.region_diffs,"MISSING_OFFICIAL_TEXT",".text",it->rva+static_cast<std::uint32_t>(rel),ref_len,"reference .text bytes absent from target");continue;}auto len=std::min<std::uint64_t>(ref_len,meaningful-rel);auto off=std::uint64_t(it->raw_offset)+rel;if(off+len>d.size()){push_region(out.region_diffs,"MISSING_OFFICIAL_TEXT",".text",it->rva+static_cast<std::uint32_t>(rel),len,"target .text raw bytes unavailable");continue;}++compared;auto h=fnv64(d.subspan(static_cast<std::size_t>(off),static_cast<std::size_t>(len)));if(len==ref_len&&h==tr->hashes[i])++out.text_chunks_matched;else push_region(out.region_diffs,"PATCHED_TEXT_CHUNK",".text",it->rva+static_cast<std::uint32_t>(rel),len,"same-relative .text chunk differs from official reference");}
    out.text_chunk_match_ratio=tr->count?double(out.text_chunks_matched)/double(tr->count):0.0;
    if(meaningful>tr->text_meaningful)push_region(out.region_diffs,"NEW_EXECUTABLE_TAIL",".text",it->rva+tr->text_meaningful,meaningful-tr->text_meaningful,"target .text extends beyond official reference");
    auto refsecs=parse_sections(struct_ref.sections);for(const auto&s:pe.sections){if(!(s.characteristics&0x20000000)||s.name==".text")continue;if(!refsecs.count(s.name)){auto sz=std::max<std::uint32_t>(s.vsize,s.raw_size);out.region_diffs.push_back({"NEW_EXECUTABLE_SECTION",s.name,s.rva,sz,"executable section is absent from official reference"});}}
    out.text_reference_status=out.region_diffs.empty()?"MATCH":"DIFF";
    std::vector<RangeRef> new_ranges;for(const auto&r:out.region_diffs)if(r.kind=="NEW_EXECUTABLE_TAIL"||r.kind=="NEW_EXECUTABLE_SECTION")new_ranges.push_back({r.rva,r.size,r.kind});
    if(!new_ranges.empty()){auto refs=find_direct_control_refs(d,pe,new_ranges,256);for(const auto&x:refs)out.new_region_xrefs.push_back({x.source_rva,x.target_rva,x.size,x.kind});}
    std::ostringstream e;e<<"CPython .text reference chunks matched "<<out.text_chunks_matched<<"/"<<out.text_chunks_reference<<" ("<<std::fixed<<std::setprecision(3)<<out.text_chunk_match_ratio<<")";out.evidence.push_back(e.str());
    if(!out.new_region_xrefs.empty())out.evidence.push_back(std::to_string(out.new_region_xrefs.size())+" direct control-flow reference(s) enter newly added executable region(s)");
}
void semantic_compare(std::span<const std::uint8_t>d,const PeInfo&pe,CPythonInfo&out){
    static constexpr std::string_view shallow_names[]={"PyMarshal_ReadObjectFromString","Py_CompileStringExFlags","PyObject_Call","PyImport_ImportModule","Py_Initialize"};
    std::vector<double> shallow_scores;
    std::vector<CPythonFunctionDiff> shallow_probes;
    bool have_ref=false;
    for(const auto&r:kCPythonSemanticReferences){
        if(r.version_hex!=out.version_hex||r.machine!=pe.machine)continue;
        have_ref=true;
        if(std::find(std::begin(shallow_names),std::end(shallow_names),std::string_view(r.name))==std::end(shallow_names))continue;
        auto ex=find_export(pe,r.name);if(!ex)continue;
        auto cfg=build_x86_cfg(d,pe,ex->rva,0x3000,8);if(!cfg.valid||cfg.blocks.empty())continue;
        std::set<std::uint64_t> ref_hashes(r.hashes,r.hashes+r.count);std::uint32_t matched=0;for(const auto&b:cfg.blocks)matched+=ref_hashes.count(b.hash)?1:0;
        CPythonFunctionDiff fd;fd.name=r.name;fd.target_rva=ex->rva;fd.reference_blocks=static_cast<std::uint32_t>(r.count);fd.target_blocks=static_cast<std::uint32_t>(cfg.blocks.size());fd.matched_blocks=matched;fd.reference_coverage=double(matched)/double(cfg.blocks.size());fd.state="SHALLOW_PROBE";
        shallow_scores.push_back(fd.reference_coverage);shallow_probes.push_back(std::move(fd));
    }
    if(!have_ref){out.semantic_reference_status="NO_SEMANTIC_REFERENCE";return;}
    if(shallow_scores.size()>=3){
        auto sorted=shallow_scores;std::sort(sorted.begin(),sorted.end());auto n=sorted.size();auto median=n%2?sorted[n/2]:(sorted[n/2-1]+sorted[n/2])/2.0;
        if(median<0.50){
            out.semantic_reference_status="BUILD_INCOMPARABLE";out.semantic_probe_count=static_cast<std::uint32_t>(shallow_scores.size());out.semantic_probe_median=median;
            for(auto&fd:shallow_probes){fd.state="INCOMPARABLE_SHALLOW_PROBE";out.function_diffs.push_back(std::move(fd));}
            std::ostringstream e;e<<"CPython shallow comparability gate median official-block coverage="<<std::fixed<<std::setprecision(3)<<median<<" across "<<shallow_scores.size()<<" probe(s): BUILD_INCOMPARABLE; deep semantic probes skipped";out.evidence.push_back(e.str());
            return;
        }
    }

    std::vector<double> coverages;
    std::vector<CPythonFunctionDiff> probes;
    for(const auto&r:kCPythonSemanticReferences){
        if(r.version_hex!=out.version_hex||r.machine!=pe.machine)continue;
        auto ex=find_export(pe,r.name);if(!ex)continue;
        auto cfg=build_x86_cfg(d,pe,ex->rva,0x3000,256);if(!cfg.valid)continue;
        CPythonFunctionDiff fd;fd.name=r.name;fd.target_rva=ex->rva;fd.reference_blocks=static_cast<std::uint32_t>(r.count);fd.target_blocks=static_cast<std::uint32_t>(cfg.blocks.size());
        auto digest=semantic_cfg_digest(cfg);
        if(r.count==cfg.blocks.size()&&digest==r.digest){fd.matched_blocks=fd.reference_blocks;fd.reference_coverage=1.0;fd.state="REFERENCE_MATCH";}
        else{std::vector<std::uint64_t> hs(r.hashes,r.hashes+r.count);auto diff=compare_semantic_cfg(cfg,hs);fd.matched_blocks=diff.matched_blocks;fd.reference_coverage=r.count?double(diff.matched_blocks)/double(r.count):0.0;fd.changed_ranges=std::move(diff.changed_ranges);fd.state="DIFF_PROBE";}
        coverages.push_back(fd.reference_coverage);probes.push_back(std::move(fd));
    }
    out.semantic_probe_count=static_cast<std::uint32_t>(coverages.size());if(coverages.empty()){out.semantic_reference_status="NO_USABLE_PROBES";return;}
    std::sort(coverages.begin(),coverages.end());auto n=coverages.size();out.semantic_probe_median=n%2?coverages[n/2]:(coverages[n/2-1]+coverages[n/2])/2.0;
    const bool comparable=coverages.size()>=5&&out.semantic_probe_median>=0.75;
    out.semantic_reference_status=comparable?"COMPARABLE":"BUILD_INCOMPARABLE";
    for(auto&fd:probes){if(comparable){if(fd.state!="REFERENCE_MATCH")fd.state="MODIFIED_CANDIDATE";}else{fd.state=fd.state=="REFERENCE_MATCH"?"REFERENCE_MATCH":"INCOMPARABLE_PROBE";fd.changed_ranges.clear();}out.function_diffs.push_back(std::move(fd));}
    std::ostringstream e;e<<"CPython deep semantic probe median official-reference coverage="<<std::fixed<<std::setprecision(3)<<out.semantic_probe_median<<" across "<<out.semantic_probe_count<<" function(s): "<<out.semantic_reference_status;out.evidence.push_back(e.str());
}
}

CPythonInfo detect_cpython(std::span<const std::uint8_t>d,const PeInfo&pe,const std::string&source){
    CPythonInfo out;out.source=source;if(!pe.valid)return out;
    std::set<std::string> ex;
    for(const auto&e:pe.exports)if(!e.name.empty())ex.insert(e.name);
    static constexpr const char* strong[]={"Py_GetVersion","Py_Version","Py_Initialize","PyObject_Call","PyImport_ImportModule","PyMarshal_ReadObjectFromString","PyUnicode_FromString","PyLong_FromLong","PyErr_Occurred"};
    for(auto n:strong)if(ex.count(n))++out.api_export_hits;
    const std::size_t py_names=std::count_if(ex.begin(),ex.end(),[](const std::string&n){return n.rfind("Py",0)==0||n.rfind("_Py",0)==0;});
    if(out.api_export_hits<5||py_names<100)return out;
    out.valid=true;out.named_export_count=static_cast<std::uint32_t>(ex.size());out.file_size=d.size();out.sha256=sha256_bytes(d);
    auto vit=std::find_if(pe.exports.begin(),pe.exports.end(),[](const PeExport&e){return e.name=="Py_Version";});
    if(vit!=pe.exports.end()){if(auto o=rva_off(pe,vit->rva,d.size()))out.version_hex=u32le(d,*o);}
    if(!out.version_hex)out.version_hex=fallback_version(d);
    out.version=version_string(out.version_hex);
    out.evidence.push_back(std::to_string(out.api_export_hits)+" core CPython API exports matched");
    out.evidence.push_back(std::to_string(py_names)+" Py*/_Py* named exports");
    if(out.version_hex)out.evidence.push_back("runtime version resolved as "+out.version+(vit!=pe.exports.end()?" via exported Py_Version":" via embedded version string"));

    const auto*ref=find_ref(out.version_hex,pe.machine);
    if(!ref){out.reference_status="NO_EXACT_REFERENCE";out.dispatch=analyze_cpython_dispatch(d,pe,out.version_hex,false);return out;}
    out.exact_reference_available=true;out.reference_version=ref->version;out.reference_sha256=ref->sha256;out.reference_size=ref->size;
    if(out.sha256==ref->sha256){out.reference_status="REFERENCE_MATCH";out.semantic_reference_status="REFERENCE_MATCH";out.semantic_probe_median=1.0;out.text_reference_status="MATCH";out.text_chunk_match_ratio=1.0;out.evidence.push_back("full DLL SHA-256 matches official reference");out.dispatch=analyze_cpython_dispatch(d,pe,out.version_hex,true,true);return out;}
    out.reference_status="DIFFERS_FROM_OFFICIAL_REFERENCE";
    auto rs=parse_sections(ref->sections);std::set<std::string>all;
    for(const auto&s:pe.sections)all.insert(s.name);for(const auto&kv:rs)all.insert(kv.first);
    for(const auto&name:all){CPythonSectionDiff x;x.name=name;auto ti=std::find_if(pe.sections.begin(),pe.sections.end(),[&](const PeSection&s){return s.name==name;});if(ti!=pe.sections.end()){x.target_virtual=ti->vsize;x.target_raw=ti->raw_size;}auto ri=rs.find(name);if(ri!=rs.end()){x.reference_virtual=ri->second.v;x.reference_raw=ri->second.r;}x.virtual_delta=static_cast<std::int64_t>(x.target_virtual)-static_cast<std::int64_t>(x.reference_virtual);x.raw_delta=static_cast<std::int64_t>(x.target_raw)-static_cast<std::int64_t>(x.reference_raw);if(x.virtual_delta||x.raw_delta)out.section_diffs.push_back(x);}
    auto rex=split_lines(ref->exports);std::set_difference(ex.begin(),ex.end(),rex.begin(),rex.end(),std::back_inserter(out.added_exports));std::set_difference(rex.begin(),rex.end(),ex.begin(),ex.end(),std::back_inserter(out.missing_exports));
    out.evidence.push_back("same-version official reference exists but full DLL hash differs");
    semantic_compare(d,pe,out);
    compare_text_regions(d,pe,*ref,out);
    out.dispatch=analyze_cpython_dispatch(d,pe,out.version_hex,out.semantic_reference_status=="COMPARABLE"||out.semantic_reference_status=="REFERENCE_MATCH");
    return out;
}

std::optional<std::array<std::uint8_t,4>> cpython_official_pyc_magic(std::uint32_t version_hex){for(const auto&r:kCPythonPycMagicReferences)if(r.version_hex==version_hex)return r.magic;return std::nullopt;}
std::optional<CPythonOpcodeNormalizationMap> cpython_validated_opcode_map(const CPythonInfo&i){
    CPythonOpcodeNormalizationMap out;out.target_to_official.fill(-1);
    if(i.dispatch.table_found&&(i.dispatch.reference_status=="REFERENCE_MATCH"||i.dispatch.reference_status=="OPCODE_PERMUTATION")){
        if(i.dispatch.reference_status=="REFERENCE_MATCH"){
            for(std::uint32_t z=0;z<i.dispatch.table_entry_count;++z){auto op=std::uint32_t(i.dispatch.table_first_opcode)+z;if(op<256){out.target_to_official[op]=static_cast<std::int16_t>(op);++out.mapped_opcodes;}}
        }else{
            for(const auto&m:i.dispatch.mappings){int r=-1;if(m.state=="SLOT_MATCH"||m.state=="SEMANTIC_SLOT_MATCH")r=m.target_opcode;else if((m.state=="PERMUTED"||m.state=="SEMANTIC_PERMUTED")&&m.reference_opcodes.size()==1)r=m.reference_opcodes.front();if(m.target_opcode<256&&r>=0&&r<256&&out.target_to_official[m.target_opcode]<0){out.target_to_official[m.target_opcode]=static_cast<std::int16_t>(r);++out.mapped_opcodes;}}
        }
        if(out.mapped_opcodes){out.source="dispatch";return out;}
    }
    if(i.compiler_probe.success&&(i.compiler_probe.state=="REFERENCE_MATCH"||i.compiler_probe.state=="OPCODE_PERMUTATION_RECOVERED")){
        for(const auto&m:i.compiler_probe.mappings)if(m.target_opcode<256&&m.reference_opcode<256&&out.target_to_official[m.target_opcode]<0){out.target_to_official[m.target_opcode]=static_cast<std::int16_t>(m.reference_opcode);++out.mapped_opcodes;}
        if(out.mapped_opcodes){out.source="compiler_probe";return out;}
    }
    return std::nullopt;
}

Finding cpython_finding(const CPythonInfo&i){
    Finding f;f.kind="runtime";f.family="CPython-derived";
    const bool embedded_artifact=i.source.rfind("CArchive:",0)==0;
    const auto cp_basis=embedded_artifact?CoordinateBasis::ARTIFACT_IMAGE:CoordinateBasis::CURRENT_INPUT_IMAGE;
    const auto cp_identity=embedded_artifact?i.source:std::string{};
    if(!i.valid){f.state="FAILED";return f;}
    f.state="CONFIRMED";f.confidence.reset();f.variant=i.version;f.evidence=i.evidence;
    f.fields["version"]=i.version;f.fields["version_hex"]=std::to_string(i.version_hex);f.fields["reference_status"]=i.reference_status;f.fields["semantic_reference_status"]=i.semantic_reference_status;
    if(i.semantic_probe_count){std::ostringstream x;x<<std::fixed<<std::setprecision(3)<<i.semantic_probe_median;f.fields["semantic_probe_median"]=x.str();f.fields["semantic_probe_count"]=std::to_string(i.semantic_probe_count);}
    f.fields["export_count"]=std::to_string(i.named_export_count);
    std::size_t mods=0;
    for(const auto&fd:i.function_diffs){if(fd.state!="MODIFIED_CANDIDATE")continue;++mods;std::ostringstream e;e<<fd.name<<" semantic reference coverage="<<std::fixed<<std::setprecision(3)<<fd.reference_coverage<<" ("<<fd.matched_blocks<<"/"<<fd.reference_blocks<<" reference blocks)";f.negative_evidence.push_back(e.str());for(const auto&r:fd.changed_ranges)f.ranges.push_back(rva_range(r.offset,r.size,fd.name+": "+r.label,cp_basis,cp_identity));}
    f.fields["modified_function_candidates"]=std::to_string(mods);f.fields["text_reference_status"]=i.text_reference_status;
    if(i.text_chunks_reference){std::ostringstream tr;tr<<std::fixed<<std::setprecision(3)<<i.text_chunk_match_ratio;f.fields["text_chunk_match_ratio"]=tr.str();f.fields["text_chunks_matched"]=std::to_string(i.text_chunks_matched);f.fields["text_chunks_reference"]=std::to_string(i.text_chunks_reference);}
    for(const auto&r:i.region_diffs){f.ranges.push_back(rva_range(r.rva,r.size,r.kind+" "+r.section+": "+r.detail,cp_basis,cp_identity));if(r.kind=="NEW_EXECUTABLE_TAIL"||r.kind=="NEW_EXECUTABLE_SECTION"){std::ostringstream x;x<<r.kind<<" "<<r.section<<" RVA=0x"<<std::hex<<r.rva<<std::dec<<" size="<<r.size;f.negative_evidence.push_back(x.str());}}
    f.fields["region_diff_count"]=std::to_string(i.region_diffs.size());f.fields["new_region_direct_xrefs"]=std::to_string(i.new_region_xrefs.size());
    for(const auto&x:i.new_region_xrefs){std::ostringstream xe;xe<<"incoming "<<x.kind<<" RVA 0x"<<std::hex<<x.source_rva<<" -> 0x"<<x.target_rva;f.evidence.push_back(xe.str());f.ranges.push_back(rva_range(x.source_rva,x.size,"INCOMING_XREF to new executable code",cp_basis,cp_identity));}
    if(i.dispatch.attempted){
        f.fields["dispatch_state"]=i.dispatch.state;f.fields["dispatch_reference_status"]=i.dispatch.reference_status;f.fields["dispatch_table_found"]=i.dispatch.table_found?"true":"false";
        if(i.dispatch.table_found){f.ranges.push_back(rva_range(i.dispatch.table_rva,std::uint64_t(i.dispatch.table_entry_count)*4,"CPython opcode dispatch table",cp_basis,cp_identity));f.fields["dispatch_table_rva"]=std::to_string(i.dispatch.table_rva);f.fields["dispatch_first_opcode"]=std::to_string(i.dispatch.table_first_opcode);f.fields["dispatch_entry_count"]=std::to_string(i.dispatch.table_entry_count);f.fields["dispatch_unique_handlers"]=std::to_string(i.dispatch.unique_handler_count);f.fields["opcode_slot_matches"]=std::to_string(i.dispatch.slot_matches);f.fields["opcode_permuted_slots"]=std::to_string(i.dispatch.permuted_slots);f.fields["opcode_handler_modified"]=std::to_string(i.dispatch.handler_modified);f.fields["opcode_semantic_mapped"]=std::to_string(i.dispatch.semantic_mapped);f.fields["opcode_ambiguous"]=std::to_string(i.dispatch.ambiguous);f.fields["opcode_unmapped"]=std::to_string(i.dispatch.unmapped);}
        if(i.dispatch.reference_status=="REFERENCE_MATCH")f.evidence.push_back("CPython 256-entry opcode dispatch table matches the official same-version reference");
        else if(i.dispatch.reference_status=="OPCODE_PERMUTATION"||i.dispatch.reference_status=="OPCODE_AND_HANDLER_MODIFIED"||i.dispatch.reference_status=="HANDLER_MODIFIED"||i.dispatch.reference_status=="PARTIAL_OPCODE_MAPPING"){
            for(const auto&m:i.dispatch.mappings){if(m.state=="SLOT_MATCH")continue;std::ostringstream x;x<<"opcode "<<m.target_opcode<<" "<<m.state<<" handler RVA 0x"<<std::hex<<m.target_handler_rva<<std::dec;if(!m.reference_names.empty()){x<<" -> official ";for(std::size_t z=0;z<m.reference_names.size();++z){if(z)x<<'|';x<<m.reference_opcodes[z]<<':'<<m.reference_names[z];}}f.negative_evidence.push_back(x.str());if(m.state.find("HANDLER_MODIFIED")!=std::string::npos)f.ranges.push_back(rva_range(m.target_handler_rva,0x40,"CPython opcode handler modified candidate",cp_basis,cp_identity));}
        }else if(i.dispatch.reference_status=="TABLE_RECOVERED_BUILD_INCOMPARABLE")f.negative_evidence.push_back("opcode dispatch table was recovered, but handler mapping claims are suppressed because this CPython native build is not comparable to the selected official reference");
    }
    if(i.compiler_probe.attempted){f.fields["compiler_probe_state"]=i.compiler_probe.state;f.fields["compiler_probe_launched"]=i.compiler_probe.launched?"true":"false";f.fields["compiler_probe_observed_opcodes"]=std::to_string(i.compiler_probe.observed_opcodes);f.fields["compiler_probe_changed_opcodes"]=std::to_string(i.compiler_probe.changed_opcodes);if(i.compiler_probe.state=="REFERENCE_MATCH")f.evidence.push_back("dynamic target-compiler probe emitted bytecode identical to the official same-version compiler reference");else if(i.compiler_probe.state=="OPCODE_PERMUTATION_RECOVERED"){f.evidence.push_back("dynamic target-compiler probe recovered a strict opcode permutation with identical code-object shape and opargs");for(const auto&m:i.compiler_probe.mappings)if(m.target_opcode!=m.reference_opcode)f.negative_evidence.push_back("compiler opcode "+std::to_string(m.target_opcode)+" -> official "+std::to_string(m.reference_opcode)+" observations="+std::to_string(m.observations));}else if(!i.compiler_probe.error.empty())f.negative_evidence.push_back("compiler probe: "+i.compiler_probe.error);}
    if(i.semantic_reference_status=="BUILD_INCOMPARABLE")f.negative_evidence.push_back("same CPython version but native build is not semantically comparable to the python.org reference; function-level and .text chunk mutation claims suppressed");
    if(!i.source.empty())f.fields["source"]=i.source;
    return f;
}
}
