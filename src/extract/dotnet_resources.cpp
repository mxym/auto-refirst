#include "prts/dotnet.hpp"
#include "prts/path_utf8.hpp"
#include <algorithm>
#include <fstream>
#include <limits>

namespace prts {
namespace {
std::string resource_output_name(const DotNetResource&r){
    std::string name=r.name;
    const auto slash=name.find_last_of("/\\");
    if(slash!=std::string::npos)name=name.substr(slash+1);
    std::string safe;safe.reserve(std::min<std::size_t>(name.size(),120));
    for(unsigned char c:name){
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')safe.push_back(static_cast<char>(c));
        else safe.push_back('_');
        if(safe.size()>=120)break;
    }
    while(!safe.empty()&&(safe.back()=='.'||safe.back()==' '))safe.back()='_';
    if(safe.empty())safe="unnamed";
    return "resource_"+std::to_string(r.rid)+"_"+safe;
}
std::uint64_t sat_add_resource(std::uint64_t a,std::uint64_t b){return b>(std::numeric_limits<std::uint64_t>::max)()-a?(std::numeric_limits<std::uint64_t>::max)():a+b;}
void note_resource_warning(DotNetResourceExtractResult&out,std::string text){if(out.warnings.size()<128)out.warnings.push_back(std::move(text));}
}
Finding dotnet_resources_finding(const DotNetInfo&i){
    Finding f;f.kind="managed_resource";f.family=".NET managed resources";
    if(!i.valid){f.state="FAILED";f.negative_evidence.push_back("ECMA-335 metadata did not close, so ManifestResource rows are not trusted");return f;}
    std::size_t embedded=0,external=0,assembly_refs=0,files=0,exported_types=0,unknown=0;std::uint64_t bytes=0;std::size_t rendered=0;
    for(const auto&r:i.resources){
        if(r.embedded&&r.size_known){
            ++embedded;
            bytes=bytes>(std::numeric_limits<std::uint64_t>::max)()-r.size?(std::numeric_limits<std::uint64_t>::max)():bytes+r.size;
            if(rendered<64){f.ranges.push_back(file_offset_range(r.data_offset,r.size,"embedded managed resource "+(r.name.empty()?std::to_string(r.rid):r.name)));++rendered;}
        } else if(r.implementation_token){
            ++external;
            if(r.implementation_kind=="AssemblyRef")++assembly_refs;
            else if(r.implementation_kind=="File")++files;
            else if(r.implementation_kind=="ExportedType")++exported_types;
            else ++unknown;
        }
    }
    if(!embedded&&!external){
        if(i.resources.empty()){f.state="ABSENT";return f;}
        f.state="PARTIAL";f.confidence=0.55;f.variant="unresolved-references";f.evidence.push_back("ManifestResource rows were structurally decoded, but no embedded payload or external implementation target closed");f.negative_evidence={"the CLR resources directory was absent/unresolved or the implementation coded indexes did not close to a reportable target","resource names and extensions do not establish payload type or execution"};f.fields["resource_count"]=std::to_string(i.resources.size());f.fields["embedded_count"]="0";f.fields["external_reference_count"]="0";f.fields["resource_semantics"]="NOT_ATTEMPTED_STATIC_ONLY";f.suggested_actions={"inspect CLR resources directory and ManifestResource implementation tokens","supply sibling files/assemblies before runtime tracing"};return f;
    }
    f.state=embedded?"CONFIRMED":"LIKELY";f.confidence=embedded?0.92:0.68;f.variant=embedded?(external?"embedded-and-external":"embedded-payloads"):"external-references";
    f.evidence.push_back("ECMA-335 ManifestResource rows were structurally decoded; embedded rows closed to the CLR resources directory and external implementation tokens were retained");
    f.negative_evidence={"resource names and extensions do not establish payload type or execution","embedded bytes are reported as static artifacts only; decompression, decryption and CLR resource semantics are not inferred"};
    if(embedded)f.evidence.push_back(std::to_string(embedded)+" embedded resource(s) expose exact file-backed payload ranges totaling "+std::to_string(bytes)+" bytes");
    if(external){
        f.evidence.push_back(std::to_string(external)+" resource implementation reference(s) point outside this image and require supplied sibling artifacts");
        if(assembly_refs)f.evidence.push_back(std::to_string(assembly_refs)+" external resource reference(s) target AssemblyRef rows");
        if(files)f.evidence.push_back(std::to_string(files)+" external resource reference(s) target File rows");
        if(exported_types)f.evidence.push_back(std::to_string(exported_types)+" external resource reference(s) target ExportedType rows");
        if(unknown)f.negative_evidence.push_back(std::to_string(unknown)+" external implementation reference(s) have no recognized ECMA-335 target table");
    }
    if(embedded>rendered)f.negative_evidence.push_back("only the first 64 embedded resource ranges are rendered; the count and byte total cover all validated rows");
    f.fields["resource_count"]=std::to_string(i.resources.size());f.fields["embedded_count"]=std::to_string(embedded);f.fields["embedded_bytes"]=std::to_string(bytes);f.fields["external_reference_count"]=std::to_string(external);f.fields["external_assembly_ref_count"]=std::to_string(assembly_refs);f.fields["external_file_count"]=std::to_string(files);f.fields["external_exported_type_count"]=std::to_string(exported_types);f.fields["external_unknown_count"]=std::to_string(unknown);f.fields["ranges_rendered"]=std::to_string(rendered);f.fields["resource_semantics"]="NOT_ATTEMPTED_STATIC_ONLY";
    f.suggested_actions={"extract:dotnet-resources","inspect embedded DLL/EXE/config payloads before runtime tracing","resolve external resource implementations from supplied sibling artifacts"};
    return f;
}

DotNetResourceExtractResult extract_dotnet_resources(std::span<const std::uint8_t>d,const DotNetInfo&i,const std::filesystem::path&outdir,bool core_only,std::uint64_t max_output_bytes,std::uint32_t max_output_files){
    DotNetResourceExtractResult out;out.output_dir=outdir;out.core_only=core_only;
    if(!i.valid){out.error=".NET metadata not valid";return out;}
    std::vector<const DotNetResource*>embedded;embedded.reserve(i.resources.size());for(const auto&r:i.resources)if(r.embedded&&r.size_known)embedded.push_back(&r);
    out.embedded_count=embedded.size()>(std::numeric_limits<std::uint32_t>::max)()?(std::numeric_limits<std::uint32_t>::max)():static_cast<std::uint32_t>(embedded.size());
    if(embedded.empty()){out.success=true;return out;}
    if(outdir.empty()){out.error=".NET resource output directory is empty";return out;}
    std::error_code ec;std::filesystem::create_directories(outdir,ec);if(ec){out.error="cannot create .NET resource output directory: "+ec.message();return out;}
    for(const auto*r:embedded){
        if(r->data_offset>d.size()||r->size>d.size()-r->data_offset){note_resource_warning(out,"embedded managed resource range is outside the input: "+(r->name.empty()?std::to_string(r->rid):r->name));continue;}
        if(out.files.size()>=max_output_files||r->size>max_output_bytes-out.output_bytes){out.budget_exhausted=true;++out.omitted_count;out.omitted_bytes=sat_add_resource(out.omitted_bytes,r->size);continue;}
        if(r->size>static_cast<std::uint64_t>((std::numeric_limits<std::streamsize>::max)())){note_resource_warning(out,"embedded managed resource exceeds the local stream write limit: "+std::to_string(r->rid));continue;}
        const auto rel=resource_output_name(*r);auto path=outdir/prts::path_from_utf8(rel);if(path.empty()){note_resource_warning(out,"cannot encode managed resource output name for RID "+std::to_string(r->rid));continue;}
        auto st=std::filesystem::symlink_status(path,ec);if(!ec&&st.type()!=std::filesystem::file_type::not_found){if(st.type()==std::filesystem::file_type::symlink){note_resource_warning(out,"refusing managed resource output symlink: "+prts::path_utf8(path));continue;}if(st.type()!=std::filesystem::file_type::regular){note_resource_warning(out,"refusing non-regular managed resource output: "+prts::path_utf8(path));continue;}}
        ec.clear();std::ofstream f(path,std::ios::binary|std::ios::trunc);if(!f){note_resource_warning(out,"cannot create managed resource output: "+prts::path_utf8(path));continue;}
        f.write(reinterpret_cast<const char*>(d.data()+static_cast<std::size_t>(r->data_offset)),static_cast<std::streamsize>(r->size));f.flush();if(!f){f.close();ec.clear();std::filesystem::remove(path,ec);note_resource_warning(out,"managed resource output write failed: "+prts::path_utf8(path));continue;}
        ec.clear();const auto written=std::filesystem::file_size(path,ec);if(ec||written!=r->size){ec.clear();std::filesystem::remove(path,ec);note_resource_warning(out,"managed resource output size mismatch: "+prts::path_utf8(path));continue;}
        out.files.push_back(path);++out.written_count;out.output_bytes=sat_add_resource(out.output_bytes,r->size);
    }
    out.success=out.written_count==out.embedded_count&&!out.budget_exhausted&&out.warnings.empty();
    if(!out.success&&out.error.empty()&&(out.budget_exhausted||out.written_count<out.embedded_count))out.error="not all validated embedded managed resources were materialized";
    return out;
}
} // namespace prts
