#include "prts/dotnet.hpp"
#include <limits>

namespace prts {
Finding dotnet_resources_finding(const DotNetInfo&i){
    Finding f;f.kind="managed_resource";f.family=".NET managed resources";
    if(!i.valid){f.state="FAILED";f.negative_evidence.push_back("ECMA-335 metadata did not close, so ManifestResource rows are not trusted");return f;}
    std::size_t embedded=0,external=0,assembly_refs=0,files=0,exported_types=0,unknown=0;std::uint64_t bytes=0;std::size_t rendered=0;
    for(const auto&r:i.resources){
        if(r.embedded&&r.size_known){
            ++embedded;
            bytes=bytes>std::numeric_limits<std::uint64_t>::max()-r.size?std::numeric_limits<std::uint64_t>::max():bytes+r.size;
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
} // namespace prts
