#include "prts/dotnet_boundary.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>

namespace prts { namespace {

constexpr std::size_t kDependencyCap=96;
constexpr std::size_t kBridgeMethodCap=128;
constexpr std::uint32_t kExecutable=0x20000000u;
constexpr std::uint16_t kMethodAbstract=0x0400u;
constexpr std::uint16_t kImplCodeTypeMask=0x0003u;
constexpr std::uint16_t kImplForwardRef=0x0010u;
constexpr std::uint16_t kImplInternalCall=0x1000u;

std::uint32_t le32(std::span<const std::uint8_t> data,std::size_t offset){
    if(offset>data.size()||data.size()-offset<4)return 0;
    return std::uint32_t(data[offset])|(std::uint32_t(data[offset+1])<<8)|
           (std::uint32_t(data[offset+2])<<16)|(std::uint32_t(data[offset+3])<<24);
}

std::optional<std::size_t> rva_file_offset(const PeInfo& pe,std::uint32_t rva,std::size_t file_size){
    if(rva<pe.headers_size&&rva<file_size)return static_cast<std::size_t>(rva);
    for(const auto& section:pe.sections){
        const auto span=std::max(section.vsize,section.raw_size);
        if(rva<section.rva||std::uint64_t(rva)>=std::uint64_t(section.rva)+span)continue;
        const auto delta=std::uint64_t(rva)-section.rva;
        if(delta>=section.raw_size) return std::nullopt;
        const auto file=std::uint64_t(section.raw_offset)+delta;
        if(file<file_size)return static_cast<std::size_t>(file);
        return std::nullopt;
    }
    return std::nullopt;
}

const PeSection* section_for_rva(const PeInfo& pe,std::uint32_t rva){
    for(const auto& section:pe.sections){
        const auto span=std::max(section.vsize,section.raw_size);
        if(rva>=section.rva&&std::uint64_t(rva)<std::uint64_t(section.rva)+span)return &section;
    }
    return nullptr;
}

bool range_file_backed(const PeInfo& pe,std::uint32_t rva,std::uint32_t size,std::size_t file_size,
                       std::size_t&offset){
    const auto start=rva_file_offset(pe,rva,file_size);
    if(!start)return false;
    if(size>file_size-*start)return false;
    const auto* section=section_for_rva(pe,rva);
    if(!section)return false;
    const auto delta=std::uint64_t(rva)-section->rva;
    if(delta>section->raw_size||std::uint64_t(size)>std::uint64_t(section->raw_size)-delta)return false;
    offset=*start;
    return true;
}

std::string lower_ascii(std::string value){
    for(auto& c:value)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

std::string hex_u32(std::uint32_t value){
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

bool loader_module(std::string_view name){
    auto n=lower_ascii(std::string(name));
    return n=="mscoree.dll"||n=="mscoree"||n=="clr.dll"||n=="coreclr.dll"||n=="hostfxr.dll"||n=="hostpolicy.dll";
}

void add_dependency(DotNetBoundaryInfo& out,const DotNetBoundaryDependency& dep){
    if(out.dependencies.size()>=kDependencyCap){out.truncated=true;return;}
    out.dependencies.push_back(dep);
}

} // namespace

DotNetBoundaryInfo analyze_dotnet_boundary(std::span<const std::uint8_t> data,
                                           const PeInfo& pe,
                                           const DotNetInfo& dotnet){
    DotNetBoundaryInfo out;
    if(!pe.valid||!pe.clr.present)return out;
    out.candidate=true;
    out.clr_rva=pe.clr.rva;out.clr_size=pe.clr.size;
    std::size_t clr_offset=0;
    out.clr_range_file_backed=range_file_backed(pe,pe.clr.rva,pe.clr.size,data.size(),clr_offset);
    if(out.clr_range_file_backed){
        out.clr_file_offset=clr_offset;
        if(const auto* section=section_for_rva(pe,pe.clr.rva))out.clr_section=section->name;
        out.ranges.push_back(file_offset_range(clr_offset,pe.clr.size,"PE COR20/CLR header",CoordinateBasis::CURRENT_INPUT_FILE));
    }else{
        out.partial=true;
        out.error="PE CLR data directory is not fully file-backed";
    }

    out.pe_entry_rva=pe.entry_rva;
    if(const auto pe_entry=rva_file_offset(pe,pe.entry_rva,data.size())){
        out.pe_entry_file_backed=true;out.pe_entry_file_offset=*pe_entry;
        if(const auto* section=section_for_rva(pe,pe.entry_rva))out.pe_entry_section=section->name;
        out.ranges.push_back(file_offset_range(*pe_entry,1,"PE optional-header entrypoint",CoordinateBasis::CURRENT_INPUT_FILE));
    }

    // The COR20 flags and EntryPointTokenOrRVA are read again only after the
    // directory range has been checked.  DotNetInfo remains the authoritative
    // metadata parser, while this gate keeps a malformed header from becoming
    // a high-confidence native bridge claim.
    std::uint32_t clr_flags=dotnet.clr_flags;
    std::uint32_t entry_token_or_rva=dotnet.entry_point_token_or_rva;
    if(out.clr_range_file_backed&&pe.clr.size>=24&&clr_offset<=data.size()-24){
        clr_flags=le32(data,clr_offset+16);
        entry_token_or_rva=le32(data,clr_offset+20);
    }
    out.native_entrypoint=(clr_flags&0x10u)!=0;
    if(out.native_entrypoint){
        out.native_entry_rva=entry_token_or_rva;
        if(const auto native_entry=rva_file_offset(pe,out.native_entry_rva,data.size())){
            out.native_entry_file_backed=true;out.native_entry_file_offset=*native_entry;
            if(const auto* section=section_for_rva(pe,out.native_entry_rva)){
                out.native_entry_section=section->name;
                out.native_entry_executable=(section->characteristics&kExecutable)!=0;
            }
            out.ranges.push_back(file_offset_range(*native_entry,1,"CLR native EntryPointTokenOrRVA",CoordinateBasis::CURRENT_INPUT_FILE));
        }else{out.partial=true;out.error="CLR native EntryPointTokenOrRVA cannot be mapped to file-backed PE bytes";}
        out.entry_rva_diverges=out.native_entry_rva!=0&&out.native_entry_rva!=pe.entry_rva;
    }

    out.managed_method_count=static_cast<std::uint32_t>(std::min<std::size_t>(dotnet.methods.size(),std::numeric_limits<std::uint32_t>::max()));
    for(const auto& method:dotnet.methods){
        if(method.pinvoke){
            ++out.pinvoke_method_count;
            if(!method.import_module.empty())add_dependency(out,{"PInvoke",method.import_module,method.import_name,method.token,method.metadata_row_offset});
        }
        const auto impl_code=static_cast<std::uint16_t>(method.impl_flags&kImplCodeTypeMask);
        if(impl_code==1)++out.native_impl_method_count;
        else if(impl_code==3)++out.runtime_impl_method_count;
        const bool externally_defined=method.pinvoke||(method.flags&kMethodAbstract)!=0||(method.impl_flags&(kImplForwardRef|kImplInternalCall))!=0||impl_code==3;
        if(!method.rva){
            if(!externally_defined&&(impl_code==0||impl_code==2)){
                ++out.suspicious_rva_absent_method_count;
                if(out.bridge_methods.size()<kBridgeMethodCap){
                    DotNetBoundaryMethod bridge;bridge.token=method.token;bridge.rva=0;bridge.body_file_backed=false;bridge.pinvoke=method.pinvoke;bridge.type_name=method.type_name;bridge.name=method.name;bridge.import_module=method.import_module;bridge.import_name=method.import_name;bridge.state="METHOD_RVA_ABSENT_SUSPICIOUS";out.bridge_methods.push_back(std::move(bridge));
                }else out.truncated=true;
            }
            continue;
        }
        if(!method.body_file_backed){
            ++out.non_file_backed_method_count;
            const auto method_file=rva_file_offset(pe,method.rva,data.size());
            if(method_file)++out.body_geometry_invalid_method_count;else ++out.rva_unmapped_method_count;
            if(out.bridge_methods.size()<kBridgeMethodCap){
                DotNetBoundaryMethod bridge;bridge.token=method.token;bridge.rva=method.rva;bridge.body_file_backed=false;bridge.pinvoke=method.pinvoke;bridge.type_name=method.type_name;bridge.name=method.name;bridge.import_module=method.import_module;bridge.import_name=method.import_name;bridge.state=method_file?"METHOD_BODY_GEOMETRY_INVALID":"METHOD_RVA_UNMAPPED";
                if(method_file){
                    bridge.file_offset=*method_file;
                    if(out.ranges.size()<32)out.ranges.push_back(file_offset_range(*method_file,1,"MethodDef RVA / unresolved body",CoordinateBasis::CURRENT_INPUT_FILE));
                }
                out.bridge_methods.push_back(std::move(bridge));
            }else out.truncated=true;
        }else if(method.code_size==0){
            ++out.zero_code_method_count;
        }
    }

    std::set<std::string> native_modules;
    for(const auto& module:pe.imports){
        if(module.name.empty())continue;
        const auto key=lower_ascii(module.name);
        if(!loader_module(module.name))native_modules.insert(key);
        for(const auto& fn:module.functions){
            if(loader_module(module.name))continue;
            ++out.native_import_count;
            if(out.dependencies.size()<kDependencyCap){
                DotNetBoundaryDependency dep;dep.source="PE import";dep.module=module.name;dep.name=fn.by_ordinal?"#"+std::to_string(fn.ordinal):fn.name;dep.file_offset=0;add_dependency(out,dep);
            }else out.truncated=true;
        }
    }
    out.native_import_module_count=static_cast<std::uint32_t>(std::min<std::size_t>(native_modules.size(),std::numeric_limits<std::uint32_t>::max()));
    out.native_export_count=static_cast<std::uint32_t>(std::min<std::size_t>(pe.exports.size(),std::numeric_limits<std::uint32_t>::max()));

    if(!out.clr_range_file_backed){out.state="FAILED";out.boundary_kind="UNRESOLVED_BOUNDARY";return out;}
    if(out.native_entrypoint){
        out.boundary_kind="MIXED_NATIVE_MANAGED_BOUNDARY";
        if(!out.native_entry_file_backed||!out.native_entry_executable||!dotnet.valid){
            out.state="PARTIAL";out.partial=true;
            if(out.error.empty())out.error=!dotnet.valid?"CLR metadata did not close while native entrypoint evidence was present":"native CLR entrypoint is not an executable, file-backed RVA";
        }else{out.state="CONFIRMED";out.valid=true;}
    }else if(dotnet.valid&&(out.pinvoke_method_count||out.native_import_module_count||out.native_export_count)){
        out.boundary_kind="MANAGED_NATIVE_DEPENDENCY_SURFACE";out.state="LIKELY";out.valid=true;
    }else if(dotnet.valid){
        out.boundary_kind="MANAGED_ONLY_STATIC_SURFACE";out.state="CONFIRMED";out.valid=true;
    }else{
        out.boundary_kind="UNRESOLVED_BOUNDARY";out.state="PARTIAL";out.partial=true;
        if(out.error.empty())out.error=dotnet.error.empty()?"CLR metadata did not close":"CLR metadata parser returned a partial result: "+dotnet.error;
    }
    return out;
}

Finding dotnet_boundary_finding(const DotNetBoundaryInfo& info){
    Finding finding;finding.kind="runtime";finding.family="CLR/native boundary";finding.variant=info.boundary_kind;finding.state=info.state;
    if(info.state=="CONFIRMED")finding.confidence=0.90;else if(info.state=="LIKELY")finding.confidence=0.78;else if(info.state=="PARTIAL")finding.confidence=0.55;
    if(!info.candidate){finding.state="FAILED";finding.negative_evidence.push_back("PE CLR data directory is absent");return finding;}
    if(info.clr_range_file_backed)finding.evidence.push_back("PE COR20/CLR data directory is fully file-backed");
    else finding.negative_evidence.push_back("PE COR20/CLR data directory is not fully file-backed");
    if(info.native_entrypoint){
        finding.evidence.push_back("COR20 COMIMAGE_FLAGS_NATIVE_ENTRYPOINT is set; EntryPointTokenOrRVA is treated as an RVA only after PE mapping");
        if(info.native_entry_file_backed&&info.native_entry_executable)finding.evidence.push_back("CLR native EntryPointTokenOrRVA maps to an executable PE section");
        else finding.negative_evidence.push_back("CLR native EntryPointTokenOrRVA is not both file-backed and executable");
        if(info.entry_rva_diverges)finding.evidence.push_back("CLR native entry RVA diverges from the PE optional-header entry RVA; loader/stub and native bridge are separate coordinates");
    }else finding.negative_evidence.push_back("COR20 native-entry flag is absent; no native CLR entrypoint is promoted from the managed entry token");
    if(info.non_file_backed_method_count)finding.evidence.push_back(std::to_string(info.non_file_backed_method_count)+" MethodDef RVA(s) have no bounded IL body; native/malformed bridge remains unresolved");
    if(info.suspicious_rva_absent_method_count)finding.evidence.push_back(std::to_string(info.suspicious_rva_absent_method_count)+" non-abstract, non-P/Invoke MethodDef(s) declare IL/optimized-IL semantics but have no RVA; this is a bounded modified/stripped-body surface");
    if(info.body_geometry_invalid_method_count)finding.evidence.push_back(std::to_string(info.body_geometry_invalid_method_count)+" MethodDef RVA(s) map to file-backed bytes but fail the bounded tiny/fat IL body geometry check");
    if(info.rva_unmapped_method_count)finding.negative_evidence.push_back(std::to_string(info.rva_unmapped_method_count)+" MethodDef RVA(s) cannot be mapped to current file-backed PE bytes");
    if(info.zero_code_method_count)finding.negative_evidence.push_back(std::to_string(info.zero_code_method_count)+" file-backed IL body(ies) declare zero code bytes; IL semantics were not decoded");
    if(info.native_impl_method_count||info.runtime_impl_method_count)finding.evidence.push_back("MethodImpl code-type surface: native="+std::to_string(info.native_impl_method_count)+" runtime="+std::to_string(info.runtime_impl_method_count)+"; implementation kind is metadata evidence only");
    if(info.pinvoke_method_count)finding.evidence.push_back(std::to_string(info.pinvoke_method_count)+" bounded P/Invoke method(s) expose an external native dependency surface");
    if(info.native_import_module_count||info.native_export_count)finding.evidence.push_back("PE native surface: "+std::to_string(info.native_import_module_count)+" non-CLR import module(s), "+std::to_string(info.native_export_count)+" export(s)");
    if(info.truncated)finding.negative_evidence.push_back("dependency or bridge-method sample was capped; omitted entries are not evidence of absence");
    if(!info.error.empty())finding.negative_evidence.push_back(info.error);
    finding.fields["boundary_kind"]=info.boundary_kind;finding.fields["clr_rva"]=hex_u32(info.clr_rva);finding.fields["native_entry_rva"]=hex_u32(info.native_entry_rva);finding.fields["managed_methods"]=std::to_string(info.managed_method_count);finding.fields["non_file_backed_methods"]=std::to_string(info.non_file_backed_method_count);finding.fields["suspicious_rva_absent_methods"]=std::to_string(info.suspicious_rva_absent_method_count);finding.fields["rva_unmapped_methods"]=std::to_string(info.rva_unmapped_method_count);finding.fields["body_geometry_invalid_methods"]=std::to_string(info.body_geometry_invalid_method_count);finding.fields["zero_code_methods"]=std::to_string(info.zero_code_method_count);finding.fields["native_impl_methods"]=std::to_string(info.native_impl_method_count);finding.fields["runtime_impl_methods"]=std::to_string(info.runtime_impl_method_count);finding.fields["pinvoke_methods"]=std::to_string(info.pinvoke_method_count);finding.fields["native_import_modules"]=std::to_string(info.native_import_module_count);finding.fields["native_imports"]=std::to_string(info.native_import_count);finding.fields["native_exports"]=std::to_string(info.native_export_count);finding.fields["runtime_resolution"]="NOT_PERFORMED";finding.fields["execution_refusal"]="static preprocessing never executes CLR/native payloads";
    finding.ranges=info.ranges;finding.suggested_actions={"inspect:CLR EntryPointTokenOrRVA and PE OEP at reported file offsets","resolve P/Invoke/PE import modules against supplied DLL artifacts","inspect MethodDef RVA/body geometry anomalies before trusting managed control flow","treat unresolved MethodDef bodies as bridge candidates; do not infer recovered native logic"};
    return finding;
}

} // namespace prts
