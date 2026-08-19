#pragma once
#include "prts/finding.hpp"
#include "prts/implicit_exec.hpp"
#include "prts/pe.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct DotNetTypeRef {
    std::uint32_t rid=0,token=0,resolution_scope=0;
    std::string namespc,name,full_name,scope_name;
};
struct DotNetParam {
    std::uint32_t rid=0,token=0;
    std::uint16_t flags=0,sequence=0;
    std::string name;
};
struct DotNetField {
    std::uint32_t rid=0,token=0,signature_blob=0;
    std::uint16_t flags=0;
    bool has_layout=false,has_rva=false;
    std::uint32_t offset=0,rva=0;
    std::string type_name,name,declaring_type,full_name,signature;
};
struct DotNetType {
    std::uint32_t rid=0,token=0,flags=0,extends_token=0,field_start=0,method_start=0,enclosing_token=0;
    std::string namespc,name,full_name,base_type,enclosing_type;
    std::vector<std::string> interfaces,generic_params;
};
struct DotNetMethod {
    std::uint32_t rid=0,token=0,rva=0,signature_blob=0,param_start=0,generic_arity=0;
    std::uint16_t impl_flags=0,flags=0;
    std::uint64_t metadata_row_offset=0,body_file_offset=0,body_header_size=0,code_file_offset=0,code_size=0;
    bool has_this=false,explicit_this=false,pinvoke=false,body_file_backed=false;
    std::string calling_convention,type_name,name,return_type,signature,full_name,import_module,import_name;
    std::vector<std::string> param_types,param_names,generic_params;
};
struct DotNetMemberRef {
    std::uint32_t rid=0,token=0,parent_token=0,signature_blob=0;
    std::string parent,name,kind,signature;
};
struct DotNetAssemblyRef {
    std::uint32_t rid=0,token=0;
    std::uint16_t major=0,minor=0,build=0,revision=0;
    std::string name,culture,version;
};
struct DotNetProperty {
    std::uint32_t rid=0,token=0,signature_blob=0;
    std::uint16_t flags=0;
    std::string declaring_type,name,type_name,signature,getter,setter;
};
struct DotNetEvent {
    std::uint32_t rid=0,token=0,event_type_token=0;
    std::uint16_t flags=0;
    std::string declaring_type,name,event_type,adder,remover,raiser;
};
struct DotNetGenericParam {
    std::uint32_t rid=0,token=0,owner_token=0;
    std::uint16_t number=0,flags=0;
    std::string name,owner;
    std::vector<std::string> constraints;
};
struct DotNetMethodSpec {
    std::uint32_t rid=0,token=0,method_token=0,signature_blob=0;
    std::string method,signature;
    std::vector<std::string> type_args;
};
struct DotNetResource {
    std::uint32_t rid=0,token=0,offset=0,flags=0,implementation_token=0;
    bool embedded=false,size_known=false;
    std::uint64_t data_offset=0,size=0;
    std::string name,implementation;
};
struct DotNetInfo {
    bool valid=false,unity_managed=false,unity_mono=false,unity_path_hint=false,unity_engine_reference=false,signature_parse_complete=true,entry_point_native=false;
    std::uint32_t clr_flags=0,entry_point_token_or_rva=0,managed_entry_method_token=0;
    std::string runtime_version,managed_entry_method,managed_entry_type;
    std::uint64_t metadata_offset=0,metadata_size=0,blob_heap_size=0,resources_offset=0,resources_size=0;
    std::array<std::uint32_t,64> table_rows{};
    std::vector<DotNetTypeRef> type_refs;
    std::vector<DotNetType> types;
    std::vector<DotNetField> fields;
    std::vector<DotNetMethod> methods;
    std::vector<DotNetParam> params;
    std::vector<DotNetMemberRef> member_refs;
    std::vector<DotNetAssemblyRef> assembly_refs;
    std::vector<DotNetProperty> properties;
    std::vector<DotNetEvent> events;
    std::vector<DotNetGenericParam> generic_params;
    std::vector<DotNetMethodSpec> method_specs;
    std::vector<DotNetResource> resources;
    std::vector<std::string> anomalies;
    std::vector<std::string> obfuscation_hints;
    ImplicitExecutionInfo implicit_exec;
    std::string error;
};
struct DotNetExtractResult {
    bool success=false;
    std::filesystem::path symbols_csv,types_csv,members_csv;
    std::uint64_t symbol_count=0,type_count=0,member_count=0;
    std::string error;
};
DotNetInfo detect_dotnet(std::span<const std::uint8_t>data,const PeInfo&pe,const std::filesystem::path&path={});
Finding dotnet_finding(const DotNetInfo&info);
DotNetExtractResult extract_dotnet_symbols(const DotNetInfo&info,const std::filesystem::path&out);
}
