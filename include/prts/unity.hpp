#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <filesystem>
#include <limits>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct UnityDispatchTypeRef {
    std::uint32_t type_index=0;
    std::int32_t type_definition_index=-1;
    std::string type_name;
};
struct UnityInterfaceOffsetInfo {
    std::uint32_t global_index=0,type_index=0;
    std::int32_t type_definition_index=-1,offset=0;
    std::uint16_t method_count=0;
    std::string type_name;
};
struct UnityVtableEntryInfo {
    std::uint32_t global_index=0,slot=0,encoded=0,raw_kind=0,kind=0,source_index=0,method_definition_index=0xffffffffu,interface_type_index=0xffffffffu;
    std::int32_t interface_type_definition_index=-1,interface_offset=-1,interface_slot=-1;
    bool null_entry=false,invalid_usage=false,interface_mapped=false;
    std::string kind_name,resolved,interface_name;
};
struct UnityTypeInfo {
    std::uint32_t index=0;
    std::string namespc,name,full_name,image_name;
    std::int32_t image_index=-1;
    std::uint32_t first_field=0,first_method=0,flags=0,bitfield=0;
    std::int64_t generic_container_index=-1,declaring_type_index=-1,parent_type_index=-1;
    std::int32_t declaring_type_definition_index=-1,parent_type_definition_index=-1;
    std::int64_t first_event=-1,first_property=-1,nested_types_start=-1,interfaces_start=-1,vtable_start=-1,interface_offsets_start=-1;
    std::uint16_t field_count=0,method_count=0,property_count=0,event_count=0,nested_type_count=0,vtable_count=0,interfaces_count=0,interface_offsets_count=0;
    std::vector<std::string> generic_parameters;
    std::vector<std::uint32_t> nested_type_indices;
    std::vector<UnityDispatchTypeRef> interfaces;
    std::vector<UnityInterfaceOffsetInfo> interface_offsets;
    std::vector<UnityVtableEntryInfo> vtable;
    std::string declaring_type_name,parent_type_name;
    std::uint32_t token=0;
    bool is_value_type=false,is_enum=false,is_interface=false,is_abstract=false;
    bool type_sizes_resolved=false,field_offsets_resolved=false,field_offsets_runtime_only=false,static_init_listed=false,static_constructor_resolved=false;
    std::int64_t static_constructor_method_index=-1;
    std::uint64_t field_offsets_pointer_va=0,static_constructor_rva=0;
    std::uint32_t instance_size=0,static_fields_size=0,thread_static_fields_size=0;
    std::int32_t native_size=0;
    std::vector<std::int32_t> field_offsets;
};
struct UnityStringLiteralInfo {
    std::uint32_t index=0,data_index=0,length=0;
    std::uint64_t record_file_offset=0,data_file_offset=0;
    bool utf8_valid=true;
    std::string value;
};
struct UnityFieldInfo {
    std::uint32_t index=0,token=0,type_index=0;
    std::int64_t declaring_type=-1;
    std::string declaring_type_name,name,full_name,type_name;
    bool offset_resolved=false,offset_runtime_only=false;
    std::int32_t offset=0;
};
struct UnityMethodParameterInfo {
    std::uint32_t index=0,token=0,type_index=0;
    std::string name,type_name;
};
struct UnityMethodInfo {
    std::uint32_t index=0,token=0,return_type_index=0,parameter_start=0xffffffffu,return_parameter_token=0;
    std::int64_t declaring_type=-1,generic_container_index=-1;
    std::string image_name,type_name,name,full_name,return_type,signature;
    std::uint16_t parameter_count=0,flags=0,impl_flags=0,vtable_slot=0;
    bool pinvoke_impl=false;
    std::int32_t invoker_index=-1;
    std::uint64_t rva=0,invoker_pointer_va=0,invoker_rva=0,adjustor_thunk_va=0,adjustor_thunk_rva=0;
    std::uint32_t native_end_rva=0,native_size=0,native_alias_count=0;
    bool invoker_resolved=false,adjustor_thunk_resolved=false,native_bound_resolved=false;
    std::vector<UnityMethodParameterInfo> parameters;
    std::vector<std::string> generic_parameters;
};
struct UnityPInvokeInfo {
    std::uint32_t method_index=0,body_rva=0,resolver_call_rva=0,cache_rva=0,parameter_size=0,module_length=0,entry_length=0;
    std::uint16_t method_flags=0,impl_flags=0;
    std::uint32_t charset=0,calling_convention=0;
    std::uint64_t resolver_va=0,cache_va=0,module_va=0,entry_va=0;
    bool resolved=false,no_mangle=false;
    std::string method,module,entry,state,error;
};
struct UnityMetadataRegistrationPair { std::string role; std::uint64_t count=0,pointer_va=0; };


struct UnityIl2CppTypeArg {
    std::uint64_t va=0,data=0;
    std::int32_t type_definition_index=-1,generic_class_index=-1;
    std::uint16_t attrs=0;
    std::uint8_t type_code=0,raw_flags=0;
    std::string type_name,resolved_name;
};
struct UnityGenericInstInfo {
    std::uint32_t index=0,argc=0;
    std::uint64_t va=0,argv_va=0;
    std::vector<UnityIl2CppTypeArg> args;
};
struct UnityGenericContainerInfo {
    std::uint32_t index=0,owner_index=0,parameter_start=0,parameter_count=0;
    bool is_method=false;
    std::string owner_name;
};
struct UnityGenericParameterInfo {
    std::uint32_t index=0,owner_container=0,constraint_start=0;
    std::uint16_t constraint_count=0,number=0,flags=0;
    std::string name;
    std::vector<std::uint32_t> constraint_type_indices;
    std::vector<std::string> constraints;
};
struct UnityGenericClassInfo {
    std::uint32_t index=0,type_definition_index=0,class_inst_index=0;
    std::int32_t method_inst_index=-1;
    std::uint64_t va=0,type_va=0,tail_qword=0;
    std::uint8_t type_code=0;
    bool duplicate_struct=false;
    std::string type_full_name;
};
struct UnityDefaultValueInfo {
    std::uint32_t index=0,owner_index=0,default_type_index=0,data_size=0;
    std::int64_t data_index=-1;
    std::uint64_t record_file_offset=0,data_file_offset=0;
    bool data_index_null=false,value_resolved=false;
    std::string record_kind,owner_name,declared_type,value_type,value,blob_preview_hex;
};
struct UnityMetadataUsageInfo {
    std::uint32_t index=0,destination_index=0,raw_usage_kind=0,usage_kind=0,source_index=0,reference_count=0;
    std::int32_t type_definition_index=-1;
    std::uint32_t encoded_source=0;
    std::uint64_t storage_va=0,storage_rva=0,storage_file_offset=0;
    bool storage_file_backed=false,always_init=false,runtime_discovered=false;
    std::uint32_t init_site_count=0;
    std::string usage_name,resolved;
};
struct UnityMethodUsageXrefInfo {
    std::uint32_t body_rva=0,body_end_rva=0,method_index=0,usage_index=0,first_instruction_rva=0,xref_count=0,alias_count=0;
    bool init_site_seen=false;
    std::string method;
};
struct UnityRgctxEntryInfo {
    std::uint32_t index=0,kind=0,range_index=0,owner_token=0;
    std::int32_t raw_index=-1,type_index=-1,generic_method_index=-1,constrained_type_index=-1;
    std::uint32_t encoded_method_index=0,encoded_method_usage=0,encoded_method_decoded_index=0;
    std::uint64_t data_va=0;
    std::string kind_name,owner_kind,owner_name,resolved,constrained_method;
};
struct UnityRgctxRangeInfo {
    std::uint32_t index=0,token=0,start=0,length=0;
    std::string owner_kind,owner_name;
};
struct UnityCodeGenModuleInfo {
    std::uint32_t index=0,rgctx_range_count=0,rgctx_entry_count=0;
    std::uint64_t va=0;
    std::string name;
    bool rgctx_valid=false;
    std::vector<UnityRgctxRangeInfo> ranges;
    std::vector<UnityRgctxEntryInfo> entries;
};
struct UnityGenericMethodInfo {
    std::uint32_t index=0,method_spec_index=0,method_definition_index=0;
    std::int32_t class_inst_index=-1,method_inst_index=-1,method_pointer_index=-1,invoker_index=-1,adjustor_thunk_index=-1;
    std::uint64_t method_pointer_va=0,invoker_pointer_va=0,adjustor_thunk_va=0;
    std::uint64_t method_rva=0,invoker_rva=0,adjustor_thunk_rva=0;
    bool method_pointer_resolved=false,invoker_pointer_resolved=false,adjustor_thunk_resolved=false;
    std::string method_full_name;
};
struct UnityInfo {
    bool valid=false,il2cpp=false,mono=false,unity_generic=false,unity_player_import=false,il2cpp_export_evidence=false,il2cpp_string_evidence=false,game_assembly_validated=false,mono_runtime_validated=false,metadata_valid=false,string_literals_valid=false,metadata_usages_resolved=false,default_values_resolved=false,method_bounds_resolved=false,pinvoke_resolved=false,type_dispatch_metadata_resolved=false,metadata_xrefs_resolved=false,member_metadata_valid=false,member_signatures_resolved=false,generic_parameter_metadata_valid=false,generic_parameter_constraints_resolved=false,registration_resolved=false,metadata_registration_resolved=false,generic_insts_resolved=false,registered_types_resolved=false,generic_classes_resolved=false,generic_methods_resolved=false,rgctx_resolved=false,method_dispatch_resolved=false;
    std::int32_t metadata_version=0;
    std::string backend_state="ABSENT",metadata_layout,engine_version_state="NOT_ATTEMPTED",engine_version,engine_version_source,engine_version_detail,globalgamemanagers_state="ABSENT",globalgamemanagers_version,globalgamemanagers_detail,data_unity3d_state="ABSENT",data_unity3d_version,data_unity3d_detail,string_literals_error,metadata_usage_state="NOT_ATTEMPTED",metadata_usage_profile,metadata_usage_error,default_values_state="NOT_ATTEMPTED",default_values_profile,default_values_error,method_bounds_state="NOT_ATTEMPTED",method_bounds_profile,method_bounds_error,pinvoke_state="NOT_ATTEMPTED",pinvoke_profile,pinvoke_error,type_dispatch_metadata_state="NOT_ATTEMPTED",type_dispatch_metadata_profile,type_dispatch_metadata_error,metadata_xrefs_state="NOT_ATTEMPTED",metadata_xrefs_profile,metadata_xrefs_error,registration_variant,registration_error,metadata_registration_profile_state="NOT_ATTEMPTED",metadata_registration_profile,metadata_registration_normalized_variant,metadata_registration_engine_hint,metadata_registration_profile_detail,metadata_registration_error,member_metadata_error,member_signatures_error,generic_parameter_metadata_error,generic_parameter_constraints_error,generic_insts_error,registered_types_error,generic_classes_profile,generic_classes_error,generic_methods_state="NOT_ATTEMPTED",generic_methods_error,rgctx_state="NOT_ATTEMPTED",rgctx_profile,rgctx_error,method_dispatch_state="NOT_ATTEMPTED",method_dispatch_profile,method_dispatch_error;
    std::uint64_t code_registration_va=0,codegen_modules_va=0,registration_thunk_va=0,registration_target_va=0,metadata_registration_va=0,registration_third_argument_va=0;
    std::uint32_t codegen_module_count=0,mapped_method_count=0,metadata_type_definition_count=0,metadata_method_definition_count=0,metadata_field_count=0,metadata_parameter_count=0;
    std::uint32_t string_literal_count=0,string_literal_invalid_utf8_count=0,string_literal_empty_count=0,string_literal_max_length=0;
    std::uint64_t string_literal_total_bytes=0,string_literal_table_offset=0,string_literal_data_offset=0;
    std::uint32_t string_literal_record_size=0;
    std::uint32_t metadata_usage_declared_count=0,metadata_usage_effective_storage_count=0,metadata_usage_count=0,metadata_usage_pair_reference_count=0,metadata_usage_file_backed_storage_count=0,metadata_usage_max_reference_count=0;
    std::uint32_t metadata_usage_typeinfo_count=0,metadata_usage_type_count=0,metadata_usage_methoddef_count=0,metadata_usage_field_count=0,metadata_usage_string_count=0,metadata_usage_methodref_count=0,metadata_usage_field_rva_count=0;
    std::uint32_t field_default_record_count=0,field_constant_count=0,parameter_default_count=0,field_rva_count=0,field_rva_sized_count=0,decoded_default_count=0,unresolved_default_count=0,null_default_count=0,default_dummy_count=0;
    std::uint32_t method_bound_count=0,method_unbound_count=0,native_body_count=0,native_alias_extra_count=0,native_max_alias_count=0;
    std::uint32_t pinvoke_method_count=0,pinvoke_resolved_count=0,pinvoke_unresolved_count=0;
    std::uint64_t pinvoke_resolver_va=0;
    std::uint32_t nested_type_row_count=0,direct_interface_row_count=0,interface_offset_row_count=0,vtable_entry_count=0,vtable_methoddef_count=0,vtable_methodref_count=0,vtable_null_count=0,vtable_invalid_count=0,vtable_exact_slot_count=0,vtable_interface_mapped_count=0;
    std::uint32_t runtime_metadata_usage_count=0,always_init_metadata_usage_count=0,runtime_metadata_wrapper_count=0;
    std::uint64_t runtime_metadata_initializer_va=0,metadata_xref_relation_count=0,metadata_xref_instruction_count=0,metadata_xref_method_count=0,metadata_xref_slot_count=0;
    std::uint64_t default_data_offset=0,default_data_size=0;
    std::uint32_t resolved_field_type_count=0,resolved_method_signature_count=0,resolved_parameter_type_count=0;
    std::uint32_t field_offset_type_count=0,field_offset_runtime_only_type_count=0,field_offset_null_type_count=0,type_size_type_count=0,generic_inst_count=0,generic_type_arg_count=0,generic_max_argc=0,registered_type_count=0;
    std::uint32_t generic_container_count=0,generic_parameter_count=0,generic_constraint_count=0,resolved_generic_constraint_count=0;
    std::uint32_t generic_class_count=0,generic_class_unique_struct_count=0,generic_class_duplicate_ref_count=0,generic_class_unique_type_definition_count=0,generic_class_max_argc=0;
    std::uint32_t generic_class_tail_nonzero_count=0,generic_class_tail_image_pointer_count=0,generic_class_tail_small_value_count=0;
    std::uint32_t generic_method_record_count=0,method_spec_count=0,generic_method_pointer_count=0,invoker_pointer_count=0;
    std::uint32_t generic_method_native_count=0,generic_method_null_count=0,generic_invoker_missing_count=0,generic_invoker_null_count=0,generic_adjustor_count=0,generic_adjustor_null_count=0;
    std::uint32_t rgctx_module_count=0,rgctx_module_with_data_count=0,rgctx_range_count=0,rgctx_entry_count=0,rgctx_resolved_entry_count=0,rgctx_constrained_count=0;
    std::uint32_t method_dispatch_method_count=0,method_invoker_resolved_count=0,method_invoker_missing_count=0,method_adjustor_count=0,static_init_type_count=0,static_init_with_cctor_count=0;
    std::filesystem::path metadata_path,game_assembly_path,managed_path,mono_runtime_path,engine_version_root,globalgamemanagers_path,data_unity3d_path;
    std::uint64_t string_heap_offset=0,string_heap_size=0;
    std::uint64_t method_table_offset=0,type_table_offset=0;
    std::uint32_t method_record_size=0,type_record_size=0;
    std::vector<UnityTypeInfo> types;
    std::vector<UnityStringLiteralInfo> string_literals;
    std::vector<UnityFieldInfo> fields;
    std::vector<UnityMethodParameterInfo> parameters;
    std::vector<UnityMethodInfo> methods;
    std::vector<UnityMetadataRegistrationPair> metadata_registration_pairs;
    std::vector<UnityGenericInstInfo> generic_insts;
    std::vector<UnityGenericContainerInfo> generic_containers;
    std::vector<UnityGenericParameterInfo> generic_parameters;
    std::vector<UnityGenericClassInfo> generic_classes;
    std::vector<UnityGenericMethodInfo> generic_methods;
    std::vector<UnityDefaultValueInfo> default_values;
    std::vector<UnityPInvokeInfo> pinvokes;
    std::vector<UnityMetadataUsageInfo> metadata_usages;
    std::vector<UnityMethodUsageXrefInfo> metadata_xrefs;
    std::vector<UnityCodeGenModuleInfo> codegen_modules;
    std::string error;
};
struct UnityExtractResult { bool success=false,budget_exhausted=false,callgraph_requested=true; std::filesystem::path symbols_csv,layouts_csv,generics_csv,rgctx_csv,strings_csv,usages_csv,defaults_csv,xrefs_csv,pinvoke_csv,dispatch_csv,dispatch_calls_csv,dispatch_targets_csv,callgraph_csv; std::uint64_t row_budget=std::numeric_limits<std::uint64_t>::max(),materialized_rows=0,omitted_rows=0,symbol_count=0,layout_row_count=0,generic_row_count=0,rgctx_row_count=0,string_row_count=0,usage_row_count=0,default_row_count=0,xref_row_count=0,pinvoke_row_count=0,dispatch_row_count=0,dispatch_callsite_count=0,dispatch_virtual_callsite_count=0,dispatch_interface_callsite_count=0,dispatch_exact_count=0,dispatch_bounded_count=0,dispatch_unresolved_count=0,dispatch_rejected_helper_count=0,dispatch_candidate_set_count=0,dispatch_candidate_row_count=0,call_edge_count=0,callgraph_body_count=0,callgraph_partial_body_count=0,callgraph_instruction_count=0,callgraph_unresolved_direct_count=0,callgraph_unresolved_indirect_count=0; std::vector<std::string> omitted_planes; std::string error,dispatch_callsite_state="NOT_ATTEMPTED",dispatch_callsite_error,callgraph_error; };
UnityInfo inspect_unity_il2cpp_metadata(std::span<const std::uint8_t>data);
UnityInfo detect_unity(const std::filesystem::path&input,std::span<const std::uint8_t>data,const PeInfo&pe);
Finding unity_finding(const UnityInfo&info);
UnityExtractResult extract_unity_symbols(const UnityInfo&info,const std::filesystem::path&out,bool include_callgraph=true,std::uint64_t max_rows=std::numeric_limits<std::uint64_t>::max());
}
