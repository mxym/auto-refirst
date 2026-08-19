#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace prts {
struct CPythonIntrospectionStringListFact {
    std::vector<std::string> items;
    std::uint64_t count=0,scanned=0;
    bool truncated=false,unsupported=false,consumer_truncated=false;
};
struct CPythonIntrospectionPrimitiveSummaryFact {
    std::string kind,value,hex;
    std::uint64_t length=0,bit_length=0;
    std::int64_t sign=0;
    bool bool_value=false,bool_value_present=false,truncated=false,value_omitted=false;
};
struct CPythonIntrospectionSampleFact {
    bool has_key=false;
    CPythonIntrospectionPrimitiveSummaryFact key,value;
};
struct CPythonIntrospectionValueSummaryFact {
    std::string kind,value,hex,address,type,name,qualname,module,file,package,loader_type,origin,backing,code_identity,filename;
    std::uint64_t length=0,bit_length=0,count=0,sample_count=0,sample_scan_count=0,globals_count=0;
    std::int64_t first_line=0;
    std::int64_t sign=0;
    bool bool_value=false,bool_value_present=false,truncated=false,value_omitted=false,sample_scan_truncated=false,partial=false,unsupported=false;
    bool file_present=false,package_present=false,origin_present=false,consumer_sample_truncated=false;
    std::vector<CPythonIntrospectionSampleFact> primitive_sample;
};
struct CPythonIntrospectionVariableFact {
    std::string name,type,summary_kind;
    std::uint64_t summary_count=0,sample_count=0,sample_scan_count=0;
    bool summary_truncated=false,sample_scan_truncated=false;
    CPythonIntrospectionValueSummaryFact summary;
};
struct CPythonIntrospectionModuleFact {
    std::string name,file,package,loader_type,origin,backing,address,state,type;
    std::uint64_t globals_count=0;
    bool file_present=false,package_present=false,loader_type_present=false,origin_present=false;
};
struct CPythonIntrospectionFrameFact {
    std::uint32_t depth=0;
    std::string frame_identity,caller_frame_identity;
    std::int64_t line=0,lasti=0;
    std::string code_identity,code_name,code_qualname,filename;
    std::int64_t first_line=0,code_argcount=0,code_posonlyargcount=0,code_kwonlyargcount=0,code_nlocals=0,code_stacksize=0,code_flags=0;
    CPythonIntrospectionStringListFact code_names,code_varnames,code_freevars,code_cellvars;
    std::vector<CPythonIntrospectionVariableFact> locals,globals;
    std::uint64_t locals_count=0,globals_count=0,locals_scanned=0,globals_scanned=0;
    bool locals_truncated=false,globals_truncated=false,locals_scan_truncated=false,globals_scan_truncated=false;
    bool locals_consumer_truncated=false,globals_consumer_truncated=false;
    std::string locals_count_semantics,globals_count_semantics;
};
struct CPythonIntrospectionEventFact {
    std::string event,state,transport,hook,trigger,hook_scope,exception_type;
    bool behavior_modified=false,behavior_modified_present=false;
    std::uint64_t thread_ident=0,thread_native_id=0;
    std::string thread_name,interpreter_runtime,interpreter_executable,interpreter_identity_kind,interpreter_identity,interpreter_modules_identity;
    std::vector<CPythonIntrospectionFrameFact> frames;
    bool frames_truncated=false,frames_consumer_truncated=false,partial_reasons_consumer_truncated=false;
    std::vector<std::string> partial_reasons;
};
struct CPythonIntrospectionRuntimeFact {
    std::string version,executable,prefix,base_prefix;
    std::uint64_t sys_path_count=0,module_count=0,sys_path_scanned=0,modules_scanned=0;
    bool sys_path_truncated=false,modules_truncated=false,sys_path_scan_truncated=false,modules_scan_truncated=false;
    bool sys_path_unsupported=false,modules_unsupported=false,sys_path_consumer_truncated=false,modules_consumer_truncated=false;
    std::string sys_path_count_semantics,module_count_semantics;
    std::vector<std::string> sys_path_items;
    std::vector<CPythonIntrospectionModuleFact> modules;
};
struct CPythonIntrospectionBudgets {
    std::size_t max_line_bytes=2u*1024u*1024u,max_json_depth=64,max_json_nodes=65536,max_records=256,max_events=128,max_frames_per_event=32,max_variables_per_scope=64,max_partial_reasons=32;
    std::size_t max_code_items_per_list=64,max_runtime_modules=256,max_sys_path_items=128,max_container_samples_per_variable=8;
};
struct CPythonIntrospectionReport {
    bool attempted=false,protocol_valid=false;
    std::uint32_t schema=0;
    std::string state="NOT_ATTEMPTED",runtime_state="NOT_ATTEMPTED",parser_state="NOT_ATTEMPTED",transport,error;
    std::uint64_t records_seen=0,records_retained=0;
    bool records_truncated=false,events_consumer_truncated=false;
    std::uint64_t hook_armed_count=0,hook_triggered_count=0,frame_snapshot_count=0;
    CPythonIntrospectionRuntimeFact runtime;
    std::vector<CPythonIntrospectionEventFact> events;
};
CPythonIntrospectionReport cpython_introspection_controller_state(std::string state,std::string transport={},std::string error={});
bool parse_cpython_introspection_jsonl(const std::filesystem::path& path,CPythonIntrospectionReport& report,std::string& error,const CPythonIntrospectionBudgets& budgets={});
}
