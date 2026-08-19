#pragma once
#include "prts/finding.hpp"
#include "prts/implicit_exec.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace prts {
struct JvmFieldInfo {
    std::uint16_t access_flags=0;
    std::string name,descriptor,type_name,generic_signature,constant_value;
    std::vector<std::string> annotations;
};
struct JvmMethodInfo {
    std::uint16_t access_flags=0,max_stack=0,max_locals=0;
    std::uint64_t code_offset=0,code_size=0;
    std::uint32_t line_number_count=0;
    std::string name,descriptor,signature,return_type,generic_signature;
    std::vector<std::string> parameter_types,parameter_names,exceptions,annotations;
};
struct JvmReference {
    std::string kind,owner,name,descriptor,signature;
};
struct JvmClassInfo {
    bool candidate=false,valid=false,preview=false,kotlin_metadata=false,descriptor_parse_complete=true;
    std::uint16_t minor=0,major=0,access_flags=0;
    std::uint32_t constant_pool_count=0,bootstrap_method_count=0,invokedynamic_count=0,dynamic_count=0;
    std::uint32_t inner_class_count=0,nest_member_count=0,permitted_subclass_count=0,record_component_count=0;
    std::string java_release,class_name,super_name,source_file,generic_signature,module_name,error;
    std::uint64_t error_offset=0;
    std::vector<std::string> interfaces,string_constants,annotations,obfuscation_hints,anomalies;
    std::vector<JvmFieldInfo> fields;
    std::vector<JvmMethodInfo> methods;
    std::vector<JvmReference> references;
    ImplicitExecutionInfo implicit_exec;
};
struct JvmExtractResult {
    bool success=false;
    std::filesystem::path methods_csv,fields_csv,references_csv;
    std::uint64_t method_count=0,field_count=0,reference_count=0;
    std::string error;
};
struct JarEntryInfo {
    std::string name;
    std::uint64_t compressed_size=0,uncompressed_size=0;
    std::uint32_t crc32=0;
    std::uint16_t method=0;
    bool directory=false,encrypted=false,supported=false,safe_path=false,symlink=false,class_file=false,nested_archive=false;
};
struct JarInfo {
    bool candidate=false,valid=false,multi_release=false,spring_boot=false,fat_jar=false,zip64=false;
    std::uint32_t entry_count=0,class_count=0,nested_archive_count=0,native_library_count=0;
    std::uint64_t total_uncompressed=0,total_compressed=0;
    std::string variant,main_class,automatic_module_name,implementation_version,error;
    std::vector<JarEntryInfo> entries;
    std::vector<std::string> manifest_lines,interesting_entries,anomalies;
};
struct JarExtractResult {
    bool success=false,budget_exhausted=false,analysis_only=false;
    std::filesystem::path output_dir;
    std::uint64_t file_count=0,output_bytes=0,omitted_count=0,omitted_bytes=0;
    std::vector<std::filesystem::path> files;
    std::vector<std::string> warnings;
    std::string error;
};

JvmClassInfo parse_jvm_class(std::span<const std::uint8_t>data);
Finding jvm_class_finding(const JvmClassInfo&info);
JvmExtractResult extract_jvm_maps(const JvmClassInfo&info,const std::filesystem::path&methods_csv);
JarInfo detect_jar(std::span<const std::uint8_t>data,const std::filesystem::path&path={});
Finding jar_finding(const JarInfo&info);
JarExtractResult extract_jar(std::span<const std::uint8_t>data,const JarInfo&info,const std::filesystem::path&output_dir,
                             std::uint64_t max_output_bytes=512ull*1024*1024,std::uint32_t max_output_files=100000,bool analysis_only=false);
}
