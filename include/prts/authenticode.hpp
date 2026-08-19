#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct AuthenticodeCertificateInfo {
    std::string subject,issuer,serial,not_before,not_after,sha256_fingerprint,role_hint;
    bool matched_primary_signer=false,extensions_present=false,extended_key_usage_present=false,extended_key_usage_critical=false;
    bool eku_code_signing=false,eku_time_stamping=false,basic_constraints_present=false,basic_constraints_ca=false;
    std::vector<std::string> extended_key_usage_oids;
};
struct AuthenticodeTimestampInfo {
    std::string kind,state,gen_time,policy,message_imprint_algorithm,message_imprint,serial;
    std::string computed_signature_value_imprint,signer_subject,signer_issuer,signer_serial,signer_certificate_sha256,signer_role_state,error;
    bool message_imprint_binding_checked=false,message_imprint_matches_signature_value=false,signer_certificate_matched=false;
    bool signer_eku_time_stamping=false,signer_extended_key_usage_critical=false;
};
struct AuthenticodePageHashEntry {
    std::uint32_t signed_file_offset=0,current_file_offset=0,current_rva=0,current_file_bytes=0;
    std::string region,signed_digest,computed_digest;
    bool offset_match=false,digest_match=false,match=false,terminator=false;
};
struct AuthenticodeSignerInfo {
    std::string identifier_type,issuer,serial,digest_algorithm,signature_algorithm,signing_time,signature_value_sha256;
    bool certificate_matched=false;
    int certificate_index=-1;
    std::uint32_t countersignature_count=0,rfc3161_timestamp_count=0,signature_value_size=0;
    std::vector<AuthenticodeTimestampInfo> timestamps;
};
struct AuthenticodeSignatureInfo {
    std::uint64_t certificate_offset=0,certificate_size=0;
    std::uint16_t revision=0,certificate_type=0;
    std::uint32_t nesting_depth=0,nested_signature_count=0;
    int parent_signature_index=-1;
    std::string source="WIN_CERTIFICATE",nested_signature_error;
    bool pkcs7=false,spc_indirect_data=false,signer_infos_present=false,digest_extracted=false,digest_match=false;
    bool page_hashes_present=false,page_hashes_verified=false;
    std::uint32_t signer_info_count=0,page_size=0,page_hash_mismatch_count=0;
    std::vector<AuthenticodeCertificateInfo> certificates;
    std::vector<AuthenticodeSignerInfo> signers;
    std::vector<AuthenticodePageHashEntry> page_hashes;
    std::string signer_metadata_state,signer_metadata_error;
    std::string page_hash_algorithm,page_hash_state,page_hash_error;
    std::string digest_algorithm,signed_digest,computed_digest,state,error;
};
struct AuthenticodeInfo {
    bool present=false,certificate_table_valid=false;
    std::uint64_t certificate_table_offset=0,certificate_table_size=0;
    std::uint64_t checksum_offset=0,certificate_directory_entry_offset=0;
    std::uint64_t headers_size=0,last_section_end=0,covered_bytes=0;
    std::uint64_t post_section_bytes=0,pre_certificate_unhashed_bytes=0,post_certificate_unhashed_bytes=0;
    std::vector<AuthenticodeSignatureInfo> signatures;
    std::string state,error;
};
AuthenticodeInfo analyze_authenticode(std::span<const std::uint8_t> data,const PeInfo& pe);
Finding authenticode_finding(const AuthenticodeInfo& info);
}
