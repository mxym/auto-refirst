#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct CryptoKeyUse {
    std::string algorithm,state;
    std::uint32_t function_rva=0,function_end_rva=0,callsite_rva=0;
    std::string key_arg,key_length_arg,key_source,key_section,key_hex;
    std::string iv_arg,iv_length_arg,iv_source,iv_section,iv_hex,api_source,mode,operation;
    bool key_resolved=false,key_length_resolved=false,iv_resolved=false,iv_length_resolved=false;
    std::uint32_t key_rva=0,key_size=0,iv_rva=0,iv_size=0;
    std::uint64_t key_length=0,iv_length=0;
    std::uint32_t fixed_key_offsets=0,dynamic_key_accesses=0;
    std::uint32_t shift4=0,shift5=0,xor_ops=0,addsub_ops=0,back_edges=0,delta_constants=0;
    std::vector<std::string> evidence;
};
struct CryptoInfo {
    bool attempted=false,valid=false;
    std::vector<CryptoKeyUse> uses;
};
bool has_crypto_api_imports(const PeInfo& pe);
CryptoInfo detect_crypto_key_uses(std::span<const std::uint8_t> data,const PeInfo& pe,const StaticScanReport& scan);
Finding crypto_finding(const CryptoInfo& info);
}
