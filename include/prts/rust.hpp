#pragma once
#include "prts/finding.hpp"
#include "prts/pe.hpp"
#include "prts/elf.hpp"
#include <cstdint>
#include <span>
#include <string>
#include <vector>
namespace prts {
struct RustSymbol { std::uint64_t va=0,rva=0,size=0; std::string mangled,demangled; };
struct RustCrateHint { std::string crate,version,path; };
struct RustInfo {
    bool valid=false;
    bool symbol_table_present=false;
    std::string rustc_source_hash;
    std::vector<std::string> std_source_paths;
    std::vector<RustCrateHint> crates;
    std::vector<RustSymbol> symbols;
    std::string error;
};
RustInfo detect_rust(std::span<const std::uint8_t>data,const PeInfo&pe,const ElfInfo&elf);
Finding rust_finding(const RustInfo&info);
}
