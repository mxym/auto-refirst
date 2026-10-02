#include "prts/pe_debug.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {
void put32(std::vector<std::uint8_t>& d,std::size_t off,std::uint32_t v){
    for(std::size_t i=0;i<4;++i)d[off+i]=static_cast<std::uint8_t>(v>>(8*i));
}
prts::PeInfo pe_info(){
    prts::PeInfo pe;pe.valid=true;pe.pe64=true;pe.headers_size=0x200;
    pe.debug.present=true;pe.debug.rva=0x1000;pe.debug.size=28;
    prts::PeSection s;s.rva=0x1000;s.vsize=0x1000;s.raw_offset=0x100;s.raw_size=0x1000;pe.sections.push_back(s);
    return pe;
}
}

int main(){
    auto pe=pe_info();std::vector<std::uint8_t> d(0x300,0);
    const std::size_t dir=0x100,payload=0x140;put32(d,dir+12,2);put32(d,dir+16,24+10+1+8);put32(d,dir+24,payload);
    std::memcpy(d.data()+payload,"RSDS",4);std::memcpy(d.data()+payload+24,"normal.pdb",10);d[payload+34]=0;
    const std::size_t tail=payload+35;d[tail]=0x7f;d[tail+1]='E';d[tail+2]='L';d[tail+3]='F';
    auto suspicious=prts::detect_pe_debug_payload(d,pe);
    if(suspicious.size()!=1||suspicious.front().state!="CONFIRMED"||suspicious.front().variant!="CodeView trailing embedded ELF")return 1;
    if(suspicious.front().fields["embedded_file_offset"]!=std::to_string(tail)||
       suspicious.front().fields["embedded_size"]!="4"||suspicious.front().ranges.size()!=2||
       suspicious.front().ranges.back().offset!=tail||suspicious.front().ranges.back().size!=4)return 4;
    put32(d,dir+16,24+10+1+16);
    std::fill(d.begin()+tail,d.begin()+tail+16,std::uint8_t(0));
    auto padding=prts::detect_pe_debug_payload(d,pe);
    if(!padding.empty())return 2;
    put32(d,dir+16,24+10+1);d[tail]=0;
    auto ordinary=prts::detect_pe_debug_payload(d,pe);
    if(!ordinary.empty())return 3;
    put32(d,dir+12,4);put32(d,dir+16,8);put32(d,dir+24,payload);
    std::fill(d.begin()+payload,d.begin()+payload+8,std::uint8_t(0));
    const std::uint8_t zip_magic[4]={'P','K',3,4};std::memcpy(d.data()+payload+2,zip_magic,4);
    auto non_codeview=prts::detect_pe_debug_payload(d,pe);
    if(non_codeview.size()!=1||non_codeview.front().fields["embedded_file_offset"]!=std::to_string(payload+2)||
       non_codeview.front().ranges.back().offset!=payload+2||non_codeview.front().ranges.back().size!=4)return 8;
    put32(d,dir+12,2);put32(d,dir+16,24+10+1);std::memcpy(d.data()+payload,"RSDS",4);
    std::memcpy(d.data()+payload+24,"normal.pdb",10);d[payload+34]=0;
    // Some linkers retain AddressOfRawData while leaving PointerToRawData
    // unset.  Recover the file-backed RVA, but never treat offset zero as a
    // debug payload when neither coordinate is present.
    put32(d,dir+16,24+10+1+4);put32(d,dir+20,0x1040);put32(d,dir+24,0);
    const std::uint8_t elf_magic[4]={0x7f,'E','L','F'};std::memcpy(d.data()+tail,elf_magic,4);
    auto recovered=prts::detect_pe_debug_payload(d,pe);
    if(recovered.size()!=1||recovered.front().fields["payload_file_offset"]!=std::to_string(tail)||
       recovered.front().fields["embedded_file_offset"]!=std::to_string(tail))return 5;
    put32(d,dir+20,0);auto no_coordinates=prts::detect_pe_debug_payload(d,pe);
    if(!no_coordinates.empty())return 6;
    d.resize(0x2200);put32(d,dir+16,8);put32(d,dir+20,0x1ffc);put32(d,dir+24,0);
    auto spills_section=prts::detect_pe_debug_payload(d,pe);
    if(!spills_section.empty())return 7;
    std::cout<<"PASS\n";return 0;
}
