#include "prts/pe_debug.hpp"
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
    put32(d,dir+16,24+10+1);d[tail]=0;
    auto ordinary=prts::detect_pe_debug_payload(d,pe);
    if(!ordinary.empty())return 2;
    std::cout<<"PASS\n";return 0;
}
