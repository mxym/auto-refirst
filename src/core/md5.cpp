#include "prts/md5.hpp"
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <vector>
namespace prts {
namespace {
inline std::uint32_t rotl(std::uint32_t x,std::uint32_t n){return (x<<n)|(x>>(32-n));}
constexpr std::array<std::uint32_t,64> S={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
const std::array<std::uint32_t,64>& K(){static const auto k=[](){std::array<std::uint32_t,64>a{};for(int i=0;i<64;i++)a[i]=static_cast<std::uint32_t>(std::floor(std::abs(std::sin(i+1))*4294967296.0));return a;}();return k;}
}
std::array<std::uint8_t,16> md5(std::span<const std::uint8_t>d){std::vector<std::uint8_t>m(d.begin(),d.end());std::uint64_t bits=std::uint64_t(d.size())*8;m.push_back(0x80);while(m.size()%64!=56)m.push_back(0);for(int i=0;i<8;i++)m.push_back(std::uint8_t(bits>>(8*i)));std::uint32_t a0=0x67452301,b0=0xefcdab89,c0=0x98badcfe,d0=0x10325476;for(std::size_t o=0;o<m.size();o+=64){std::uint32_t M[16];for(int i=0;i<16;i++)M[i]=std::uint32_t(m[o+i*4])|(std::uint32_t(m[o+i*4+1])<<8)|(std::uint32_t(m[o+i*4+2])<<16)|(std::uint32_t(m[o+i*4+3])<<24);auto A=a0,B=b0,C=c0,D=d0;for(std::uint32_t i=0;i<64;i++){std::uint32_t F,g;if(i<16){F=(B&C)|((~B)&D);g=i;}else if(i<32){F=(D&B)|((~D)&C);g=(5*i+1)%16;}else if(i<48){F=B^C^D;g=(3*i+5)%16;}else{F=C^(B|(~D));g=(7*i)%16;}F+=A+K()[i]+M[g];A=D;D=C;C=B;B+=rotl(F,S[i]);}a0+=A;b0+=B;c0+=C;d0+=D;}std::array<std::uint8_t,16>out{};std::uint32_t h[4]={a0,b0,c0,d0};for(int i=0;i<4;i++)for(int j=0;j<4;j++)out[i*4+j]=std::uint8_t(h[i]>>(8*j));return out;}
}
