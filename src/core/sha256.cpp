#include "prts/sha256.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <span>
#include <vector>
namespace prts {
namespace {
constexpr std::array<std::uint32_t,64> K={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
inline std::uint32_t rr(std::uint32_t x,int n){return (x>>n)|(x<<(32-n));}
struct Sha256 {
 std::array<std::uint32_t,8> h{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 std::array<std::uint8_t,64> buf{}; std::size_t used=0; std::uint64_t bytes=0;
 void block(const std::uint8_t* p){
  std::uint32_t w[64]; for(int i=0;i<16;i++) w[i]=(std::uint32_t(p[i*4])<<24)|(std::uint32_t(p[i*4+1])<<16)|(std::uint32_t(p[i*4+2])<<8)|p[i*4+3];
  for(int i=16;i<64;i++){auto s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3);auto s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+s0+w[i-7]+s1;}
  auto a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
  for(int i=0;i<64;i++){auto S1=rr(e,6)^rr(e,11)^rr(e,25);auto ch=(e&f)^((~e)&g);auto t1=hh+S1+ch+K[i]+w[i];auto S0=rr(a,2)^rr(a,13)^rr(a,22);auto maj=(a&b)^(a&c)^(b&c);auto t2=S0+maj;hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
 }
 void update(const std::uint8_t* p,std::size_t n){bytes+=n;while(n){auto take=std::min(n,64-used);std::copy(p,p+take,buf.begin()+static_cast<std::ptrdiff_t>(used));used+=take;p+=take;n-=take;if(used==64){block(buf.data());used=0;}}}
 std::string finish(){auto bits=bytes*8;buf[used++]=0x80;if(used>56){while(used<64)buf[used++]=0;block(buf.data());used=0;}while(used<56)buf[used++]=0;for(int i=7;i>=0;i--)buf[used++]=std::uint8_t(bits>>(i*8));block(buf.data());std::ostringstream o;o<<std::hex<<std::setfill('0');for(auto x:h)o<<std::setw(8)<<x;return o.str();}
};
}
std::string sha256_bytes(std::span<const std::uint8_t> data){Sha256 s;if(!data.empty())s.update(data.data(),data.size());return s.finish();}
std::string sha256_parts(const std::vector<std::span<const std::uint8_t>>&parts){Sha256 s;for(auto p:parts)if(!p.empty())s.update(p.data(),p.size());return s.finish();}
std::string sha256_file(const std::filesystem::path& p){std::ifstream f(p,std::ios::binary);if(!f)return{};Sha256 s;std::array<std::uint8_t,1<<16>b{};while(f){f.read(reinterpret_cast<char*>(b.data()),b.size());auto n=f.gcount();if(n>0)s.update(b.data(),static_cast<std::size_t>(n));}return s.finish();}
}
