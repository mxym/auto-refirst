#include "prts/sha1.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
namespace prts { namespace {
inline std::uint32_t rol(std::uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
void block(std::array<std::uint32_t,5>&h,const std::uint8_t*b){std::uint32_t w[80];for(int i=0;i<16;i++)w[i]=(std::uint32_t(b[i*4])<<24)|(std::uint32_t(b[i*4+1])<<16)|(std::uint32_t(b[i*4+2])<<8)|b[i*4+3];for(int i=16;i<80;i++)w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);auto a=h[0],c=h[2],d=h[3],e=h[4],bb=h[1];for(int i=0;i<80;i++){std::uint32_t f,k;if(i<20){f=(bb&c)|((~bb)&d);k=0x5a827999;}else if(i<40){f=bb^c^d;k=0x6ed9eba1;}else if(i<60){f=(bb&c)|(bb&d)|(c&d);k=0x8f1bbcdc;}else{f=bb^c^d;k=0xca62c1d6;}auto t=rol(a,5)+f+e+k+w[i];e=d;d=c;c=rol(bb,30);bb=a;a=t;}h[0]+=a;h[1]+=bb;h[2]+=c;h[3]+=d;h[4]+=e;}
}
namespace {
struct Sha1Stream {
    std::array<std::uint32_t,5> h{0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
    std::array<std::uint8_t,64> buf{};std::size_t used=0;std::uint64_t bytes=0;
    void update(std::span<const std::uint8_t>d){bytes+=d.size();std::size_t p=0;while(p<d.size()){auto n=std::min<std::size_t>(64-used,d.size()-p);std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(p),n,buf.begin()+static_cast<std::ptrdiff_t>(used));used+=n;p+=n;if(used==64){block(h,buf.data());used=0;}}}
    std::array<std::uint8_t,20> finish(){auto bits=bytes*8;buf[used++]=0x80;if(used>56){while(used<64)buf[used++]=0;block(h,buf.data());used=0;}while(used<56)buf[used++]=0;for(int i=7;i>=0;--i)buf[used++]=std::uint8_t(bits>>(i*8));block(h,buf.data());std::array<std::uint8_t,20>o{};for(int i=0;i<5;i++){o[i*4]=static_cast<std::uint8_t>(h[i]>>24);o[i*4+1]=static_cast<std::uint8_t>(h[i]>>16);o[i*4+2]=static_cast<std::uint8_t>(h[i]>>8);o[i*4+3]=static_cast<std::uint8_t>(h[i]);}return o;}
};
}
std::array<std::uint8_t,20> sha1_bytes(std::span<const std::uint8_t>d){Sha1Stream s;s.update(d);return s.finish();}
std::array<std::uint8_t,20> sha1_parts(const std::vector<std::span<const std::uint8_t>>&parts){Sha1Stream s;for(auto p:parts)s.update(p);return s.finish();}
std::array<std::uint8_t,20> hmac_sha1(std::span<const std::uint8_t>key,std::span<const std::uint8_t>data){std::array<std::uint8_t,64>k{};if(key.size()>64){auto x=sha1_bytes(key);std::copy(x.begin(),x.end(),k.begin());}else std::copy(key.begin(),key.end(),k.begin());std::array<std::uint8_t,64>ip{},op{};for(int i=0;i<64;i++){ip[i]=k[i]^0x36;op[i]=k[i]^0x5c;}std::vector<std::uint8_t>a;a.reserve(64+data.size());a.insert(a.end(),ip.begin(),ip.end());a.insert(a.end(),data.begin(),data.end());auto inner=sha1_bytes(a);std::vector<std::uint8_t>b;b.reserve(84);b.insert(b.end(),op.begin(),op.end());b.insert(b.end(),inner.begin(),inner.end());return sha1_bytes(b);}
void pbkdf2_hmac_sha1(std::string_view password,std::string_view salt,std::uint32_t iterations,std::span<std::uint8_t>out){auto k=std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(password.data()),password.size());std::size_t done=0;for(std::uint32_t blockid=1;done<out.size();blockid++){std::vector<std::uint8_t>s(reinterpret_cast<const std::uint8_t*>(salt.data()),reinterpret_cast<const std::uint8_t*>(salt.data())+salt.size());s.push_back(std::uint8_t(blockid>>24));s.push_back(std::uint8_t(blockid>>16));s.push_back(std::uint8_t(blockid>>8));s.push_back(std::uint8_t(blockid));auto u=hmac_sha1(k,s),t=u;for(std::uint32_t i=1;i<iterations;i++){u=hmac_sha1(k,u);for(std::size_t j=0;j<t.size();j++)t[j]^=u[j];}auto n=std::min<std::size_t>(t.size(),out.size()-done);std::copy_n(t.begin(),n,out.begin()+static_cast<std::ptrdiff_t>(done));done+=n;}}
}
