#include "prts/nuitka.hpp"
#include "prts/zstd_wrap.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <cmath>
#include <iomanip>
#include <limits>
#include <sstream>
#include <optional>
#include <string_view>
namespace prts { namespace {
std::uint64_t u64(std::span<const std::uint8_t>d,std::size_t o){if(o+8>d.size())return 0;std::uint64_t v=0;for(int i=7;i>=0;--i)v=(v<<8)|d[o+i];return v;}
std::uint32_t u32(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);}
bool safe_name(std::string_view n){if(n.empty()||n.size()>4096)return false;if(n.find("..")!=std::string_view::npos)return false;std::size_t printable=0;for(unsigned char c:n){if(c==0)return false;if(c>=0x20&&c<0x7f)++printable;}return printable*100/n.size()>80;}
std::optional<std::pair<std::string,std::size_t>> read_name8(std::span<const std::uint8_t>d,std::size_t p){auto q=p;while(q<d.size()&&q-p<4096&&d[q])++q;if(q>=d.size()||q-p>=4096)return{};std::string n(reinterpret_cast<const char*>(d.data()+p),q-p);return std::pair{n,q+1};}
std::optional<std::pair<std::string,std::size_t>> read_name16(std::span<const std::uint8_t>d,std::size_t p){std::string n;for(std::size_t q=p;q+1<d.size()&&n.size()<2048;q+=2){auto c=std::uint16_t(d[q])|(std::uint16_t(d[q+1])<<8);if(!c)return std::pair{n,q+2};if(c>0x7f)return{};n.push_back(char(c));}return{};}
struct ParsedArchive {bool ok=false,win=false,crc=false,posix_flags=false;std::vector<NuitkaEntry> entries;std::size_t consumed=0;int score=0;};
ParsedArchive parse_archive(std::span<const std::uint8_t>d,bool win,bool flags,bool crc){ParsedArchive r;r.win=win;r.crc=crc;r.posix_flags=flags;std::size_t p=0;for(std::size_t count=0;count<100000;count++){auto nr=win?read_name16(d,p):read_name8(d,p);if(!nr)return r;auto name=nr->first;p=nr->second;if(name.empty()){r.ok=!r.entries.empty();r.consumed=p;r.score=int(r.entries.size())*100+(p==d.size()?500:0);return r;}if(!safe_name(name))return r;std::uint8_t fl=0;if(flags){if(p>=d.size())return r;fl=d[p++];if(fl>3)return r;}if(p+8>d.size())return r;auto sz=u64(d,p);p+=8;if(crc){if(p+4>d.size())return r;p+=4;}if(sz>d.size()-p)return r;NuitkaEntry e;e.name=std::move(name);e.size=sz;e.data_offset=p;e.flags=fl;r.entries.push_back(std::move(e));p+=std::size_t(sz);}return r;}
ParsedArchive best_archive(std::span<const std::uint8_t>d,const PeInfo&pe,const ElfInfo&elf){ParsedArchive best;std::vector<ParsedArchive> all;bool likelywin=pe.valid;bool likelyposix=elf.valid;auto tryone=[&](bool w,bool f,bool c){auto x=parse_archive(d,w,f,c);if(x.ok&&x.score>best.score)best=std::move(x);};if(likelywin){tryone(true,false,false);tryone(true,false,true);}if(likelyposix){tryone(false,true,false);tryone(false,true,true);}tryone(false,false,false);tryone(false,false,true);tryone(true,false,false);tryone(true,false,true);return best;}
std::vector<NuitkaConstantBlock> parse_constant_directory(std::span<const std::uint8_t>d,std::size_t start,std::uint64_t&total){
    std::vector<NuitkaConstantBlock> out;total=0;std::size_t p=start;
    for(std::size_t count=0;count<10000&&p<d.size();++count){
        auto h=p;auto q=p;
        while(q<d.size()&&q-p<512&&d[q]){auto c=d[q];if(c<0x20||c>0x7e)return out;++q;}
        if(q>=d.size()||q-p>=512)return out;
        std::string name(reinterpret_cast<const char*>(d.data()+p),q-p);p=q+1;
        if(p+4>d.size())return out;
        auto sz=u32(d,p);p+=4;if(!sz||sz>d.size()-p)return out;
        out.push_back({std::move(name),h,p,sz});p+=sz;
        if(p>=d.size())break;
        // If the next header is not plausible, this was the final valid block.
        auto t=p;while(t<d.size()&&t-p<512&&d[t]&&d[t]>=0x20&&d[t]<=0x7e)++t;
        if(t>=d.size()||t-p>=512||t+5>d.size())break;
        auto nsz=u32(d,t+1);if(!nsz||nsz>d.size()-(t+5))break;
    }
    if(!out.empty())total=p-start;
    return out;
}
std::optional<std::pair<std::uint64_t,std::vector<NuitkaConstantBlock>>> find_constant_blob(std::span<const std::uint8_t>d){
    constexpr std::string_view mark=".bytecode";std::size_t pos=0;
    while(pos<d.size()){
        auto it=std::search(d.begin()+static_cast<std::ptrdiff_t>(pos),d.end(),mark.begin(),mark.end());if(it==d.end())break;
        auto o=std::size_t(it-d.begin());pos=o+1;
        if(o+mark.size()+5>d.size()||d[o+mark.size()]!=0)continue;
        std::uint64_t total=0;auto blocks=parse_constant_directory(d,o,total);
        if(blocks.size()>=2&&blocks.front().name==".bytecode"&&blocks.front().size>1024)return std::pair{total,std::move(blocks)};
    }
    return{};
}
enum class ConstEncoding { Varint, LegacyLong32, LegacyLong64 };
struct ConstReader {
    std::span<const std::uint8_t> d;
    std::size_t p=0;
    NuitkaDecodedBlock *out=nullptr;
    int depth=0;
    ConstEncoding encoding=ConstEncoding::Varint;
    bool fail(std::string msg){if(out&&out->error.empty()){out->error=std::move(msg);out->error_offset=p;}return false;}
    bool need(std::size_t n){return n<=d.size()-std::min(p,d.size())||fail("constant blob truncated");}
    bool legacy()const{return encoding!=ConstEncoding::Varint;}
    std::size_t legacy_long_width()const{return encoding==ConstEncoding::LegacyLong64?8u:4u;}
    std::uint8_t byte(){if(!need(1))return 0;return d[p++];}
    std::uint16_t word(){if(!need(2))return 0;auto v=static_cast<std::uint16_t>(std::uint16_t(d[p])|(std::uint16_t(d[p+1])<<8));p+=2;return v;}
    std::uint32_t fixed32(){if(!need(4))return 0;auto v=u32(d,p);p+=4;return v;}
    std::uint64_t fixed64(){if(!need(8))return 0;auto v=u64(d,p);p+=8;return v;}
    std::int64_t signed_fixed(std::size_t width){
        std::uint64_t v=width==8?fixed64():fixed32();if(out&&!out->error.empty())return 0;
        if(width==4){if(v&0x80000000ull)return -1-static_cast<std::int64_t>((~v)&0xffffffffull);return static_cast<std::int64_t>(v);}
        if(v&(1ull<<63))return -1-static_cast<std::int64_t>(~v);
        return static_cast<std::int64_t>(v);
    }
    std::uint64_t var(){std::uint64_t r=0,f=1;for(int i=0;i<10;i++){auto v=byte();if(out&&!out->error.empty())return 0;if(v&0x7f){if((v&0x7f)>std::numeric_limits<std::uint64_t>::max()/f){fail("constant varint overflow");return 0;}r+=std::uint64_t(v&0x7f)*f;}if(v<128)return r;if(f>(std::numeric_limits<std::uint64_t>::max()>>7)){fail("constant varint overflow");return 0;}f<<=7;}fail("constant varint too long");return 0;}
    std::uint64_t size_value(){return legacy()?fixed32():var();}
    std::string cstr(std::size_t max=1<<20){auto q=p;while(q<d.size()&&q-p<max&&d[q])++q;if(q>=d.size()||q-p>=max){fail("unterminated constant string");return{};}std::string x(reinterpret_cast<const char*>(d.data()+p),q-p);p=q+1;return x;}
    std::string rawstr(std::size_t n){if(n>d.size()-p){fail("constant string length out of range");return{};}std::string x(reinterpret_cast<const char*>(d.data()+p),n);p+=n;return x;}
};
std::string repr_text(std::string_view s){std::string r="\"";std::size_t shown=0;for(unsigned char c:s){if(shown++>=512){r+="...";break;}if(c=='\\')r+="\\\\";else if(c=='\"')r+="\\\"";else if(c=='\n')r+="\\n";else if(c=='\r')r+="\\r";else if(c=='\t')r+="\\t";else if(c>=0x20&&c<0x7f)r+=char(c);else{char b[5];std::snprintf(b,sizeof(b),"\\x%02x",c);r+=b;}}return r+'\"';}
std::string repr_bytes(std::string_view s){return "b"+repr_text(s);}
std::string join_values(std::string_view open,std::string_view close,const std::vector<std::string>&v){std::string r(open);std::size_t n=0;for(const auto&x:v){if(n++)r+=", ";if(r.size()+x.size()>2048){r+="...";break;}r+=x;}r+=close;return r;}
bool printable_hint(std::string_view s){if(s.size()<3||s.size()>4096)return false;std::size_t ok=0;for(unsigned char c:s)if(c>=0x20&&c<0x7f)++ok;return ok*100/s.size()>=85;}
struct DVal { std::string repr; std::optional<std::string> str; };
bool decode_value(ConstReader&r,DVal&v,std::optional<DVal> previous);
bool decode_seq(ConstReader&r,std::size_t n,std::vector<DVal>&vals){if(n>1000000)return r.fail("constant sequence count unreasonable");vals.reserve(n);std::optional<DVal>prev;for(std::size_t i=0;i<n;i++){DVal v;if(!decode_value(r,v,prev))return false;vals.push_back(v);prev=v;}return true;}
std::string vals_repr(const std::vector<DVal>&v,std::string_view a,std::string_view b){std::vector<std::string>x;x.reserve(v.size());for(const auto&q:v)x.push_back(q.repr);return join_values(a,b,x);}
bool decode_code(ConstReader&r,DVal&v){if(r.legacy())return r.fail("code-object tag is not valid in legacy fixed-width constant streams");if(r.depth>128)return r.fail("Nuitka constant nesting too deep");NuitkaCodeObjectInfo ci;ci.flags=r.var();if(!r.out->error.empty())return false;DVal name;if(!decode_value(r,name,std::nullopt))return false;ci.name=name.str.value_or(name.repr);ci.line=static_cast<std::uint32_t>(r.var()+1);DVal args;if(!decode_value(r,args,std::nullopt))return false;ci.args=args.repr;ci.arg_count=static_cast<std::uint32_t>(r.var());constexpr std::uint64_t QUAL=1,FREE=2,KW=4,POS=8;if(ci.flags&QUAL){DVal q;if(!decode_value(r,q,std::nullopt))return false;ci.qualname=q.str.value_or(q.repr)+"."+ci.name;}else ci.qualname=ci.name;if(ci.flags&FREE){DVal q;if(!decode_value(r,q,std::nullopt))return false;ci.free_vars=q.repr;}if(ci.flags&KW)ci.kw_only=static_cast<std::uint32_t>(r.var()+1);if(ci.flags&POS)ci.pos_only=static_cast<std::uint32_t>(r.var()+1);if(!r.out->error.empty())return false;r.out->code_objects.push_back(ci);std::ostringstream o;o<<"code(name="<<repr_text(ci.name)<<", line="<<ci.line<<", argc="<<ci.arg_count<<", flags=0x"<<std::hex<<ci.flags<<std::dec<<")";v.repr=o.str();return true;}
bool decode_value(ConstReader&r,DVal&v,std::optional<DVal> previous){
    if(r.depth++>128){--r.depth;return r.fail("Nuitka constant nesting too deep");}
    auto done=[&](bool ok){--r.depth;return ok;};
    auto save_string=[&](const std::string&x){v.str=x;if(r.out&&printable_hint(x)&&r.out->string_values.size()<4096)r.out->string_values.push_back(x);};
    auto tag=r.byte();if(!r.out->error.empty())return done(false);
    switch(tag){
    case 0x70: if(!previous)return done(r.fail("PREVIOUS tag without previous value"));v=*previous;return done(true);
    case 0x6e:v.repr="None";return done(true);case 0x74:v.repr="True";return done(true);case 0x46:v.repr="False";return done(true);case 0x73:v.repr="\"\"";v.str=std::string();return done(true);
    case 0x54:case 0x4c:case 0x53:case 0x50:{auto n=r.size_value();std::vector<DVal>x;if(!decode_seq(r,n,x))return done(false);if(tag==0x54)v.repr=vals_repr(x,"(",")");else if(tag==0x4c)v.repr=vals_repr(x,"[","]");else if(tag==0x53)v.repr=vals_repr(x,"set{","}");else v.repr=vals_repr(x,"frozenset{","}");return done(true);}
    case 0x44:{auto n=r.size_value();std::vector<DVal>k,x;if(!decode_seq(r,n,k)||!decode_seq(r,n,x))return done(false);std::string z="{";for(std::size_t i=0;i<k.size();i++){if(i)z+=", ";if(z.size()+k[i].repr.size()+x[i].repr.size()>2048){z+="...";break;}z+=k[i].repr+": "+x[i].repr;}z+='}';v.repr=std::move(z);return done(true);}
    case 0x6c:case 0x71:case 0x69:case 0x49:{
        if(r.legacy()){
            if(tag==0x49)return done(r.fail("negative-int tag is not valid in legacy fixed-width constant streams"));
            auto n=tag==0x71?r.signed_fixed(8):r.signed_fixed(r.legacy_long_width());if(!r.out->error.empty())return done(false);v.repr=std::to_string(n);return done(true);
        }
        auto n=r.var();bool neg=tag==0x71||tag==0x49;v.repr=(neg?"-":"")+std::to_string(n);return done(true);
    }
    case 0x67:{
        if(r.legacy()){
            auto sign=r.byte();if(sign!='+'&&sign!='-')return done(r.fail("invalid legacy bigint sign"));auto n=r.fixed32();if(n>100000)return done(r.fail("large integer part count unreasonable"));for(std::uint64_t i=0;i<n;i++)(void)r.fixed64();if(!r.out->error.empty())return done(false);v.repr=std::string(sign=='-'?"-":"")+"bigint["+std::to_string(n)+" parts]";return done(true);
        }
        auto n=r.var();if(n>100000)return done(r.fail("large integer part count unreasonable"));for(std::uint64_t i=0;i<n;i++)(void)r.var();v.repr="bigint["+std::to_string(n)+" parts]";return done(r.out->error.empty());
    }
    case 0x47:{
        if(r.legacy()){std::vector<DVal>x;if(!decode_seq(r,2,x))return done(false);v.repr="GenericAlias("+x[0].repr+", "+x[1].repr+")";return done(true);}
        auto n=r.var();if(n>100000)return done(r.fail("large integer part count unreasonable"));for(std::uint64_t i=0;i<n;i++)(void)r.var();v.repr="-bigint["+std::to_string(n)+" parts]";return done(r.out->error.empty());
    }
    case 0x66:{if(!r.need(8))return done(false);std::uint64_t u=0;for(int i=0;i<8;i++)u|=std::uint64_t(r.d[r.p+i])<<(8*i);r.p+=8;double f;std::memcpy(&f,&u,8);std::ostringstream o;o<<std::setprecision(17)<<f;v.repr=o.str();return done(true);}
    case 0x6a:{if(!r.need(16))return done(false);std::uint64_t a=0,b=0;for(int i=0;i<8;i++){a|=std::uint64_t(r.d[r.p+i])<<(8*i);b|=std::uint64_t(r.d[r.p+8+i])<<(8*i);}r.p+=16;double x,y;std::memcpy(&x,&a,8);std::memcpy(&y,&b,8);std::ostringstream o;o<<'('<<std::setprecision(17)<<x<<(y>=0?"+":"")<<y<<"j)";v.repr=o.str();return done(true);}
    case 0x4a:{std::vector<DVal>x;if(!decode_seq(r,2,x))return done(false);v.repr="complex("+x[0].repr+", "+x[1].repr+")";return done(true);}
    case 0x77:case 0x64:{if(!r.need(1))return done(false);std::string x(1,char(r.byte()));save_string(x);v.repr=(tag==0x77?repr_text(x):repr_bytes(x));return done(true);}
    case 0x75:case 0x61:case 0x63:{auto x=r.cstr();if(!r.out->error.empty())return done(false);save_string(x);v.repr=(tag==0x63?repr_bytes(x):repr_text(x));return done(true);}
    case 0x76:case 0x62:case 0x42:{auto n=r.size_value();if(n>(1ull<<31))return done(r.fail("constant byte/string length unreasonable"));auto x=r.rawstr(static_cast<std::size_t>(n));if(!r.out->error.empty())return done(false);save_string(x);v.repr=(tag==0x76?repr_text(x):(tag==0x42?"bytearray("+repr_bytes(x)+")":repr_bytes(x)));return done(true);}
    case 0x3a:case 0x3b:{std::vector<DVal>x;if(!decode_seq(r,3,x))return done(false);v.repr=std::string(tag==0x3a?"slice(":"range(")+x[0].repr+", "+x[1].repr+", "+x[2].repr+")";return done(true);}
    case 0x4d:case 0x51:{auto n=r.byte();v.repr=std::string(tag==0x4d?"builtin_anon#":"builtin_special#")+std::to_string(n);return done(r.out->error.empty());}
    case 0x4f:case 0x45:{auto x=r.cstr();if(!r.out->error.empty())return done(false);v.repr=std::string(tag==0x45?"exception(":"builtin(")+x+")";save_string(x);return done(true);}
    case 0x5a:{auto n=r.byte();static const char*sp[]={"0.0","-0.0","nan","-nan","inf","-inf"};if(n>=6)return done(r.fail("invalid float-special subtype"));v.repr=sp[n];return done(true);}
    case 0x58:{auto n=r.size_value();if(n>r.d.size()-r.p)return done(r.fail("blob-data length out of range"));r.p+=static_cast<std::size_t>(n);v.repr="blob_data["+std::to_string(n)+"]";return done(true);}
    case 0x41:{if(r.legacy())return done(r.fail("GenericAlias tag is not valid in legacy fixed-width constant streams"));std::vector<DVal>x;if(!decode_seq(r,2,x))return done(false);v.repr="GenericAlias("+x[0].repr+", "+x[1].repr+")";return done(true);}
    case 0x48:{std::vector<DVal>x;if(!decode_seq(r,1,x))return done(false);v.repr="Union("+x[0].repr+")";return done(true);}
    case 0x43:{auto ok=decode_code(r,v);return done(ok);}
    case 0x2e:return done(r.fail("unexpected END tag before declared constant count"));
    default:{std::ostringstream o;o<<"unknown Nuitka constant tag 0x"<<std::hex<<unsigned(tag);return done(r.fail(o.str()));}
    }
}
NuitkaDecodedBlock decode_constant_block_profile(std::span<const std::uint8_t>all,const NuitkaConstantBlock&b,ConstEncoding encoding){
    NuitkaDecodedBlock o;o.name=b.name;if(b.data_offset>all.size()||b.size>all.size()-b.data_offset){o.error="constant block bounds invalid";return o;}auto d=all.subspan(b.data_offset,b.size);ConstReader r{d,0,&o,0,encoding};if(d.size()<3){o.error="constant block too small";return o;}o.declared_count=r.word();std::vector<DVal> vals;if(!decode_seq(r,o.declared_count,vals)){o.consumed=r.p;return o;}if(r.p>=d.size()||d[r.p]!=0x2e){o.error="constant stream END tag missing after declared count";o.error_offset=r.p;o.consumed=r.p;return o;}++r.p;o.consumed=r.p;if(r.p!=d.size()){o.error="constant stream trailing bytes after END tag";o.error_offset=r.p;return o;}o.success=true;std::size_t cap=512;for(std::size_t i=0;i<vals.size()&&i<cap;i++)o.values.push_back(vals[i].repr);if(vals.size()>cap)o.values.push_back("... "+std::to_string(vals.size()-cap)+" more constants");return o;
}
bool same_decoded_semantics(const NuitkaDecodedBlock&a,const NuitkaDecodedBlock&b){
    if(a.declared_count!=b.declared_count||a.values!=b.values||a.string_values!=b.string_values||a.code_objects.size()!=b.code_objects.size())return false;
    for(std::size_t i=0;i<a.code_objects.size();++i){const auto&x=a.code_objects[i];const auto&y=b.code_objects[i];if(x.name!=y.name||x.qualname!=y.qualname||x.args!=y.args||x.free_vars!=y.free_vars||x.flags!=y.flags||x.line!=y.line||x.arg_count!=y.arg_count||x.kw_only!=y.kw_only||x.pos_only!=y.pos_only)return false;}
    return true;
}
NuitkaDecodedBlock decode_constant_block(std::span<const std::uint8_t>all,const NuitkaConstantBlock&b){
    auto modern=decode_constant_block_profile(all,b,ConstEncoding::Varint);
    auto legacy64=decode_constant_block_profile(all,b,ConstEncoding::LegacyLong64);
    auto legacy32=decode_constant_block_profile(all,b,ConstEncoding::LegacyLong32);
    std::vector<const NuitkaDecodedBlock*> successes;for(const auto*x:{&modern,&legacy64,&legacy32})if(x->success)successes.push_back(x);
    if(!successes.empty()){
        for(std::size_t i=1;i<successes.size();++i)if(!same_decoded_semantics(*successes[0],*successes[i])){NuitkaDecodedBlock o;o.name=b.name;o.declared_count=successes[0]->declared_count;o.error="constant stream encoding profile ambiguous";return o;}
        return *successes[0];
    }
    const NuitkaDecodedBlock*best=&modern;for(const auto*x:{&legacy64,&legacy32})if(x->consumed>best->consumed)best=x;return *best;
}
void decode_constant_blocks(std::span<const std::uint8_t>d,NuitkaInfo&i){i.decoded_blocks.clear();for(const auto&b:i.constant_blocks)i.decoded_blocks.push_back(decode_constant_block(d,b));}
std::string block_safe_name(std::string n){if(n.empty())n="__global__";for(auto&c:n)if(!(std::isalnum(static_cast<unsigned char>(c))||c=='_'||c=='.'||c=='-'))c='_';return n;}
std::string decoded_manifest(const NuitkaDecodedBlock&b){std::ostringstream o;o<<"Nuitka constants block: "<<(b.name.empty()?"<global>":b.name)<<"\nstate: "<<(b.success?"CONFIRMED":"FAILED")<<"\ndeclared_count: "<<b.declared_count<<"\nconsumed: "<<b.consumed<<"\n";if(!b.error.empty())o<<"error_offset: 0x"<<std::hex<<b.error_offset<<std::dec<<"\nerror: "<<b.error<<"\n";if(!b.code_objects.empty()){o<<"code_objects:\n";for(const auto&c:b.code_objects)o<<"  "<<c.qualname<<" line="<<c.line<<" argc="<<c.arg_count<<" kwonly="<<c.kw_only<<" posonly="<<c.pos_only<<" flags=0x"<<std::hex<<c.flags<<std::dec<<" args="<<c.args<<" free="<<c.free_vars<<"\n";}o<<"constants:\n";for(std::size_t i=0;i<b.values.size();i++)o<<"  ["<<i<<"] "<<b.values[i]<<"\n";return o.str();}
std::string sanitize(std::string s){std::replace(s.begin(),s.end(),'\\','/');while(s.find("../")!=std::string::npos)s.replace(s.find("../"),3,"__/ ");if(!s.empty()&&(s[0]=='/'||s[0]=='\\'))s.erase(s.begin());return s;}
}
NuitkaInfo detect_nuitka(std::span<const std::uint8_t>d,const PeInfo&pe,const ElfInfo&elf,std::uint64_t max_decompressed_size){
    NuitkaInfo best;
    for(std::size_t p=0;p+3<d.size();++p){
        if(d[p]!='K'||d[p+1]!='A'||(d[p+2]!='X'&&d[p+2]!='Y'))continue;
        bool comp=d[p+2]=='Y';std::vector<std::uint8_t> dec;std::size_t frame=0;std::span<const std::uint8_t> payload;
        if(comp){
            unsigned char*out=nullptr;size_t os=0;unsigned long long bound=0;int limit_hit=0;
            auto lim=static_cast<std::size_t>(std::min<std::uint64_t>(max_decompressed_size,std::numeric_limits<std::size_t>::max()));
            if(!prts_zstd_decompress_frame_limited(d.data()+p+3,d.size()-(p+3),lim,&out,&os,&frame,&bound,&limit_hit)){
                if(limit_hit&&!best.valid){best.valid=true;best.compressed=true;best.decompression_limited=true;best.payload_offset=p;best.payload_size=frame?3+frame:0;best.zstd_decompressed_bound=bound;best.decompression_limit=max_decompressed_size;best.variant="onefile-KAY-budget-limited";best.error="Nuitka KAY Zstandard payload exceeds configured static decompression limit";}
                continue;
            }
            dec.assign(out,out+os);prts_zstd_free(out);payload=dec;
        } else payload=d.subspan(p+3);
        auto a=best_archive(payload,pe,elf);if(!a.ok)continue;
        NuitkaInfo x;x.valid=true;x.onefile=true;x.compressed=comp;x.windows_names=a.win;x.payload_offset=p;x.payload_size=3+(comp?frame:a.consumed);x.decompressed_size=payload.size();x.entries=a.entries;
        x.variant=std::string("onefile-")+(comp?"KAY-zstd":"KAX-raw")+(a.win?"-win":"-posix")+(a.crc?"-crc":"");
        if(best.decompression_limited||!best.valid||x.entries.size()>best.entries.size())best=std::move(x);
    }
    if(auto cb=find_constant_blob(d)){
        if(!best.valid){best.valid=true;best.variant="standalone-constant-blob";}
        best.constant_blob_offset=cb->second.front().header_offset;best.constant_blob_size=cb->first;best.constant_blocks=std::move(cb->second);decode_constant_blocks(d,best);
    }
    // The __compiled__ tuple belongs to the current compiled image. A
    // onefile executable is a bootstrap/container around a child image, so do
    // not project any outer-loader tuple onto the payload. For ordinary
    // standalone images and extension modules, the fully closed tuple
    // initializer is independently strong structural Nuitka evidence.
    if(!best.onefile){
        best.compiled_version=detect_nuitka_compiled_version(d,elf);
        if(best.compiled_version.valid&&!best.valid){
            best.valid=true;bool module=false;
            for(const auto&s:elf.dynamic.symbols)if(s.exported&&s.name.rfind("PyInit_",0)==0){module=true;break;}
            best.variant=module?"module-compiled-version-structseq":"compiled-version-structseq";
        }
    }
    // String/API anchors are routing evidence only. In particular,
    // PyByteArray_FromStringAndSize is a normal CPython API and appears in
    // stock interpreters. Likewise, a literal "Nuitka", "__nuitka__", or
    // "constant_bin_data" can be embedded as bait. Do not turn any of those
    // into a validated ecosystem result when neither the onefile member
    // stream nor the constant directory closed structurally. The caller's
    // generic static string finding remains available as a weak SUSPECTED
    // route when a Nuitka-specific text anchor was actually observed.
    return best;
}
Finding nuitka_finding(const NuitkaInfo&i){
    Finding f;f.kind="ecosystem";f.family="Nuitka";if(!i.valid){f.state="FAILED";return f;}
    if(i.decompression_limited){f.state="LIKELY";f.confidence=.9;f.variant=i.variant;f.evidence={"KAY marker followed by a structurally bounded Zstandard frame"};f.negative_evidence.push_back(i.error);f.fields["zstd_decompressed_bound"]=std::to_string(i.zstd_decompressed_bound);f.fields["decompression_limit"]=std::to_string(i.decompression_limit);f.suggested_actions={"raise explicit artifact byte budget only if the input is trusted enough to justify it"};return f;}
    if(i.onefile){f.state="CONFIRMED";f.variant=i.variant;f.evidence={"KA[X/Y] payload located and contained-file stream structurally parsed"};if(i.compressed)f.evidence.push_back("Zstandard payload successfully decompressed");f.fields["entries"]=std::to_string(i.entries.size());f.fields["payload_offset"]=std::to_string(i.payload_offset);}
    else if(!i.constant_blocks.empty()){f.state="CONFIRMED";f.variant=i.variant;f.evidence={"Nuitka constant_bin directory structurally parsed",".bytecode and module constant blocks recovered"};f.fields["constant_blocks"]=std::to_string(i.constant_blocks.size());f.fields["constant_blob_offset"]=std::to_string(i.constant_blob_offset);std::size_t ok=0,fail=0,total=0,codes=0;std::vector<std::string> hints;for(const auto&b:i.decoded_blocks){if(b.success)++ok;else{++fail;std::ostringstream x;x<<"constant block '"<<(b.name.empty()?"<global>":b.name)<<"' decode failed at +0x"<<std::hex<<b.error_offset<<std::dec<<": "<<b.error;f.negative_evidence.push_back(x.str());}total+=b.declared_count;codes+=b.code_objects.size();if(b.name=="__main__"||b.name.rfind("__main__",0)==0)for(const auto&s:b.string_values)if(hints.size()<20)hints.push_back(s);}f.fields["decoded_blocks"]=std::to_string(ok);f.fields["decode_failures"]=std::to_string(fail);f.fields["decoded_constants"]=std::to_string(total);f.fields["code_objects"]=std::to_string(codes);if(!hints.empty()){std::string h;for(const auto&x:hints){if(!h.empty())h+=" | ";if(h.size()+x.size()>1200)break;h+=x;}f.fields["__main___string_hints"]=h;}if(ok)f.evidence.push_back("constant tag streams decoded and validated against declared counts/END tags");}
    else if(i.compiled_version.valid){f.state="CONFIRMED";f.variant=i.variant;}
    else{f.state="LIKELY";f.confidence=.85;f.variant=i.variant;f.evidence={"Nuitka/CPython runtime anchors present"};if(!i.error.empty())f.negative_evidence.push_back(i.error);}
    if(i.compiled_version.valid){const auto&v=i.compiled_version;f.evidence.push_back("Nuitka __compiled__ named-tuple descriptor and major/minor/micro/releaselevel initializers were structurally recovered from bounded ELF64/x86-64 generated code");f.fields["compiled_version_tuple"]=std::to_string(v.major)+"."+std::to_string(v.minor)+"."+std::to_string(v.micro);f.fields["compiled_version_major"]=std::to_string(v.major);f.fields["compiled_version_minor"]=std::to_string(v.minor);f.fields["compiled_version_micro"]=std::to_string(v.micro);f.fields["compiled_releaselevel"]=v.releaselevel;f.fields["compiled_version_profile"]=v.profile;f.fields["compiled_version_semantics"]="DUNDER_COMPILED_MAJOR_MINOR_MICRO_NOT_FULL_RELEASE_TAG";f.fields["compiled_version_descriptor_fields"]=std::to_string(v.descriptor_field_count);f.fields["compiled_version_descriptor_va"]=std::to_string(v.descriptor_va);f.fields["compiled_version_init_va"]=std::to_string(v.init_call_va);f.fields["compiled_version_int_constructor_va"]=std::to_string(v.int_constructor_va);}else if(!i.compiled_version.error.empty())f.negative_evidence.push_back(i.compiled_version.error);
    return f;
}
NuitkaExtractResult extract_nuitka(std::span<const std::uint8_t>d,const NuitkaInfo&i,const std::filesystem::path&outdir,bool core_only,std::uint64_t max_output_bytes,std::uint32_t max_output_files){
    NuitkaExtractResult r;r.core_only=core_only;r.output_dir=outdir;if(!i.valid){r.error="Nuitka not validated";return r;}std::error_code ec;std::filesystem::create_directories(outdir,ec);if(ec){r.error=ec.message();return r;}
    auto omit=[&](std::uint64_t n){r.budget_exhausted=true;++r.omitted_count;r.omitted_bytes=n>std::numeric_limits<std::uint64_t>::max()-r.omitted_bytes?std::numeric_limits<std::uint64_t>::max():r.omitted_bytes+n;};
    auto put=[&](const std::filesystem::path&p,std::span<const std::uint8_t>b){if(r.file_count>=max_output_files||b.size()>max_output_bytes-r.output_bytes){omit(b.size());return false;}std::filesystem::create_directories(p.parent_path(),ec);ec.clear();std::ofstream o(p,std::ios::binary|std::ios::trunc);if(!o)return false;o.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size()));if(!o)return false;++r.file_count;r.output_bytes+=b.size();r.files.push_back(p);return true;};
    auto put_text=[&](const std::filesystem::path&p,const std::string&t){return put(p,std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(t.data()),t.size()));};
    if(!i.onefile&&!i.constant_blocks.empty()){
        for(std::size_t bi=0;bi<i.constant_blocks.size();++bi){const auto&b=i.constant_blocks[bi];if(b.data_offset>d.size()||b.size>d.size()-b.data_offset)continue;auto n=block_safe_name(b.name);if(!core_only)put(outdir/(n+".nuitka-const.bin"),d.subspan(b.data_offset,b.size));if(bi<i.decoded_blocks.size())put_text(outdir/(n+".nuitka-const.txt"),decoded_manifest(i.decoded_blocks[bi]));}
        r.success=r.file_count>0;if(!r.success)r.error="no constant/code artifacts written";return r;
    }
    if(!i.onefile){r.error="no validated Nuitka onefile payload";return r;}
    std::vector<std::uint8_t>dec;std::span<const std::uint8_t>payload;if(i.compressed){unsigned char*out=nullptr;size_t os=0,fs=0;if(!prts_zstd_decompress_frame(d.data()+i.payload_offset+3,d.size()-(i.payload_offset+3),&out,&os,&fs)){r.error="zstd payload decompression failed";return r;}dec.assign(out,out+os);prts_zstd_free(out);payload=dec;}else payload=d.subspan(i.payload_offset+3);
    auto score=[&](const NuitkaEntry&e){std::string n=e.name;std::transform(n.begin(),n.end(),n.begin(),[](unsigned char c){return char(std::tolower(c));});auto slash=n.find_last_of("/\\");auto base=slash==std::string::npos?n:n.substr(slash+1);int sc=(base=="main.bin"||base=="__main__.bin")?1200:0;if(base.size()>=4&&base.ends_with(".exe"))sc=std::max(sc,1100);const bool runtime_lib=base.ends_with(".so")||base.find(".so.")!=std::string::npos||base.ends_with(".dll")||base.ends_with(".pyd")||base.ends_with(".dylib");if(!runtime_lib&&e.data_offset<=payload.size()&&e.size<=payload.size()-e.data_offset&&e.size>=4){auto q=payload.subspan(e.data_offset,4);if((q[0]=='M'&&q[1]=='Z')||(q[0]==0x7f&&q[1]=='E'&&q[2]=='L'&&q[3]=='F'))sc=std::max(sc,1000);}return sc;};
    std::vector<const NuitkaEntry*>selected;if(core_only){for(const auto&e:i.entries)if(score(e)>=1000)selected.push_back(&e);if(selected.empty()&&!i.entries.empty()){auto it=std::max_element(i.entries.begin(),i.entries.end(),[](const auto&a,const auto&b){return a.size<b.size;});selected.push_back(&*it);}std::stable_sort(selected.begin(),selected.end(),[&](auto*a,auto*b){auto as=score(*a),bs=score(*b);return as!=bs?as>bs:a->size>b->size;});}else for(const auto&e:i.entries)selected.push_back(&e);
    for(const auto*ep:selected){const auto&e=*ep;if(e.data_offset>payload.size()||e.size>payload.size()-e.data_offset){r.error="entry bounds invalid";return r;}auto name=sanitize(e.name);if(name.empty())continue;put(outdir/std::filesystem::path(name),payload.subspan(e.data_offset,e.size));}
    r.success=r.file_count>0;if(!r.success)r.error=core_only?"no Nuitka main executable/code payload materialized":"no files written";return r;
}
}
