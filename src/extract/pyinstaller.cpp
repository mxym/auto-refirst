#include "prts/pyinstaller.hpp"
#include "prts/sha256.hpp"
#include "prts/python_marshal.hpp"
#include "prts/cpython.hpp"
#include "prts/byte_search.hpp"
#include "prts/path_utf8.hpp"
extern "C" {
#include "miniz.h"
}
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <variant>

namespace prts {
namespace {
struct PyInstallerLoaderReference { const char* label; int python_minor; const char* module; std::uint32_t size; const char* sha256; };
struct PyInstallerLoaderSemanticReference { const char* label; int python_minor; const char* module; const char* semantic_sha256; };
#include "../reference/pyinstaller_loader_refs.inc"
#include "../reference/pyinstaller_loader_semantic_refs.inc"
#include "../reference/python_stdlib_roots.inc"
}
 namespace {
constexpr std::array<std::uint8_t,8> MAGIC={'M','E','I',014,013,012,013,016};
constexpr std::size_t COOKIE_SIZE=88;
std::uint32_t be32(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;return(std::uint32_t(d[o])<<24)|(std::uint32_t(d[o+1])<<16)|(std::uint32_t(d[o+2])<<8)|d[o+3];}
std::int32_t le_i32(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;std::uint32_t v=std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);return static_cast<std::int32_t>(v);}
bool sane_type(char c){static constexpr std::string_view ok="bdzZMmsxoln";return ok.find(c)!=std::string_view::npos;}
bool sane_name(std::span<const std::uint8_t> n){if(n.empty()||n.size()>4096)return false;std::size_t chars=0;for(auto c:n){if(c==0)break;if(c<0x20&&c!='\t')return false;++chars;}return chars>0;}
std::string clean_name(std::span<const std::uint8_t> n){std::string s;for(auto c:n){if(!c)break;s.push_back(char(c));}return s;}
std::string clean_lib(std::span<const std::uint8_t> n){std::string s;for(auto c:n){if(!c)break;if(c<0x20||c>0x7e)return {};s.push_back(char(c));}return s;}
std::string ascii_lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
bool valid_utf8(std::string_view s){for(std::size_t i=0;i<s.size();){auto c=static_cast<unsigned char>(s[i]);std::size_t n=0;if(c<0x80){if(c<0x20)return false;++i;continue;}if(c>=0xc2&&c<=0xdf)n=2;else if(c>=0xe0&&c<=0xef)n=3;else if(c>=0xf0&&c<=0xf4)n=4;else return false;if(i+n>s.size())return false;for(std::size_t z=1;z<n;++z)if((static_cast<unsigned char>(s[i+z])&0xc0)!=0x80)return false;if(n==3){auto c1=static_cast<unsigned char>(s[i+1]);if((c==0xe0&&c1<0xa0)||(c==0xed&&c1>=0xa0))return false;}if(n==4){auto c1=static_cast<unsigned char>(s[i+1]);if((c==0xf0&&c1<0x90)||(c==0xf4&&c1>=0x90))return false;}i+=n;}return true;}
bool reserved_windows_component(std::string_view part){std::string low(part);std::transform(low.begin(),low.end(),low.begin(),[](unsigned char c){return char(std::tolower(c));});auto dot=low.find('.');auto stem=low.substr(0,dot);return stem=="con"||stem=="prn"||stem=="aux"||stem=="nul"||stem=="clock$"||(stem.size()==4&&stem.rfind("com",0)==0&&stem[3]>='1'&&stem[3]<='9')||(stem.size()==4&&stem.rfind("lpt",0)==0&&stem[3]>='1'&&stem[3]<='9');}
bool safe_relative_path(std::string raw,std::filesystem::path&out){out.clear();if(raw.empty()||raw.front()=='/'||raw.front()=='\\')return false;std::replace(raw.begin(),raw.end(),'\\','/');std::size_t pos=0;while(pos<=raw.size()){auto slash=raw.find('/',pos);auto part=std::string_view(raw).substr(pos,slash==std::string::npos?raw.size()-pos:slash-pos);if(part.empty()||part=="."||part==".."||part.size()>255||!valid_utf8(part))return false;for(unsigned char c:part)if(c==':'||c==0)return false;if(part.back()=='.'||part.back()==' '||reserved_windows_component(part))return false;auto native=path_from_utf8(part);if(native.empty())return false;out/=native;if(slash==std::string::npos)break;pos=slash+1;}return !out.empty()&&!out.is_absolute()&&!out.has_root_name();}
bool safe_module_path(std::string name,std::filesystem::path&out){std::replace(name.begin(),name.end(),'.','/');return safe_relative_path(std::move(name),out);}
bool ensure_output_parent(const std::filesystem::path&root,const std::filesystem::path&dest,std::string&why){auto nr=root.lexically_normal(),parent=dest.parent_path().lexically_normal();auto rel=parent.lexically_relative(nr);if(rel.empty()&&parent!=nr){why="output parent is outside extraction root";return false;}for(const auto&part:rel)if(part==".."){why="output parent escapes extraction root";return false;}std::error_code ec;auto ensure=[&](const std::filesystem::path&p){auto st=std::filesystem::symlink_status(p,ec);if(!ec&&st.type()!=std::filesystem::file_type::not_found){if(st.type()==std::filesystem::file_type::symlink){why="output path component is a symlink: "+path_utf8(p);return false;}if(st.type()!=std::filesystem::file_type::directory){why="output path component is not a directory: "+path_utf8(p);return false;}return true;}ec.clear();if(!std::filesystem::create_directory(p,ec)&&ec){why="cannot create output directory: "+ec.message();return false;}ec.clear();st=std::filesystem::symlink_status(p,ec);if(ec||st.type()!=std::filesystem::file_type::directory){why="created output component is not a real directory";return false;}return true;};if(!ensure(nr))return false;auto cur=nr;for(const auto&part:rel){if(part.empty()||part==".")continue;cur/=part;if(!ensure(cur))return false;}return true;}
bool write_file_safe(const std::filesystem::path&root,const std::filesystem::path&p,std::span<const std::uint8_t>d,std::string&why){if(!ensure_output_parent(root,p,why))return false;std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);if(!ec&&st.type()==std::filesystem::file_type::symlink){why="output file is a symlink: "+path_utf8(p);return false;}std::ofstream f(p,std::ios::binary|std::ios::trunc);if(!f){why="cannot create output file: "+path_utf8(p);return false;}f.write(reinterpret_cast<const char*>(d.data()),static_cast<std::streamsize>(d.size()));if(!f){why="write failed: "+path_utf8(p);return false;}return true;}
std::string csvq(std::string_view s){std::string o="\"";for(char c:s){if(c=='\"')o+="\"\"";else if(c=='\n'||c=='\r')o+=' ';else o+=c;}o+='\"';return o;}
bool bootstrap_script(std::string_view n){return n=="struct"||n.rfind("pyimod",0)==0||n.rfind("pyiboot",0)==0;}
bool runtime_hook_script(std::string_view n){return n.rfind("pyi_rth",0)==0;}
bool stdlib_module(std::string_view n){auto dot=n.find('.');auto root=n.substr(0,dot);return std::binary_search(std::begin(kPythonStdlibRoots),std::end(kPythonStdlibRoots),root);}
std::string outer_role(const PyInstArchiveInfo&info,const PyInstEntry&e){if(e.typecode=='s'||e.typecode=='m'||e.typecode=='M'){if(bootstrap_script(e.name))return "bootstrap";if(runtime_hook_script(e.name))return "runtime_hook";return "user";}if(e.typecode=='z')return "pyz_archive";if(!info.python_library.empty()&&e.name==info.python_library)return "runtime_binary";return "bulk";}
int outer_score(const PyInstArchiveInfo&info,const PyInstEntry&e){auto r=outer_role(info,e);if(r=="user")return 1000;if(r=="pyz_archive")return 900;if(r=="bootstrap")return 350;if(r=="runtime_hook")return 300;if(r=="runtime_binary")return 100;return 10;}
std::string pyz_role(std::string_view n){if(bootstrap_script(n)||runtime_hook_script(n))return "bootstrap";return stdlib_module(n)?"stdlib":"user";}
int pyz_score(std::string_view n){auto r=pyz_role(n);if(n=="__main__"||n=="main")return 1200;if(r=="user")return 900;if(r=="bootstrap")return 200;return 100;}
std::optional<std::vector<std::uint8_t>> zlib_dec(std::span<const std::uint8_t> in,std::size_t expected){if(expected==0)return std::vector<std::uint8_t>{};std::vector<std::uint8_t> out(expected);mz_ulong n=static_cast<mz_ulong>(out.size());int rc=mz_uncompress(out.data(),&n,in.data(),static_cast<mz_ulong>(in.size()));if(rc!=MZ_OK)return std::nullopt;out.resize(n);return out;}
std::optional<std::vector<std::uint8_t>> zlib_dec_unknown(std::span<const std::uint8_t> in,std::size_t max_output=64ull*1024*1024,bool*limit_hit=nullptr){
    if(limit_hit)*limit_hit=false;
    max_output=std::min<std::size_t>(max_output,64ull*1024*1024);
    if(!max_output){if(limit_hit)*limit_hit=true;return std::nullopt;}
    std::size_t cap=std::min<std::size_t>(4096,max_output);
    for(;;){
        std::vector<std::uint8_t>buf(cap);mz_ulong n=static_cast<mz_ulong>(cap);
        int rc=mz_uncompress(buf.data(),&n,in.data(),static_cast<mz_ulong>(in.size()));
        if(rc==MZ_OK){buf.resize(n);return buf;}
        if(rc!=MZ_BUF_ERROR)return std::nullopt;
        if(cap==max_output){if(limit_hit)*limit_hit=true;return std::nullopt;}
        cap=std::min<std::size_t>(max_output,cap>max_output/2?max_output:cap*2);
    }
}

bool parse_toc(std::span<const std::uint8_t>d,std::uint64_t start,std::uint32_t len,std::uint32_t archive_len,std::vector<PyInstEntry>&out,int&score){
    if(start+len>d.size()||len<18)return false;
    std::size_t p=static_cast<std::size_t>(start),end=p+len;int good=0;
    while(p<end){if(p+18>end)return false;auto el=be32(d,p),off=be32(d,p+4),cs=be32(d,p+8),us=be32(d,p+12);auto cf=d[p+16];char tc=char(d[p+17]);if(el<18||p+el>end||el>(1u<<20))return false;if(off>archive_len||std::uint64_t(off)+cs>archive_len)return false;if(cf>1||!sane_type(tc))return false;auto nm=d.subspan(p+18,el-18);if(!sane_name(nm))return false;out.push_back({off,cs,us,cf,tc,clean_name(nm)});++good;p+=el;}
    score=good;return p==end&&good>0;
}
std::optional<PyInstArchiveInfo> cookie_at(std::span<const std::uint8_t>d,std::uint64_t pos,bool require_magic){
    if(pos+COOKIE_SIZE>d.size())return std::nullopt;
    if(require_magic&&!std::equal(MAGIC.begin(),MAGIC.end(),d.begin()+static_cast<std::ptrdiff_t>(pos)))return std::nullopt;
    auto al=be32(d,pos+8),to=be32(d,pos+12),tl=be32(d,pos+16),pv=be32(d,pos+20);if(al<COOKIE_SIZE||al>pos+COOKIE_SIZE||tl<18||to>=al||std::uint64_t(to)+tl>al-COOKIE_SIZE)return std::nullopt;if(!((pv>=20&&pv<100)||(pv>=200&&pv<400)))return std::nullopt;
    auto start=pos+COOKIE_SIZE-al;std::vector<PyInstEntry> entries;int score=0;if(!parse_toc(d,start+to,tl,al,entries,score))return std::nullopt;if(score<2)return std::nullopt;
    PyInstArchiveInfo r;r.valid=true;r.standard_magic=require_magic;r.heuristic_cookie=!require_magic;r.cookie_offset=pos;r.archive_start=start;r.archive_end=pos+COOKIE_SIZE;r.archive_length=al;r.toc_offset=to;r.toc_length=tl;r.python_version=pv;r.python_library=clean_lib(d.subspan(pos+24,64));r.entries=std::move(entries);
    r.evidence.push_back("CArchive TOC parsed and all entry bounds/typecodes validated");r.evidence.push_back("Python version field is plausible: "+std::to_string(pv));if(require_magic)r.evidence.push_back("standard MEI cookie magic present");else r.evidence.push_back("cookie magic is modified/absent; archive geometry recovered heuristically");if(!r.python_library.empty())r.evidence.push_back("runtime library: "+r.python_library);return r;
}

// Minimal Python marshal reader sufficient for PYZ TOC. It deliberately does not parse code objects.
struct MVal; using MV=std::shared_ptr<MVal>;
struct MVal { enum K{Null,None,Bool,Int,Str,Seq,Dict} k=None; std::int64_t i=0; std::string s; std::vector<MV> seq; std::vector<std::pair<MV,MV>> dict; };
class MarshalReader {
public: MarshalReader(std::span<const std::uint8_t>d,std::size_t p):d_(d),p_(p){}
    MV read(){return obj();} std::size_t pos()const{return p_;}
private:
    std::span<const std::uint8_t>d_;std::size_t p_;std::vector<MV>refs_;
    std::optional<std::uint8_t> u8(){if(p_>=d_.size())return{};return d_[p_++];}
    std::optional<std::int32_t> i32(){if(p_+4>d_.size())return{};auto v=le_i32(d_,p_);p_+=4;return v;}
    std::optional<std::string> bytes(std::size_t n){if(p_+n>d_.size())return{};std::string s(reinterpret_cast<const char*>(d_.data()+p_),n);p_+=n;return s;}
    MV obj(){auto cb=u8();if(!cb)return{};auto code=*cb;bool addref=code&0x80;char t=char(code&0x7f);MV v=std::make_shared<MVal>();std::size_t refidx=0;if(addref){refidx=refs_.size();refs_.push_back(v);}auto fail=[&]()->MV{return{};};
        switch(t){
            case '0':v->k=MVal::Null;break;case 'N':v->k=MVal::None;break;case 'F':case 'T':v->k=MVal::Bool;v->i=(t=='T');break;
            case 'i':{auto x=i32();if(!x)return fail();v->k=MVal::Int;v->i=*x;break;}
            case 'I':{auto lo=i32(),hi=i32();if(!lo||!hi)return fail();v->k=MVal::Int;v->i=(std::int64_t(std::uint32_t(*hi))<<32)|std::uint32_t(*lo);break;}
            case 'l':{auto n=i32();if(!n)return fail();auto cnt=std::size_t(*n<0?-*n:*n);if(cnt>1024||p_+cnt*2>d_.size())return fail();std::int64_t x=0;for(std::size_t j=0;j<cnt&&j<4;j++){std::uint16_t digit=d_[p_+j*2]|(d_[p_+j*2+1]<<8);x|=std::int64_t(digit)<<(15*j);}p_+=cnt*2;if(*n<0)x=-x;v->k=MVal::Int;v->i=x;break;}
            case 'z':case 'Z':{auto n=u8();if(!n)return fail();auto x=bytes(*n);if(!x)return fail();v->k=MVal::Str;v->s=*x;break;}
            case 's':case 't':case 'u':case 'a':case 'A':{auto n=i32();if(!n||*n<0||*n>(1<<26))return fail();auto x=bytes(*n);if(!x)return fail();v->k=MVal::Str;v->s=*x;break;}
            case '(':case '[':case '<':case '>':{auto n=i32();if(!n||*n<0||*n>(1<<22))return fail();v->k=MVal::Seq;for(int j=0;j<*n;j++){auto x=obj();if(!x)return fail();v->seq.push_back(x);}break;}
            case ')':{auto n=u8();if(!n)return fail();v->k=MVal::Seq;for(unsigned j=0;j<*n;j++){auto x=obj();if(!x)return fail();v->seq.push_back(x);}break;}
            case '{':{v->k=MVal::Dict;while(true){auto k=obj();if(!k)return fail();if(k->k==MVal::Null)break;auto x=obj();if(!x)return fail();v->dict.push_back({k,x});if(v->dict.size()>(1u<<22))return fail();}break;}
            case 'r':{auto n=i32();if(!n||*n<0||std::size_t(*n)>=refs_.size())return fail();return refs_[*n];}
            default:return fail();
        }
        if(addref)refs_[refidx]=v;
        return v;
    }
};
struct PyzEnt{std::string name;int type=0;std::uint32_t off=0,len=0;};
bool tuple_entry(const MV&name,const MV&v,PyzEnt&e){if(!name||name->k!=MVal::Str||!v||v->k!=MVal::Seq||v->seq.size()<3)return false;auto a=v->seq[0],b=v->seq[1],c=v->seq[2];if(!a||!b||!c||a->k!=MVal::Int||b->k!=MVal::Int||c->k!=MVal::Int||b->i<0||c->i<0)return false;e.name=name->s;e.type=int(a->i);e.off=std::uint32_t(b->i);e.len=std::uint32_t(c->i);return true;}
bool parse_pyz_toc(std::span<const std::uint8_t>pyz,std::vector<PyzEnt>&out,std::array<std::uint8_t,4>&magic){if(pyz.size()<17||std::memcmp(pyz.data(),"PYZ\0",4))return false;std::copy_n(pyz.begin()+4,4,magic.begin());auto to=be32(pyz,8);if(to>=pyz.size())return false;MarshalReader mr(pyz,to);auto root=mr.read();if(!root)return false;if(root->k==MVal::Seq){for(auto&item:root->seq){if(!item||item->k!=MVal::Seq||item->seq.size()!=2)continue;PyzEnt e;if(tuple_entry(item->seq[0],item->seq[1],e))out.push_back(std::move(e));}}else if(root->k==MVal::Dict){for(auto&kv:root->dict){PyzEnt e;if(tuple_entry(kv.first,kv.second,e))out.push_back(std::move(e));}}return !out.empty();}
std::vector<std::uint8_t> pyc_wrap(std::span<const std::uint8_t>marshal,const std::array<std::uint8_t,4>&magic,std::uint32_t pyver){std::size_t h=pyver>=307?16:(pyver>=303?12:8);std::vector<std::uint8_t>o(h+marshal.size(),0);std::copy(magic.begin(),magic.end(),o.begin());std::copy(marshal.begin(),marshal.end(),o.begin()+static_cast<std::ptrdiff_t>(h));return o;}
}

PyInstArchiveInfo detect_pyinstaller(std::span<const std::uint8_t>d){
    PyInstArchiveInfo none;none.error="no structurally valid CArchive found";
    // Standard magic: enumerate exact candidates cheaply, but preserve the original
    // reverse-search semantic by retaining the highest-offset valid cookie.
    if(d.size()>=COOKIE_SIZE){std::optional<PyInstArchiveInfo>last;std::size_t p=0;const std::span<const std::uint8_t>magic(MAGIC);for(;;){p=detail::find_exact(d,magic,p);if(p==std::string::npos||p+COOKIE_SIZE>d.size())break;if(auto r=cookie_at(d,p,true))last=std::move(r);++p;}if(last)return *last;}
    // A plausible big-endian Python version below 400 always starts with two zero bytes.
    // Search only those exact candidates instead of decoding a uint32 at every byte.
    if(d.size()>=COOKIE_SIZE){const std::size_t begin=d.size()>64ull*1024*1024?d.size()-64ull*1024*1024:0,last_q=d.size()-COOKIE_SIZE+20;std::optional<PyInstArchiveInfo>best;std::size_t bestn=0;std::size_t q=begin+20;constexpr std::string_view zero("\0",1);for(;;){q=detail::find_exact(d,zero,q);if(q==std::string::npos||q>last_q)break;auto p=q-20;++q;if(d[p+21]!=0)continue;auto pv=be32(d,p+20);if(!((pv>=20&&pv<100)||(pv>=200&&pv<400)))continue;auto al=be32(d,p+8),to=be32(d,p+12),tl=be32(d,p+16);if(al<COOKIE_SIZE||al>p+COOKIE_SIZE||tl<18||to>=al||std::uint64_t(to)+tl>al-COOKIE_SIZE)continue;if(auto r=cookie_at(d,p,false)){if(r->entries.size()>bestn){bestn=r->entries.size();best=std::move(r);}}}if(best)return *best;}
    return none;
}

std::optional<std::vector<std::uint8_t>> pyinstaller_entry_bytes(std::span<const std::uint8_t>d,const PyInstArchiveInfo&info,const PyInstEntry&e){
    if(!info.valid)return std::nullopt;
    auto off=info.archive_start+e.offset;if(off+e.compressed_size>d.size())return std::nullopt;auto raw=d.subspan(off,e.compressed_size);if(e.compression_flag)return zlib_dec(raw,e.uncompressed_size);return std::vector<std::uint8_t>(raw.begin(),raw.end());
}

PyInstPyzMemberData pyinstaller_pyz_member_bytes(std::span<const std::uint8_t>pyz,std::string_view name,std::size_t max_output_bytes){
    PyInstPyzMemberData out;out.name=std::string(name);std::vector<PyzEnt>toc;
    if(!parse_pyz_toc(pyz,toc,out.pyc_magic)){out.error="PYZ TOC could not be decoded";return out;}
    out.toc_entry_count=static_cast<std::uint32_t>(toc.size());const PyzEnt*selected=nullptr;
    for(const auto&e:toc)if(e.name==name){++out.match_count;selected=&e;}
    if(out.match_count!=1){out.error=out.match_count?"multiple PYZ entries have the requested module name":"requested module is absent from PYZ";return out;}
    if(!selected||std::uint64_t(selected->off)+selected->len>pyz.size()){out.error="PYZ member bounds are invalid";return out;}
    bool limit_hit=false;auto dec=zlib_dec_unknown(pyz.subspan(selected->off,selected->len),max_output_bytes,&limit_hit);
    if(!dec){out.error=limit_hit?"PYZ member exceeds bounded decompression limit":"PYZ member is encrypted/corrupt or failed zlib decompression";return out;}
    out.type=selected->type;out.marshal_payload=std::move(*dec);out.valid=true;return out;
}

std::string pyinstaller_entry_role(const PyInstArchiveInfo&info,const PyInstEntry&e){return outer_role(info,e);}

PyInstExtractResult extract_pyinstaller(std::span<const std::uint8_t>d,const PyInstArchiveInfo&info,const std::filesystem::path&dir,const CPythonInfo*cpython,std::uint64_t max_output_bytes,std::uint32_t max_output_files,PyInstExtractMode mode){
    PyInstExtractResult r;r.output_dir=dir;r.mode=mode;
    if(!info.valid){r.error="invalid CArchive info";return r;}
    std::string init_error;if(!ensure_output_parent(dir,dir/path_from_utf8(".init"),init_error)){r.error=init_error;return r;}
    std::set<std::string>claimed;
    auto remaining_bytes=[&](){return r.output_bytes<max_output_bytes?max_output_bytes-r.output_bytes:0ull;};
    auto note_omitted=[&](std::uint64_t bytes,const std::string&why){r.budget_exhausted=true;++r.omitted_count;if(bytes<=std::numeric_limits<std::uint64_t>::max()-r.omitted_bytes)r.omitted_bytes+=bytes;else r.omitted_bytes=std::numeric_limits<std::uint64_t>::max();if(r.warnings.size()<256)r.warnings.push_back(why);};
    auto count_role=[&](std::string_view role){if(role=="user"||role=="pyz_user")++r.user_files;else if(role=="bootstrap"||role=="pyz_bootstrap")++r.bootstrap_files;else if(role=="runtime_hook"||role=="runtime_binary")++r.runtime_files;else if(role=="bulk")++r.bulk_files;};
    auto write_budgeted=[&](const std::filesystem::path&p,std::span<const std::uint8_t>bytes,std::string role,std::string source,std::string priority,bool normalized=false,bool recursive=false)->bool{
        auto rel=p.lexically_normal().lexically_relative(dir.lexically_normal());if(rel.empty()||rel.is_absolute()){if(r.warnings.size()<256)r.warnings.push_back("refused output outside PyInstaller root: "+path_utf8(p));return false;}
        auto key=ascii_lower(path_utf8(rel));if(!claimed.insert(key).second){if(r.warnings.size()<256)r.warnings.push_back("refused case-colliding/duplicate PyInstaller output: "+path_utf8(rel));return false;}
        if(bytes.size()>remaining_bytes()||r.files.size()>=max_output_files){note_omitted(bytes.size(),"artifact budget refused PyInstaller output: "+path_utf8(rel));return false;}
        std::string why;if(!write_file_safe(dir,p,bytes,why)){if(r.warnings.size()<256)r.warnings.push_back("PyInstaller output refused/failed: "+why);return false;}
        r.output_bytes+=bytes.size();r.files.push_back(p);r.materialized.push_back({p,std::move(role),std::move(source),std::move(priority),normalized,recursive});count_role(r.materialized.back().role);return true;
    };
    auto write_text=[&](const std::filesystem::path&p,const std::string&text,std::string role,std::string source,std::string priority)->bool{
        return write_budgeted(p,std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(text.data()),text.size()),std::move(role),std::move(source),std::move(priority));
    };

    std::array<std::uint8_t,4>pycmagic{};bool gotmagic=false;
    for(const auto&e:info.entries){
        if(e.typecode!='z')continue;
        auto off=info.archive_start+e.offset;if(off+e.compressed_size>d.size())continue;auto raw=d.subspan(off,e.compressed_size);std::vector<std::uint8_t>tmp;std::span<const std::uint8_t>payload=raw;
        if(e.compression_flag){if(e.uncompressed_size>max_output_bytes)continue;auto dec=zlib_dec(raw,e.uncompressed_size);if(!dec)continue;tmp=std::move(*dec);payload=tmp;}
        if(payload.size()>=8&&std::memcmp(payload.data(),"PYZ\0",4)==0){std::copy_n(payload.begin()+4,4,pycmagic.begin());gotmagic=true;break;}
    }

    const bool bootstrap_proved_normalization=info.bootstrap_reference_status=="REFERENCE_MATCH"&&info.bootstrap_match_mode.find("OPCODE_NORMALIZED")!=std::string::npos;
    auto opcode_map=cpython?cpython_validated_opcode_map(*cpython):std::nullopt;
    const bool normalize_enabled=bootstrap_proved_normalization&&opcode_map.has_value();
    auto official_magic=cpython?cpython_official_pyc_magic(cpython->version_hex):std::nullopt;
    if(normalize_enabled&&!official_magic)r.warnings.push_back("opcode normalization validated, but no exact official CPython pyc magic reference is available; extracted bytecode is kept in target form");

    auto write_code=[&](std::filesystem::path base,std::span<const std::uint8_t>marshal,std::optional<std::array<std::uint8_t,4>>target_magic,std::string_view label,std::string role,std::string priority,bool recursive)->bool{
        if(normalize_enabled&&official_magic){
            auto norm=remap_python_marshal_opcodes(marshal,info.python_version,opcode_map->target_to_official);
            if(norm.valid){
                const bool magic_diff=target_magic&&*target_magic!=*official_magic;
                const bool preserve_target=norm.changed||magic_diff;
                if(preserve_target){
                    auto target=path_with_ascii_suffix(base,target_magic?".target.pyc":".target.marshal");bool ok=false;
                    if(target_magic){auto wrapped=pyc_wrap(marshal,*target_magic,info.python_version);ok=write_budgeted(target,wrapped,role,std::string(label),priority,false,recursive);}else ok=write_budgeted(target,marshal,role,std::string(label),priority,false,recursive);
                    if(!ok)return false;
                    ++r.target_preserved_files;
                }
                auto normalized=path_with_ascii_suffix(base,".pyc");auto wrapped=pyc_wrap(norm.bytes,*official_magic,info.python_version);
                if(!write_budgeted(normalized,wrapped,role,std::string(label),priority,true,recursive))return false;
                ++r.normalized_files;r.normalized_code_units+=norm.rewritten_code_units;return true;
            }
            if(r.warnings.size()<256)r.warnings.push_back("opcode normalization skipped for "+std::string(label)+": "+norm.error);
        }
        auto out=path_with_ascii_suffix(base,target_magic?".pyc":".marshal");
        if(target_magic){auto wrapped=pyc_wrap(marshal,*target_magic,info.python_version);return write_budgeted(out,wrapped,role,std::string(label),priority,false,recursive);}
        return write_budgeted(out,marshal,role,std::string(label),priority,false,recursive);
    };

    std::ostringstream ci;ci<<"name,typecode,compressed_size,uncompressed_size,compressed,role,default_policy\n";
    for(const auto&e:info.entries){auto role=outer_role(info,e);const bool auto_selected=role=="user"||role=="bootstrap"||role=="runtime_hook"||role=="pyz_archive";const bool selected=mode==PyInstExtractMode::Full?(e.typecode!='d'&&e.typecode!='o'):auto_selected;ci<<csvq(e.name)<<','<<csvq(std::string(1,e.typecode))<<','<<e.compressed_size<<','<<e.uncompressed_size<<','<<(e.compression_flag?"true":"false")<<','<<csvq(role)<<','<<(selected?"materialize":"bulk_explicit")<<'\n';if(mode==PyInstExtractMode::AutoCore&&!selected&&e.typecode!='d'&&e.typecode!='o'){++r.policy_omitted_count;auto n=std::uint64_t(e.compression_flag?e.uncompressed_size:e.compressed_size);r.policy_omitted_bytes=n>std::numeric_limits<std::uint64_t>::max()-r.policy_omitted_bytes?std::numeric_limits<std::uint64_t>::max():r.policy_omitted_bytes+n;}}
    r.carchive_inventory=dir/path_from_utf8("inventory.csv");write_text(r.carchive_inventory,ci.str(),"inventory","CArchive","ANALYSIS");

    std::vector<const PyInstEntry*>outer;outer.reserve(info.entries.size());for(const auto&e:info.entries){if(e.typecode=='d'||e.typecode=='o')continue;auto role=outer_role(info,e);if(mode==PyInstExtractMode::AutoCore&&!(role=="user"||role=="bootstrap"||role=="runtime_hook"||role=="pyz_archive"))continue;outer.push_back(&e);}
    std::stable_sort(outer.begin(),outer.end(),[&](const auto*a,const auto*b){auto as=outer_score(info,*a),bs=outer_score(info,*b);if(as!=bs)return as>bs;return a->name<b->name;});

    for(const auto*ep:outer){const auto&e=*ep;auto off=info.archive_start+e.offset;if(off+e.compressed_size>d.size()){if(r.warnings.size()<256)r.warnings.push_back("entry out of bounds during materialization: "+e.name);continue;}auto raw=d.subspan(off,e.compressed_size);std::vector<std::uint8_t>tmp;std::span<const std::uint8_t>payload=raw;
        if(e.compression_flag){if(e.uncompressed_size>max_output_bytes){note_omitted(e.uncompressed_size,"artifact budget refused PyInstaller entry before decompression: "+e.name);continue;}auto dec=zlib_dec(raw,e.uncompressed_size);if(!dec){std::filesystem::path rel;if(!safe_relative_path(e.name,rel)){if(r.warnings.size()<256)r.warnings.push_back("unsafe PyInstaller entry path refused: "+e.name);continue;}auto failed=path_with_ascii_suffix(dir/path_from_utf8("bulk")/rel,".compressed");if(mode==PyInstExtractMode::Full)write_budgeted(failed,raw,"bulk",e.name,"BULK",false,true);if(r.warnings.size()<256)r.warnings.push_back("zlib failed for CArchive entry: "+e.name);continue;}tmp=std::move(*dec);payload=tmp;}
        std::filesystem::path rel;if(!safe_relative_path(e.name,rel)){if(r.warnings.size()<256)r.warnings.push_back("unsafe/cross-platform PyInstaller entry path refused: "+e.name);continue;}
        auto role=outer_role(info,e);
        if(e.typecode=='s'||e.typecode=='m'||e.typecode=='M'){
            std::optional<std::array<std::uint8_t,4>>target_magic;if(gotmagic)target_magic=pycmagic;std::filesystem::path base;
            if(role=="user")base=dir/path_from_utf8("python")/path_from_utf8("user")/rel;
            else if(role=="bootstrap")base=dir/path_from_utf8("python")/path_from_utf8("bootstrap")/rel;
            else base=dir/path_from_utf8("python")/path_from_utf8("runtime")/rel;
            write_code(base,payload,target_magic,e.name,role,role=="user"?"HIGH":"LOW",role=="user");continue;
        }
        if(e.typecode!='z'){
            if(mode!=PyInstExtractMode::Full)continue;
            auto base=(role=="runtime_binary"?dir/path_from_utf8("runtime"):dir/path_from_utf8("bulk"))/rel;write_budgeted(base,payload,role,e.name,role=="runtime_binary"?"LOW":"BULK",false,true);continue;
        }

        auto pyz_path=dir/path_from_utf8("PYZ")/rel;if(!write_budgeted(pyz_path,payload,"pyz_archive",e.name,"HIGH",false,false))continue;
        std::vector<PyzEnt>toc;std::array<std::uint8_t,4>mg{};if(!parse_pyz_toc(payload,toc,mg)){if(r.warnings.size()<256)r.warnings.push_back("PYZ TOC could not be decoded for "+e.name);continue;}r.pyz_entry_count+=toc.size();
        std::ostringstream pi;pi<<"name,type,compressed_size,role,priority_score,policy\n";for(const auto&z:toc)pi<<csvq(z.name)<<','<<z.type<<','<<z.len<<','<<csvq(pyz_role(z.name))<<','<<pyz_score(z.name)<<",materialize_by_priority_budget\n";
        std::filesystem::path inv;if(r.pyz_inventory.empty())inv=dir/path_from_utf8("PYZ")/path_from_utf8("inventory.csv");else inv=path_with_ascii_suffix(pyz_path,".inventory.csv");if(write_text(inv,pi.str(),"inventory",e.name+":PYZ_TOC","ANALYSIS")&&r.pyz_inventory.empty())r.pyz_inventory=inv;
        std::vector<const PyzEnt*>order;order.reserve(toc.size());for(const auto&z:toc)order.push_back(&z);std::stable_sort(order.begin(),order.end(),[](const auto*a,const auto*b){auto as=pyz_score(a->name),bs=pyz_score(b->name);if(as!=bs)return as>bs;return a->name<b->name;});
        for(const auto*zptr:order){const auto&z=*zptr;if(std::uint64_t(z.off)+z.len>payload.size()){if(r.warnings.size()<256)r.warnings.push_back("PYZ entry out of bounds: "+z.name);continue;}std::filesystem::path mod;if(!safe_module_path(z.name,mod)){if(r.warnings.size()<256)r.warnings.push_back("unsafe/cross-platform PYZ module path refused: "+z.name);continue;}auto zr=pyz_role(z.name);std::filesystem::path base=dir/path_from_utf8("PYZ")/path_from_utf8(zr=="user"?"user":(zr=="bootstrap"?"bootstrap":"stdlib"))/mod;if(z.type==1)base/=path_from_utf8("__init__");auto public_role=zr=="user"?"pyz_user":(zr=="bootstrap"?"pyz_bootstrap":"pyz_stdlib");auto priority=zr=="user"?"HIGH":"LOW";
            bool limit_hit=false;auto dec=zlib_dec_unknown(payload.subspan(z.off,z.len),static_cast<std::size_t>(std::min<std::uint64_t>(remaining_bytes(),std::numeric_limits<std::size_t>::max())),&limit_hit);
            if(!dec&&limit_hit){note_omitted(z.len,"artifact budget refused PYZ module before full decompression: "+z.name);continue;}
            if(!dec){auto out=path_with_ascii_suffix(base,".encrypted");if(write_budgeted(out,payload.subspan(z.off,z.len),public_role,z.name,priority,false,zr=="user"))++r.pyz_selected_count;if(r.warnings.size()<256)r.warnings.push_back("PYZ entry is encrypted/corrupt: "+z.name);continue;}
            if(write_code(base,*dec,mg,z.name,public_role,priority,zr=="user"))++r.pyz_selected_count;
        }
    }
    r.success=!r.files.empty()&&(mode==PyInstExtractMode::AutoCore||!r.budget_exhausted);if(mode==PyInstExtractMode::Full&&r.budget_exhausted)r.error="recursive extraction budget exhausted";else if(!r.success)r.error="no PyInstaller artifacts materialized";return r;
}

Finding pyinstaller_finding(const PyInstArchiveInfo&i){Finding f;f.kind="container";f.family="PyInstaller CArchive";if(!i.valid){f.state="FAILED";f.confidence=0.0;f.evidence.push_back(i.error);return f;}f.state="CONFIRMED";f.confidence.reset();f.evidence=i.evidence;f.fields["python_version"]=std::to_string(i.python_version);f.fields["python_library"]=i.python_library;f.fields["entry_count"]=std::to_string(i.entries.size());f.fields["cookie_offset"]=std::to_string(i.cookie_offset);f.fields["archive_start"]=std::to_string(i.archive_start);if(i.heuristic_cookie)f.variant="modified-cookie";f.ranges.push_back({i.archive_start,i.archive_length,"CArchive"});f.suggested_actions={"extract:pyinstaller"};return f;}
namespace {
std::optional<std::vector<std::uint8_t>> bootstrap_payload(std::span<const std::uint8_t>d,const PyInstArchiveInfo&a,const PyInstEntry&e){
    auto off=std::uint64_t(a.archive_start)+e.offset;if(off>d.size()||e.compressed_size>d.size()-off)return{};auto in=d.subspan(static_cast<std::size_t>(off),e.compressed_size);if(!e.compression_flag)return std::vector<std::uint8_t>(in.begin(),in.end());std::vector<std::uint8_t>out(e.uncompressed_size);mz_ulong n=static_cast<mz_ulong>(out.size());auto rc=mz_uncompress(out.data(),&n,in.data(),static_cast<mz_ulong>(in.size()));if(rc!=MZ_OK||n!=e.uncompressed_size)return{};return out;
}
std::span<const std::uint8_t> bootstrap_semantic_payload(std::span<const std::uint8_t> raw,const PyInstEntry& e){
    // Older PyInstaller CArchive type-m entries retain a full pyc header.
    // Exact raw-reference matching above must keep those bytes, but marshal
    // semantic parsing starts after the PEP-552-era 16-byte header.  Detect
    // the header by its pyc CRLF marker rather than by a challenge/version name.
    if((e.typecode=='m'||e.typecode=='M')&&raw.size()>16&&raw[2]==0x0d&&raw[3]==0x0a)return raw.subspan(16);
    return raw;
}
std::string join_labels(const std::set<std::string>&s){std::string o;for(const auto&x:s){if(!o.empty())o+='|';o+=x;}return o;}
}
void analyze_pyinstaller_bootstrap(std::span<const std::uint8_t>d,PyInstArchiveInfo&a,const CPythonInfo*cpython){
    a.bootstrap_modules.clear();a.bootstrap_reference_status.clear();a.bootstrap_reference_label.clear();a.bootstrap_match_mode.clear();a.bootstrap_profile.clear();if(!a.valid)return;
    static constexpr const char* names[]={"struct","pyimod01_os_path","pyimod02_archive","pyimod03_importers","pyimod04_ctypes","pyimod01_archive","pyimod02_importers","pyimod03_ctypes","pyimod04_pywin32"};
    auto exact_reference_available=[&](std::string_view module){for(const auto&r:kPyInstallerLoaderReferences)if(r.python_minor==static_cast<int>(a.python_version)&&module==r.module)return true;return false;};
    auto semantic_reference_available=[&](std::string_view module){for(const auto&r:kPyInstallerLoaderSemanticReferences)if(r.python_minor==static_cast<int>(a.python_version)&&module==r.module)return true;return false;};
    auto semantic_labels=[&](std::string_view module,std::string_view hash){std::set<std::string> labels;for(const auto&r:kPyInstallerLoaderSemanticReferences){if(r.python_minor!=static_cast<int>(a.python_version)||module!=r.module)continue;if(hash==r.semantic_sha256)labels.insert(r.label);}return labels;};
    for(auto name:names){
        auto it=std::find_if(a.entries.begin(),a.entries.end(),[&](const PyInstEntry&e){return e.name==name;});if(it==a.entries.end())continue;
        PyInstBootstrapModuleMatch m;m.name=name;m.reference_available=exact_reference_available(m.name)||semantic_reference_available(m.name);auto raw=bootstrap_payload(d,a,*it);if(!raw){m.state="EXTRACT_FAILED";a.bootstrap_modules.push_back(std::move(m));continue;}
        m.size=raw->size();m.sha256=sha256_bytes(*raw);std::set<std::string> labels;
        for(const auto&r:kPyInstallerLoaderReferences){if(r.python_minor!=static_cast<int>(a.python_version)||m.name!=r.module)continue;if(r.size==m.size&&m.sha256==r.sha256)labels.insert(r.label);}
        if(!labels.empty()){
            m.state="EXACT_MATCH";m.reference_label=join_labels(labels);
        }else{
            // If the target interpreter is a proven pure opcode permutation, normalize the serialized
            // code units in-memory before semantic comparison. This handles bootstrap modules compiled
            // by the modified target compiler without masking real constant/control/data changes.
            if(cpython){
                auto map=cpython_validated_opcode_map(*cpython);
                auto semantic_raw=bootstrap_semantic_payload(*raw,*it);auto normalized=map?remap_python_marshal_opcodes(semantic_raw,a.python_version,map->target_to_official):PythonMarshalOpcodeRewrite{};
                if(map&&normalized.valid&&normalized.changed){
                    m.normalization_source=map->source;m.normalized_code_units=normalized.rewritten_code_units;auto sem=semantic_hash_python_marshal(normalized.bytes,a.python_version);
                    if(sem.valid){m.normalized_semantic_sha256=sem.sha256;auto nlabels=semantic_labels(m.name,m.normalized_semantic_sha256);if(!nlabels.empty()){m.state="OPCODE_NORMALIZED_SEMANTIC_MATCH";m.reference_label=join_labels(nlabels);}}
                    else m.normalize_error="normalized marshal semantic parse failed at +0x"+std::to_string(sem.error_offset)+": "+sem.error;
                }else if(map&&!normalized.valid)m.normalize_error=normalized.error;
            }
            if(m.state.empty()){
                auto semantic_raw=bootstrap_semantic_payload(*raw,*it);auto sem=semantic_hash_python_marshal(semantic_raw,a.python_version);
                if(!sem.valid){m.state="SEMANTIC_PARSE_FAILED";m.semantic_error=sem.error;m.semantic_error_offset=sem.error_offset;}
                else{
                    m.semantic_sha256=sem.sha256;auto semlabels=semantic_labels(m.name,m.semantic_sha256);
                    if(!semlabels.empty()){m.state="SEMANTIC_MATCH";m.reference_label=join_labels(semlabels);}
                    else m.state=m.reference_available?"DIFFERENT":"NO_REFERENCE";
                }
            }
        }
        a.bootstrap_modules.push_back(std::move(m));
    }
    finalize_pyinstaller_bootstrap_reference(a);
}
Finding pyinstaller_bootstrap_finding(const PyInstArchiveInfo&a){
    Finding f;f.kind="reference";f.family="PyInstaller bootstrap";
    if(!a.valid){f.state="FAILED";return f;}
    f.state=(a.bootstrap_reference_status=="REFERENCE_MATCH")?"CONFIRMED":((a.bootstrap_reference_status=="PARTIAL_REFERENCE_MATCH")?"LIKELY":"SUSPECTED");
    f.variant=a.bootstrap_reference_label;
    f.fields["bootstrap_reference_status"]=a.bootstrap_reference_status;
    f.fields["bootstrap_match_mode"]=a.bootstrap_match_mode;
    f.fields["bootstrap_profile"]=a.bootstrap_profile;
    f.fields["python_version"]=std::to_string(a.python_version);
    const auto required=pyinstaller_bootstrap_required_modules(a);std::size_t required_matched=0;
    int exact=0,semantic=0;
    for(const auto&m:a.bootstrap_modules){
        f.fields["module."+m.name]=m.state+(m.reference_label.empty()?"":" "+m.reference_label);if(m.normalized_code_units)f.fields["module."+m.name+".normalized_code_units"]=std::to_string(m.normalized_code_units);if(!m.normalization_source.empty())f.fields["module."+m.name+".normalization_source"]=m.normalization_source;if(!m.normalize_error.empty())f.fields["module."+m.name+".normalize_error"]=m.normalize_error;
        const bool module_matched=m.state=="EXACT_MATCH"||m.state=="SEMANTIC_MATCH"||m.state=="OPCODE_NORMALIZED_SEMANTIC_MATCH";
        if(module_matched&&std::find(required.begin(),required.end(),m.name)!=required.end())++required_matched;
        if(m.state=="EXACT_MATCH"){
            ++exact;f.evidence.push_back(m.name+" exact raw marshal payload match"+(m.reference_label.empty()?"":" ("+m.reference_label+")"));
        }else if(m.state=="SEMANTIC_MATCH"){
            ++semantic;f.evidence.push_back(m.name+" semantic code-object match after ignoring debug/path metadata"+(m.reference_label.empty()?"":" ("+m.reference_label+")"));
        }else if(m.state=="OPCODE_NORMALIZED_SEMANTIC_MATCH"){
            ++semantic;f.evidence.push_back(m.name+" semantic match after validated opcode normalization via "+m.normalization_source+" (rewritten code units="+std::to_string(m.normalized_code_units)+")"+(m.reference_label.empty()?"":" ("+m.reference_label+")"));
        }else if(m.state=="DIFFERENT"){
            f.negative_evidence.push_back(m.name+" differs semantically from known official loader reference(s)");
        }else if(m.state=="SEMANTIC_PARSE_FAILED"){
            std::ostringstream e;e<<m.name<<" semantic marshal parse failed at +0x"<<std::hex<<m.semantic_error_offset<<std::dec<<": "<<m.semantic_error;f.negative_evidence.push_back(e.str());
        }else if(m.state=="EXTRACT_FAILED"){
            f.negative_evidence.push_back(m.name+" could not be decompressed for reference comparison");
        }
    }
    f.fields["exact_modules"]=std::to_string(exact);
    f.fields["semantic_modules"]=std::to_string(semantic);
    f.fields["required_modules"]=std::to_string(required.size());
    f.fields["required_modules_matched"]=std::to_string(required_matched);
    if(a.bootstrap_reference_status=="REFERENCE_MATCH")f.evidence.push_back("all required PyInstaller-owned preload modules for "+a.bootstrap_profile+" match one official loader generation; bootstrap loader layer can be deprioritized");
    else if(a.bootstrap_reference_status=="REFERENCE_PROFILE_AMBIGUOUS")f.negative_evidence.push_back("both legacy and modern bootstrap module profiles are present; loader generation confirmation is intentionally withheld");
    else if(a.bootstrap_reference_status=="REFERENCE_DIFF")f.suggested_actions.push_back("inspect differing preload module(s) before native-runtime analysis");
    return f;
}
}
