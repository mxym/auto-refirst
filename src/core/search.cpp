#include "prts/search.hpp"
#include "prts/mapped_file.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
namespace prts { namespace {
std::string lower(std::string s){for(auto&c:s)c=char(std::tolower(static_cast<unsigned char>(c)));return s;}
int priority(const std::filesystem::path&p){
    auto e=lower(p.extension().string());
    static const std::array<const char*,23> hi={".dat",".bin",".data",".pak",".pck",".rpa",".rpyc",".pyc",".pyz",".luac",".lua",".json",".txt",".xml",".yaml",".yml",".ini",".cfg",".db",".sqlite",".assets",".res",".resource"};
    static const std::array<const char*,14> mid={".js",".ts",".html",".css",".wasm",".dll",".so",".dylib",".class",".dex",".jar",".zip",".wxapkg",".asset"};
    if(std::find(hi.begin(),hi.end(),e)!=hi.end())return 0;
    if(std::find(mid.begin(),mid.end(),e)!=mid.end())return 1;
    if(e==".exe"||e==".elf"||e.empty())return 3;
    return 2;
}
std::string json_escape(std::string_view s){std::string o;for(unsigned char c:s){switch(c){case '\\':o+="\\\\";break;case '"':o+="\\\"";break;case '\n':o+="\\n";break;case '\r':o+="\\r";break;case '\t':o+="\\t";break;default:if(c<0x20){char b[7];std::snprintf(b,sizeof(b),"\\u%04x",c);o+=b;}else o+=char(c);}}return o;}
std::string context_ascii(std::span<const std::uint8_t>d,std::size_t at,std::size_t n,std::size_t ctx){auto a=at>ctx?at-ctx:0;auto b=std::min(d.size(),at+n+ctx);std::string s;s.reserve(b-a);for(auto i=a;i<b;++i){auto c=d[i];s.push_back(c>=0x20&&c<=0x7e?char(c):'.');}return s;}
inline std::uint8_t fold(std::uint8_t c){return c>='A'&&c<='Z'?std::uint8_t(c+32):c;}

// Boyer-Moore-Horspool is a good fit for the dedicated hunt mode: it keeps
// preprocessing tiny, skips over most bytes for multi-byte needles, and works
// identically for the interleaved-zero UTF-16LE representation.  The folded
// variant keeps --search-ignore-case on the same fast path.
class FastPattern {
public:
    FastPattern(std::string_view needle,bool ignore_case,bool utf16):ignore_case_(ignore_case){
        pattern_.reserve(utf16?needle.size()*2:needle.size());
        for(unsigned char c:needle){pattern_.push_back(c);if(utf16)pattern_.push_back(0);}
        const auto m=pattern_.size();skip_.fill(std::max<std::size_t>(1,m));
        if(m>1)for(std::size_t i=0;i+1<m;++i)skip_[key(pattern_[i])]=m-1-i;
    }
    std::size_t size()const noexcept{return pattern_.size();}
    std::size_t find(std::span<const std::uint8_t>d,std::size_t from)const{
        const auto m=pattern_.size();if(!m||from>d.size()||m>d.size()-from)return std::string::npos;
        if(m==1&&!ignore_case_){const void*q=std::memchr(d.data()+from,pattern_[0],d.size()-from);return q?std::size_t(static_cast<const std::uint8_t*>(q)-d.data()):std::string::npos;}
        std::size_t i=from;
        while(i+m<=d.size()){
            std::size_t j=m;
            while(j&&key(d[i+j-1])==key(pattern_[j-1]))--j;
            if(!j)return i;
            i+=skip_[key(d[i+m-1])];
        }
        return std::string::npos;
    }
private:
    std::uint8_t key(std::uint8_t c)const noexcept{return ignore_case_?fold(c):c;}
    std::vector<std::uint8_t>pattern_;
    std::array<std::size_t,256>skip_{};
    bool ignore_case_=false;
};

struct Candidate {std::filesystem::path path;int rank=0;std::uintmax_t size=0;bool size_known=false;};
bool link_or_reparse(const std::filesystem::path&p){std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);if(!ec&&st.type()==std::filesystem::file_type::symlink)return true;
#ifdef _WIN32
    auto a=GetFileAttributesW(p.c_str());if(a!=INVALID_FILE_ATTRIBUTES&&(a&FILE_ATTRIBUTE_REPARSE_POINT))return true;
#endif
    return false;}
void add_candidate(std::vector<Candidate>&files,const std::filesystem::path&p){std::error_code ec;auto sz=std::filesystem::file_size(p,ec);files.push_back({p,priority(p),ec?0:sz,!ec});}
void emit(const std::filesystem::path&p,std::size_t at,std::string_view enc,std::string_view needle,std::span<const std::uint8_t>d,const SearchOptions&o){auto ctx=context_ascii(d,at,enc=="utf16le"?needle.size()*2:needle.size(),o.context);if(o.json_lines){std::cout<<"{\"file\":\""<<json_escape(p.string())<<"\",\"offset\":"<<at<<",\"encoding\":\""<<enc<<"\",\"needle\":\""<<json_escape(needle)<<"\",\"context\":\""<<json_escape(ctx)<<"\"}\n";}else{std::cout<<"[HIT] "<<p.string()<<"  off=0x"<<std::hex<<at<<std::dec<<"  "<<enc<<"  "<<ctx<<"\n";}std::cout.flush();}
}
SearchStats search_tree_streaming(const std::filesystem::path&root,const SearchOptions&o){
    SearchStats st;if(o.needle.empty())return st;std::vector<Candidate>files;std::error_code ec;
    if(link_or_reparse(root))return st;
    if(std::filesystem::is_regular_file(root,ec))add_candidate(files,root);
    else if(std::filesystem::is_directory(root,ec)){
        if(o.recursive){for(std::filesystem::recursive_directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,ec),end;it!=end;it.increment(ec)){if(ec){ec.clear();continue;}if(link_or_reparse(it->path())){it.disable_recursion_pending();continue;}if(it->is_regular_file(ec))add_candidate(files,it->path());}}
        else{for(std::filesystem::directory_iterator it(root,std::filesystem::directory_options::skip_permission_denied,ec),end;it!=end;it.increment(ec)){if(ec){ec.clear();continue;}if(link_or_reparse(it->path()))continue;if(it->is_regular_file(ec))add_candidate(files,it->path());}}
    }
    // Cache size once during enumeration instead of issuing file_size()/stat() from
    // every O(n log n) sort comparison. Small likely-data files still surface first.
    std::stable_sort(files.begin(),files.end(),[](const Candidate&a,const Candidate&b){if(a.rank!=b.rank)return a.rank<b.rank;if(a.size_known&&b.size_known&&a.size!=b.size)return a.size<b.size;return a.path.string()<b.path.string();});
    const FastPattern ascii(o.needle,o.ignore_case,false),utf16(o.needle,o.ignore_case,true);
    for(const auto&f:files){
        try{
            // Directory hunt is a snapshot operation.  If a file changed size after
            // enumeration, skip it rather than scanning bytes that did not belong to
            // the original snapshot.  Besides avoiding races, this prevents redirected
            // search output inside the searched tree from becoming a self-generated hit.
            MappedFile m(f.path);if(!m.valid())continue;if(f.size_known&&m.size()!=f.size)continue;auto d=m.bytes();++st.files;st.bytes+=d.size();
            std::size_t pos=0;while((pos=ascii.find(d,pos))!=std::string::npos){emit(f.path,pos,"ascii",o.needle,d,o);++st.matches;pos+=std::max<std::size_t>(1,ascii.size());}
            pos=0;while((pos=utf16.find(d,pos))!=std::string::npos){emit(f.path,pos,"utf16le",o.needle,d,o);++st.matches;pos+=std::max<std::size_t>(2,utf16.size());}
        }catch(...){}
    }
    return st;
}
}
