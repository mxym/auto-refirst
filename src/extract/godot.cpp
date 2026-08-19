#include "prts/godot.hpp"
#include "prts/byte_search.hpp"
#include "prts/gdscript.hpp"
#include "prts/md5.hpp"
#include "prts/sha256.hpp"
extern "C" {
#include "aes.h"
}
#include <algorithm>
#include <array>
#include <cstring>
#include <cctype>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>
#include <tuple>

namespace prts { namespace {
std::uint32_t le32(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);}
std::uint64_t le64(std::span<const std::uint8_t>d,std::size_t o){if(o+8>d.size())return 0;std::uint64_t v=0;for(int i=0;i<8;i++)v|=std::uint64_t(d[o+i])<<(8*i);return v;}
bool is_magic(std::span<const std::uint8_t>d,std::size_t o){return o+4<=d.size()&&d[o]=='G'&&d[o+1]=='D'&&d[o+2]=='P'&&d[o+3]=='C';}
bool ascii4(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return false;for(int i=0;i<4;i++)if(d[o+i]<0x20||d[o+i]>0x7e)return false;return true;}
std::string trim_path(std::span<const std::uint8_t>s){std::string v(reinterpret_cast<const char*>(s.data()),s.size());while(!v.empty()&&v.back()==0)v.pop_back();return v;}
std::filesystem::path safe_path(std::string s){if(s.rfind("res://",0)==0)s.erase(0,6);std::replace(s.begin(),s.end(),'\\','/');if(s.empty()||s.front()=='/')return{};std::filesystem::path p;for(const auto&part:std::filesystem::path(s)){auto x=part.string();if(x.empty()||x==".")continue;if(x==".."||part.has_root_name()||part.has_root_directory()||x.find(':')!=std::string::npos)return{};p/=part;}return p;}
bool write_file(const std::filesystem::path&p,std::span<const std::uint8_t>d){std::error_code ec;std::filesystem::create_directories(p.parent_path(),ec);std::ofstream f(p,std::ios::binary);if(!f)return false;f.write(reinterpret_cast<const char*>(d.data()),static_cast<std::streamsize>(d.size()));return bool(f);}
std::string output_key(const std::filesystem::path&p){auto s=p.lexically_normal().generic_string();std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});return s;}
std::string hex(std::span<const std::uint8_t>d){std::ostringstream o;o<<std::hex<<std::setfill('0');for(auto b:d)o<<std::setw(2)<<unsigned(b);return o.str();}

void aes256_cfb_decrypt(std::span<const std::uint8_t>cipher,std::span<std::uint8_t>plain,const std::array<std::uint8_t,32>&key,const std::array<std::uint8_t,16>&iv){AES_ctx ctx;AES_init_ctx(&ctx,key.data());std::array<std::uint8_t,16>feedback=iv;for(std::size_t o=0;o<cipher.size();o+=16){auto stream=feedback;AES_ECB_encrypt(&ctx,stream.data());auto n=std::min<std::size_t>(16,cipher.size()-o);for(std::size_t j=0;j<n;j++)plain[o+j]=cipher[o+j]^stream[j];for(std::size_t j=0;j<n;j++)feedback[j]=cipher[o+j];}}
struct DecStream {bool ok=false;std::vector<std::uint8_t>plain;std::size_t consumed=0;};
DecStream decrypt_stream(std::span<const std::uint8_t>d,std::size_t o,const std::array<std::uint8_t,32>&key){DecStream r;if(o+40>d.size())return r;std::array<std::uint8_t,16>want{};std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(o),16,want.begin());auto len=le64(d,o+16);if(len>512ull*1024*1024)return r;std::array<std::uint8_t,16>iv{};std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(o+24),16,iv.begin());auto padded=(len+15)&~15ull;if(o+40+padded>d.size())return r;std::vector<std::uint8_t>all(padded);aes256_cfb_decrypt(d.subspan(o+40,padded),all,key,iv);all.resize(len);if(md5(all)!=want)return r;r.ok=true;r.plain=std::move(all);r.consumed=40+padded;return r;}

bool parse_entries(std::span<const std::uint8_t>src,std::size_t p,std::uint32_t count,std::uint32_t version,std::uint64_t file_base,std::uint64_t pck_off,std::size_t whole_size,std::vector<GodotPckEntry>&out){if(count>1000000)return false;for(std::uint32_t i=0;i<count;i++){if(p+4>src.size())return false;auto sl=le32(src,p);p+=4;if(sl>1u<<20||p+sl>src.size())return false;auto path=trim_path(src.subspan(p,sl));p+=sl;if(path.empty()||path.size()>1u<<20)return false;if(p+8+8+16+(version>=2?4:0)>src.size())return false;auto stored=le64(src,p);p+=8;auto sz=le64(src,p);p+=8;GodotPckEntry e;e.path=std::move(path);e.size=sz;std::copy_n(src.begin()+static_cast<std::ptrdiff_t>(p),16,e.md5.begin());p+=16;if(version>=2){e.flags=le32(src,p);p+=4;}e.encrypted=e.flags&1;e.removal=e.flags&2;e.delta=e.flags&4;if(version>=3)e.offset=file_base+stored;else if(version==2)e.offset=file_base+stored;else e.offset=stored+pck_off;if(!e.removal&&!e.encrypted&&!e.delta&&e.offset+e.size>whole_size)return false;out.push_back(std::move(e));}return true;}

std::optional<GodotPckInfo> parse_at(std::span<const std::uint8_t>d,std::size_t off,bool allow_bad_magic,const std::optional<std::array<std::uint8_t,32>>&key={}){
    if(off+20>d.size())return{};bool standard=is_magic(d,off);if(!standard&&!allow_bad_magic)return{};auto ver=le32(d,off+4),maj=le32(d,off+8),min=le32(d,off+12),pat=le32(d,off+16);if(ver>4||maj==0||maj>25||min>1000||pat>100000)return{};
    GodotPckInfo r;r.pck_offset=off;r.format_version=ver;r.engine_major=maj;r.engine_minor=min;r.engine_patch=pat;r.modified_magic=!standard;std::size_t p=off+20;std::uint64_t stored_base=0;
    if(ver>=2){if(p+12>d.size())return{};r.flags=le32(d,p);p+=4;stored_base=le64(d,p);p+=8;if(r.flags&~7u)return{};}r.encrypted_directory=r.flags&1;r.relative_filebase=r.flags&2;r.sparse_bundle=r.flags&4;r.file_base=stored_base;if(ver==3||ver==4||(ver==2&&r.relative_filebase))r.file_base+=off;
    if(ver==3||ver==4){if(p+8>d.size())return{};r.dir_offset=le64(d,p)+off;p+=8;if(r.sparse_bundle&&r.encrypted_directory&&ver==4){if(p+32>d.size())return{};p+=32;}if(r.dir_offset==0||r.dir_offset+4>d.size())return{};p=r.dir_offset;}else{if(p+64>d.size())return{};p+=64;r.dir_offset=p;}
    if(p+4>d.size())return{};r.file_count=le32(d,p);p+=4;if(r.file_count>1000000)return{};if(r.file_count>0&&ver>=2&&r.file_base>=d.size())return{};
    if(r.encrypted_directory){if(!key){r.valid=true;r.validated=false;r.evidence={"PCK header/version/flags/directory offset are structurally valid","encrypted directory detected","file_count prefix is plausible: "+std::to_string(r.file_count)};return r;}auto dec=decrypt_stream(d,p,*key);if(!dec.ok)return{};if(!parse_entries(dec.plain,0,r.file_count,ver,r.file_base,off,d.size(),r.entries))return{};r.valid=r.validated=true;r.evidence={"encrypted PCK directory decrypted and MD5 verified","directory entries structurally validated"};return r;}
    if(!parse_entries(d,p,r.file_count,ver,r.file_base,off,d.size(),r.entries))return{};r.valid=r.validated=true;r.evidence={"PCK header and directory entries structurally validated","all unencrypted file ranges are in bounds"};return r;
}

std::optional<std::size_t> va_off(const PeInfo&pe,std::uint64_t va,std::size_t size){if(va<pe.image_base)return{};auto rva=va-pe.image_base;for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if(rva>=s.rva&&rva<s.rva+std::uint64_t(span)){auto delta=rva-s.rva;if(delta+size>s.raw_size)return{};return std::size_t(s.raw_offset+delta);}}return{};}
std::optional<std::uint64_t> off_va(const PeInfo&pe,std::size_t off){for(const auto&s:pe.sections)if(off>=s.raw_offset&&off<s.raw_offset+s.raw_size)return pe.image_base+s.rva+(off-s.raw_offset);return{};}
bool va_in_nonexec(const PeInfo&pe,std::uint64_t va){for(const auto&s:pe.sections){auto span=std::max(s.vsize,s.raw_size);if(va>=pe.image_base+s.rva&&va<pe.image_base+s.rva+span)return !(s.characteristics&0x20000000); }return false;}
using KeyCand=GodotNativeKeyCandidate;
using KeyCandidateSet=GodotNativeKeyCandidateSet;
struct ValidatedPckPayload { bool ok=false; std::vector<std::uint8_t> bytes; std::string error; };
ValidatedPckPayload validated_pck_payload(std::span<const std::uint8_t>d,const GodotPckInfo&i,const GodotPckEntry&e){
    ValidatedPckPayload r;
    if(e.removal||e.delta){r.error="PCK entry is a removal/delta record";return r;}
    if(e.size>512ull*1024*1024){r.error="PCK child exceeds D21 validation limit";return r;}
    if(e.encrypted){
        if(!i.key.confirmed){r.error="encrypted PCK child has no confirmed pack key";return r;}
        auto dec=decrypt_stream(d,e.offset,i.key.key);
        if(!dec.ok){r.error="encrypted child envelope/decryption MD5 did not validate";return r;}
        if(dec.plain.size()!=e.size){r.error="encrypted child plaintext size disagrees with PCK directory";return r;}
        if(md5(dec.plain)!=e.md5){r.error="encrypted child plaintext MD5 disagrees with PCK directory";return r;}
        r.bytes=std::move(dec.plain);r.ok=true;return r;
    }
    if(e.offset>d.size()||e.size>d.size()-static_cast<std::size_t>(e.offset)){r.error="PCK child range escapes current input";return r;}
    auto payload=d.subspan(static_cast<std::size_t>(e.offset),static_cast<std::size_t>(e.size));
    if(md5(payload)!=e.md5){r.error="PCK child MD5 disagrees with directory";return r;}
    r.bytes.assign(payload.begin(),payload.end());r.ok=true;return r;
}

struct ProjectBinaryContext { bool complete=false; std::set<std::string> singleton_autoloads; };
ProjectBinaryContext project_binary_context(std::span<const std::uint8_t>d){
    ProjectBinaryContext r;
    if(d.size()<8||std::memcmp(d.data(),"ECFG",4)!=0)return r;
    auto count=le32(d,4);
    if(count>1000000)return r;
    std::size_t p=8;
    for(std::uint32_t n=0;n<count;++n){
        if(p+4>d.size())return r;
        auto kl=le32(d,p);p+=4;
        if(!kl||kl>(1u<<20)||kl>d.size()-p)return r;
        std::string key(reinterpret_cast<const char*>(d.data()+p),kl);p+=kl;
        if(key.find('\0')!=std::string::npos)return r;
        if(p+4>d.size())return r;
        auto vl=le32(d,p);p+=4;
        if(vl>d.size()-p)return r;
        auto value=d.subspan(p,vl);p+=vl;
        if(key.rfind("autoload/",0)!=0)continue;
        auto name=key.substr(9);
        if(name.empty()||value.size()<8)return r;
        auto type=le32(value,0),sl=le32(value,4);
        if(type!=4||sl>value.size()-8)return r;
        auto padded=(std::uint64_t(sl)+3u)&~3ull;
        if(8+padded!=value.size())return r;
        std::string target(reinterpret_cast<const char*>(value.data()+8),sl);
        if(target.find('\0')!=std::string::npos)return r;
        if(!target.empty()&&target.front()=='*')r.singleton_autoloads.insert(std::move(name));
    }
    if(p!=d.size())return r;
    r.complete=true;
    return r;
}

KeyCandidateSet key_candidates(std::span<const std::uint8_t>d,const PeInfo&pe,const GodotArtifactIdentity&source={}){
    constexpr std::size_t kMaxDistinctKeyCandidates=64;
    KeyCandidateSet out;
    if(!pe.valid||!pe.pe64)return out;
    static constexpr std::string_view anchors[]={
        "Can't open encrypted pack directory.",
        "Can't open encrypted pack-referenced file '%s'.",
        "Condition \"fae.is_null()\" is true.",
        "GDScript::load_byte_code"
    };
    std::map<std::string,std::size_t>by_value;
    std::set<std::tuple<std::string,std::uint64_t,std::uint64_t,std::uint64_t>>seen_coordinates;
    for(auto anchor:anchors){
        auto it=d.begin();
        while(true){
            it=std::search(it,d.end(),anchor.begin(),anchor.end());
            if(it==d.end())break;
            auto aoff=std::size_t(it-d.begin());
            auto ava=off_va(pe,aoff);
            if(!ava){++it;continue;}
            for(const auto&xs:pe.sections){
                if(!(xs.characteristics&0x20000000)||!xs.raw_size||xs.raw_offset+xs.raw_size>d.size())continue;
                auto begin=xs.raw_offset,end=xs.raw_offset+xs.raw_size;
                for(std::size_t i=begin;i+7<=end;i++){
                    auto rex=d[i];
                    if((rex&0xf0)!=0x40||!(rex&8)||d[i+1]!=0x8d||((d[i+2]&0xc7)!=0x05))continue;
                    std::int32_t disp=0;std::memcpy(&disp,d.data()+i+3,4);
                    auto iva=pe.image_base+xs.rva+(i-xs.raw_offset);
                    auto target=iva+7+disp;
                    if(target!=*ava)continue;
                    auto center=i;
                    auto ss=center>0x2000?center-0x2000:begin;ss=std::max<std::size_t>(ss,begin);
                    auto ee=std::min<std::size_t>(end,center+0x2000);
                    for(std::size_t m=ss;m+5<ee;m++){
                        if(!(d[m]==0xBA&&d[m+1]==0x20&&d[m+2]==0&&d[m+3]==0&&d[m+4]==0))continue;
                        auto ke=std::min<std::size_t>(ee,m+5+0x200);
                        for(std::size_t j=m+5;j+7<=ke;j++){
                            auto rr=d[j];
                            if((rr&0xf0)!=0x40||!(rr&8)||(d[j+1]!=0x8b&&d[j+1]!=0x8d)||((d[j+2]&0xc7)!=0x05))continue;
                            std::int32_t dp=0;std::memcpy(&dp,d.data()+j+3,4);
                            auto jva=pe.image_base+xs.rva+(j-xs.raw_offset);
                            auto tva=jva+7+dp;
                            std::uint64_t kva=tva;
                            if(d[j+1]==0x8b){auto po=va_off(pe,tva,8);if(!po)continue;kva=le64(d,*po);}
                            if(!va_in_nonexec(pe,kva))continue;
                            auto ko=va_off(pe,kva,32);if(!ko)continue;
                            std::array<std::uint8_t,32>key{};
                            std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(*ko),32,key.begin());
                            if(!std::any_of(key.begin(),key.end(),[](auto b){return b!=0;}))continue;
                            const auto coordinate_id=std::tuple{std::string(anchor),*ava,jva,kva};
                            if(!seen_coordinates.insert(coordinate_id).second)continue;
                            ++out.discovered_coordinate_count;
                            auto hx=hex(key);
                            auto found=by_value.find(hx);
                            GodotNativeKeySourceCoordinate coordinate{std::string(anchor),*ava,jva,kva};
                            if(found!=by_value.end()){
                                out.candidates[found->second].coordinates.push_back(std::move(coordinate));
                                continue;
                            }
                            ++out.discovered_distinct_value_count;
                            if(out.candidates.size()>=kMaxDistinctKeyCandidates){out.budget_exhausted=true;return out;}
                            KeyCand c;
                            c.key=key;c.source=source;c.coordinates.push_back(std::move(coordinate));c.confidence=.65;
                            c.evidence.push_back("PE64 executable code references a Godot pack-encryption anchor, a bounded 32-byte length, and a file-backed non-executable 32-byte value");
                            by_value.emplace(std::move(hx),out.candidates.size());
                            out.candidates.push_back(std::move(c));
                        }
                    }
                }
            }
            ++it;
        }
    }
    return out;
}

bool valid_utf8_source(std::span<const std::uint8_t>d){
    std::size_t i=0;
    while(i<d.size()){
        auto c=d[i++];
        if(c<0x80){if(c==0||(c<0x20&&c!='\n'&&c!='\r'&&c!='\t'))return false;continue;}
        std::uint32_t cp=0;int need=0;
        if((c&0xe0)==0xc0){cp=c&0x1f;need=1;if(cp<2)return false;}
        else if((c&0xf0)==0xe0){cp=c&0x0f;need=2;}
        else if((c&0xf8)==0xf0){cp=c&0x07;need=3;}
        else return false;
        if(i+static_cast<std::size_t>(need)>d.size())return false;
        for(int n=0;n<need;++n){auto x=d[i++];if((x&0xc0)!=0x80)return false;cp=(cp<<6)|(x&0x3f);}
        if((need==2&&cp<0x800)||(need==3&&cp<0x10000)||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return false;
    }
    return true;
}
bool word_prefix(std::string_view line,std::string_view word){
    if(!line.starts_with(word))return false;
    if(line.size()==word.size())return true;
    auto c=static_cast<unsigned char>(line[word.size()]);
    return std::isspace(c)||c==':'||c=='(';
}
std::string_view trim_left(std::string_view value){
    while(!value.empty()&&(value.front()==' '||value.front()=='\t'))value.remove_prefix(1);
    return value;
}
bool identifier_start(char c){auto u=static_cast<unsigned char>(c);return c=='_'||std::isalpha(u);}
bool identifier_continue(char c){auto u=static_cast<unsigned char>(c);return c=='_'||std::isalnum(u);}
std::size_t identifier_length(std::string_view value){
    if(value.empty()||!identifier_start(value.front()))return 0;
    std::size_t n=1;while(n<value.size()&&identifier_continue(value[n]))++n;return n;
}
bool gdscript_anchor_line(std::string_view line){
    if(word_prefix(line,"extends")){
        auto rest=trim_left(line.substr(7));
        if(rest.starts_with("__STRING__"))return true;
        return identifier_length(rest)!=0;
    }
    if(word_prefix(line,"class_name"))return identifier_length(trim_left(line.substr(10)))!=0;
    return false;
}
bool gdscript_declaration_line(std::string_view line){
    if(word_prefix(line,"func")){
        auto rest=trim_left(line.substr(4));auto n=identifier_length(rest);if(!n)return false;
        rest=trim_left(rest.substr(n));return !rest.empty()&&rest.front()=='(';
    }
    for(auto word:{std::string_view("var"),std::string_view("const"),std::string_view("signal"),std::string_view("class")}){
        if(word_prefix(line,word)&&identifier_length(trim_left(line.substr(word.size())))!=0)return true;
    }
    if(word_prefix(line,"enum")){
        auto rest=trim_left(line.substr(4));return (!rest.empty()&&rest.front()=='{')||identifier_length(rest)!=0;
    }
    return false;
}
bool gdscript_source_structure(std::span<const std::uint8_t>d){
    constexpr std::size_t kMaxSourceScriptBytes=4u*1024u*1024u;
    if(d.empty()||d.size()>kMaxSourceScriptBytes||!valid_utf8_source(d))return false;
    std::string_view text(reinterpret_cast<const char*>(d.data()),d.size());
    bool anchor=false,declaration=false,in_comment=false,escaped=false;
    char quote=0;bool triple=false;std::size_t meaningful=0;
    std::vector<char>delimiters;std::string line_code;line_code.reserve(256);
    auto inspect_line=[&](){
        auto line=std::string_view(line_code);
        while(!line.empty()&&(line.front()==' '||line.front()=='\t'||line.front()=='\r'))line.remove_prefix(1);
        while(!line.empty()&&(line.back()==' '||line.back()=='\t'||line.back()=='\r'))line.remove_suffix(1);
        if(line.empty())return;
        ++meaningful;
        if(gdscript_anchor_line(line))anchor=true;
        if(gdscript_declaration_line(line))declaration=true;
    };
    for(std::size_t i=0;i<=text.size();++i){
        const char c=i<text.size()?text[i]:'\n';
        if(in_comment){if(c=='\n'){in_comment=false;inspect_line();line_code.clear();}continue;}
        if(quote){
            if(triple){
                if(i+2<text.size()&&text[i]==quote&&text[i+1]==quote&&text[i+2]==quote){quote=0;triple=false;i+=2;}
                else if(c=='\n'){inspect_line();line_code.clear();}
                continue;
            }
            if(c=='\n')return false;
            if(escaped){escaped=false;continue;}
            if(c=='\\'){escaped=true;continue;}
            if(c==quote)quote=0;
            continue;
        }
        if(c=='#'){in_comment=true;continue;}
        if(c=='\''||c=='"'){
            if(i+2<text.size()&&text[i+1]==c&&text[i+2]==c){quote=c;triple=true;i+=2;}
            else quote=c;
            line_code.append("__STRING__");continue;
        }
        if(c=='('||c=='['||c=='{')delimiters.push_back(c);
        else if(c==')'||c==']'||c=='}'){
            if(delimiters.empty())return false;
            const auto open=delimiters.back();
            if((c==')'&&open!='(')||(c==']'&&open!='[')||(c=='}'&&open!='{'))return false;
            delimiters.pop_back();
        }
        if(c=='\n'){inspect_line();line_code.clear();}
        else line_code.push_back(c);
    }
    // This is deliberately a bounded lexical/source-structure recognizer, not a
    // GDScript parser.  It ignores comments and quoted/triple-quoted text so a
    // filename or keyword string cannot manufacture script scope.  The already
    // authenticated PCK entry path/MD5 establishes exact child identity first.
    return !quote&&!in_comment&&delimiters.empty()&&meaningful>=2&&anchor&&declaration;
}
bool encrypted_script_path(std::string path){std::transform(path.begin(),path.end(),path.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});return path.ends_with(".gdc")||path.ends_with(".gd");}
bool validated_godot_script_plaintext(std::string path,std::span<const std::uint8_t>plain){
    std::transform(path.begin(),path.end(),path.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    if(path.ends_with(".gdc"))return analyze_gdscript_buffer(plain).valid;
    if(path.ends_with(".gd"))return gdscript_source_structure(plain);
    return false;
}
DecStream decrypt_pck_entry_verified(std::span<const std::uint8_t>d,const GodotPckEntry&e,const std::array<std::uint8_t,32>&key){DecStream r;if(!e.encrypted||e.removal||e.delta)return r;auto dec=decrypt_stream(d,e.offset,key);if(!dec.ok||dec.plain.size()!=e.size||md5(dec.plain)!=e.md5)return r;return dec;}
void set_key_candidate(GodotKeyInfo&out,const KeyCand&c){out.found=true;out.key=c.key;out.confidence=c.confidence;if(!c.coordinates.empty()){const auto&x=c.coordinates.front();out.anchor=x.anchor;out.anchor_va=x.anchor_va;out.load_va=x.load_va;out.key_va=x.key_va;}}
void validate_encrypted_scripts(std::span<const std::uint8_t>d,const GodotPckInfo&pack,GodotKeyInfo&key){
    constexpr std::size_t kMaxScriptValidations=64;std::size_t attempted=0;
    for(const auto&e:pack.entries){if(!e.encrypted||e.removal||e.delta||!encrypted_script_path(e.path))continue;++key.encrypted_script_count;if(attempted>=kMaxScriptValidations){key.script_validation_truncated=true;continue;}++attempted;auto dec=decrypt_pck_entry_verified(d,e,key.key);if(!dec.ok)continue;if(!validated_godot_script_plaintext(e.path,dec.plain))continue;++key.validated_script_count;if(key.validated_script_path.empty())key.validated_script_path=e.path;}
    key.script_validated=key.validated_script_count!=0;
}
}

namespace {
std::string hex_u64(std::uint64_t value){std::ostringstream o;o<<"0x"<<std::hex<<value;return o.str();}
std::string pck_entry_coordinate(std::size_t index,const GodotPckEntry&e){
    return "PCK:entry["+std::to_string(index)+"] path="+e.path+" payload=file+"+hex_u64(e.offset);
}
bool external_core_path(std::string path){
    std::transform(path.begin(),path.end(),path.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    auto slash=path.find_last_of('/');auto base=slash==std::string::npos?path:path.substr(slash+1);
    return path.ends_with(".gdc")||path.ends_with(".gd")||path.ends_with(".gdextension")||base=="project.binary"||base=="project.godot";
}
bool missing_output(const std::filesystem::path&p){
    std::error_code ec;auto st=std::filesystem::symlink_status(p,ec);
    if(ec==std::errc::no_such_file_or_directory)return true;
    if(ec)return false;
    return st.type()==std::filesystem::file_type::not_found;
}
bool prepare_safe_output_parent(const std::filesystem::path&root,const std::filesystem::path&rel){
    std::filesystem::path cur=root;std::error_code ec;
    for(const auto&part:rel.parent_path()){
        cur/=part;auto st=std::filesystem::symlink_status(cur,ec);
        if(ec==std::errc::no_such_file_or_directory){ec.clear();if(!std::filesystem::create_directory(cur,ec)||ec)return false;continue;}
        if(ec||st.type()!=std::filesystem::file_type::directory)return false;
    }
    return true;
}
std::size_t distinct_key_va_count(const GodotNativeKeyCandidate&candidate){
    std::set<std::uint64_t>values;for(const auto&c:candidate.coordinates)values.insert(c.key_va);return values.size();
}
std::string canonical_source_coordinate(const GodotNativeKeyCandidate&candidate){
    if(candidate.coordinates.empty())return{};
    auto coords=candidate.coordinates;
    std::sort(coords.begin(),coords.end(),[](const auto&a,const auto&b){
        return std::tie(a.key_va,a.load_va,a.anchor_va,a.anchor)<std::tie(b.key_va,b.load_va,b.anchor_va,b.anchor);
    });
    const auto&c=coords.front();
    return "PE:key_va="+hex_u64(c.key_va)+";load_va="+hex_u64(c.load_va)+";anchor_va="+hex_u64(c.anchor_va)+";anchor="+c.anchor;
}
}

GodotNativeKeyCandidateSet discover_godot_native_key_candidates(std::span<const std::uint8_t>d,const PeInfo&pe,GodotArtifactIdentity source){
    return key_candidates(d,pe,source);
}

GodotExternalPckInspection inspect_godot_external_pck(std::span<const std::uint8_t>d,GodotArtifactIdentity target){
    GodotExternalPckInspection out;out.target=std::move(target);
    if(d.size()<4||!is_magic(d,0)){out.error="exact target is not a standalone Godot PCK at file offset 0";return out;}
    auto pack=parse_at(d,0,false);
    if(!pack||!pack->valid){out.error="exact target PCK header/directory geometry is invalid";return out;}
    out.valid=true;out.pck_offset=pack->pck_offset;out.format_version=pack->format_version;
    out.engine_major=pack->engine_major;out.engine_minor=pack->engine_minor;out.engine_patch=pack->engine_patch;
    out.flags=pack->flags;out.file_count=pack->file_count;out.encrypted_directory=pack->encrypted_directory;
    out.relative_filebase=pack->relative_filebase;out.sparse_bundle=pack->sparse_bundle;
    out.directory_stream_offset=pack->dir_offset+4;
    out.target_coordinate="PCK:directory_stream=file+"+hex_u64(out.directory_stream_offset);
    out.evidence=pack->evidence;
    if(out.encrypted_directory)out.evidence.push_back("exact target exposes an encrypted directory stream whose plaintext MD5 cannot be checked without an external key");
    else if(!std::any_of(pack->entries.begin(),pack->entries.end(),[](const auto&e){return e.encrypted&&!e.removal&&!e.delta;}))
        out.evidence.push_back("exact target contains no encrypted semantic surface for an external pack key");
    return out;
}

GodotExternalPckCandidateValidation validate_godot_key_candidate_against_pck(
    std::span<const std::uint8_t>d,const GodotExternalPckInspection&inspection,
    const GodotNativeKeyCandidate&candidate,std::size_t candidate_index){
    constexpr std::size_t kMaxEncryptedFileProbes=16;
    GodotExternalPckCandidateValidation out;out.candidate_index=candidate_index;out.key=candidate.key;
    out.target_valid=inspection.valid;out.target_coordinate=inspection.target_coordinate;
    if(!inspection.valid){out.error="target inspection is invalid";return out;}
    if(inspection.pck_offset!=0){out.error="external PCK oracle requires exact target offset 0";return out;}

    if(inspection.encrypted_directory){
        if(inspection.file_count==0){out.error="encrypted directory has zero entries and therefore no key-dependent ciphertext; it cannot validate a candidate";return out;}
        auto pack=parse_at(d,0,false,candidate.key);
        if(!pack||!pack->validated){out.error="candidate did not decrypt the exact PCK directory to its authenticated MD5 and valid entry structure";return out;}
        out.validated=true;out.directory_md5_validated=true;out.directory_structure_validated=true;out.pack=std::move(*pack);
        set_key_candidate(out.pack.key,candidate);out.pack.key.confirmed=true;out.pack.key.directory_validated=true;out.pack.key.confidence.reset();
        out.evidence.push_back("candidate decrypted the exact target directory envelope and matched its embedded plaintext MD5");
        out.evidence.push_back("decrypted directory parsed exactly under the target PCK version/flags/file-count geometry");
    }else{
        auto pack=parse_at(d,0,false);
        if(!pack||!pack->validated){out.error="target PCK directory did not independently validate";return out;}
        out.pack=std::move(*pack);
        set_key_candidate(out.pack.key,candidate);out.pack.key.confidence.reset();
    }

    // Child checks are an independent, bounded strengthening plane.  Directory
    // validation remains directory-scoped even if no child decrypts.
    for(std::size_t i=0;i<out.pack.entries.size()&&out.encrypted_file_probe_count<kMaxEncryptedFileProbes;++i){
        const auto&e=out.pack.entries[i];if(!e.encrypted||e.removal||e.delta)continue;
        ++out.encrypted_file_probe_count;
        auto dec=decrypt_pck_entry_verified(d,e,candidate.key);if(!dec.ok)continue;
        ++out.encrypted_file_validated_count;
        if(out.target_coordinate==inspection.target_coordinate&&!inspection.encrypted_directory)out.target_coordinate=pck_entry_coordinate(i,e);
    }
    if(!inspection.encrypted_directory){
        if(!out.encrypted_file_validated_count){out.pack={};out.error="candidate did not authenticate any bounded encrypted child of the exact target";return out;}
        out.validated=true;out.pack.key.confirmed=true;out.pack.key.encrypted_file_validated=true;
        out.evidence.push_back("candidate authenticated at least one exact encrypted PCK child envelope and directory plaintext MD5");
    }else if(out.encrypted_file_validated_count){out.pack.key.encrypted_file_validated=true;}
    out.pack.key.encrypted_probe_count=out.encrypted_file_probe_count;

    validate_encrypted_scripts(d,out.pack,out.pack.key);
    out.encrypted_script_count=out.pack.key.encrypted_script_count;
    out.encrypted_script_validated_count=out.pack.key.validated_script_count;
    out.validated_script_path=out.pack.key.validated_script_path;
    if(out.encrypted_script_validated_count){
        for(std::size_t i=0;i<out.pack.entries.size();++i){
            const auto&e=out.pack.entries[i];
            if(!e.encrypted||e.removal||e.delta||!encrypted_script_path(e.path))continue;
            auto dec=decrypt_pck_entry_verified(d,e,candidate.key);
            if(!dec.ok||!validated_godot_script_plaintext(e.path,dec.plain))continue;
            out.validated_script_entry_index=i;
            out.validated_script_path=e.path;
            out.validated_script_target_coordinate=pck_entry_coordinate(i,e);
            break;
        }
        out.evidence.push_back("same candidate produced exact encrypted GDScript plaintext that matched entry MD5 and bounded GDScript structure");
    }
    return out;
}

GodotExternalPckValidation reduce_godot_external_pck_validations(
    const GodotExternalPckInspection&inspection,const GodotNativeKeyCandidateSet&candidates,
    std::span<const GodotExternalPckCandidateValidation> validations){
    GodotExternalPckValidation out;out.target_valid=inspection.valid;out.target=inspection.target;
    out.target_coordinate=inspection.target_coordinate;out.candidate_budget_exhausted=candidates.budget_exhausted;
    if(!inspection.valid){out.error="target PCK inspection failed";return out;}
    out.validation_attempts=validations.size();
    bool validation_coverage_complete=validations.size()==candidates.candidates.size();
    std::vector<bool>seen(candidates.candidates.size(),false);
    std::map<std::string,const GodotExternalPckCandidateValidation*> matches;
    for(const auto&v:validations){
        if(v.candidate_index>=candidates.candidates.size()||seen[v.candidate_index]||v.key!=candidates.candidates[v.candidate_index].key){validation_coverage_complete=false;continue;}
        seen[v.candidate_index]=true;
        if(v.target_valid&&v.validated)matches.emplace(hex(v.key),&v);
    }
    if(!std::all_of(seen.begin(),seen.end(),[](bool x){return x;}))validation_coverage_complete=false;
    if(!validation_coverage_complete)out.ambiguity_reasons.push_back("candidate validation coverage is incomplete or inconsistent; ambiguity cannot be closed");
    out.matching_candidate_count=matches.size();
    for(const auto&[key,v]:matches)out.matching_candidate_indices.push_back(v->candidate_index);
    if(matches.empty()){out.ambiguity_reasons.push_back("no bounded source candidate validated the exact target oracle");return out;}
    if(matches.size()!=1){out.ambiguity_reasons.push_back(std::to_string(matches.size())+" distinct source key values independently validate the same exact target; semantic value is ambiguous");return out;}
    out.value_unique=true;
    const auto&match=*matches.begin()->second;
    out.validated_key=match.key;out.pack=match.pack;out.directory_md5_validated=match.directory_md5_validated;
    out.directory_structure_validated=match.directory_structure_validated;out.encrypted_file_probe_count=match.encrypted_file_probe_count;
    out.encrypted_file_validated_count=match.encrypted_file_validated_count;out.encrypted_script_count=match.encrypted_script_count;
    out.encrypted_script_validated_count=match.encrypted_script_validated_count;out.validated_script_path=match.validated_script_path;
    out.validated_script_entry_index=match.validated_script_entry_index;out.validated_script_target_coordinate=match.validated_script_target_coordinate;
    out.target_coordinate=match.target_coordinate;out.evidence=match.evidence;

    auto it=std::find_if(candidates.candidates.begin(),candidates.candidates.end(),[&](const auto&c){return c.key==match.key;});
    if(it==candidates.candidates.end()){out.ambiguity_reasons.push_back("successful oracle result has no matching retained source candidate provenance");return out;}
    out.validated_candidate=*it;out.source=it->source;
    out.matching_source_coordinate_count=distinct_key_va_count(*it);
    out.source_coordinate=canonical_source_coordinate(*it);
    if(out.matching_source_coordinate_count!=1){out.source_coordinate_ambiguous=true;out.ambiguity_reasons.push_back("validated key value is unique but is independently stored at "+std::to_string(out.matching_source_coordinate_count)+" source key VAs");}
    if(candidates.budget_exhausted)out.ambiguity_reasons.push_back("source distinct-key candidate budget was exhausted before ambiguity could be closed");
    if(out.source_coordinate.empty())out.ambiguity_reasons.push_back("validated key value lacks an exact source coordinate");
    out.resolved=out.ambiguity_reasons.empty();
    if(out.resolved)out.evidence.push_back("all retained bounded distinct key values were tested; exactly one value matched and its source key VA is unique");
    return out;
}

GodotExternalPckValidation validate_godot_key_candidates_against_pck(
    std::span<const std::uint8_t>d,const GodotExternalPckInspection&inspection,const GodotNativeKeyCandidateSet&candidates){
    std::vector<GodotExternalPckCandidateValidation> validations;validations.reserve(candidates.candidates.size());
    for(std::size_t i=0;i<candidates.candidates.size();++i)
        validations.push_back(validate_godot_key_candidate_against_pck(d,inspection,candidates.candidates[i],i));
    return reduce_godot_external_pck_validations(inspection,candidates,validations);
}

GodotExternalPckMaterializeResult materialize_godot_external_pck_core(
    std::span<const std::uint8_t>d,const GodotExternalPckValidation&validation,const std::filesystem::path&dir,
    std::uint64_t max_output_bytes,std::uint32_t max_output_files){
    GodotExternalPckMaterializeResult out;out.output_dir=dir;
    if(!validation.resolved||!validation.value_unique){out.error="external PCK semantic key closure is unresolved";return out;}
    if(!validation.pack.validated||!validation.pack.key.confirmed){out.error="validated target pack/key state is unavailable";return out;}
    std::error_code ec;auto root_state=std::filesystem::symlink_status(dir,ec);
    if(!ec&&root_state.type()==std::filesystem::file_type::symlink){out.error="refusing symlink materialization root";return out;}
    ec.clear();std::filesystem::create_directories(dir,ec);if(ec){out.error="cannot create external PCK output directory: "+ec.message();return out;}
    std::size_t selected=0;std::set<std::string>output_paths;
    for(std::size_t i=0;i<validation.pack.entries.size();++i){
        const auto&e=validation.pack.entries[i];if(e.removal||e.delta||!external_core_path(e.path))continue;++selected;
        if(out.children.size()>=max_output_files||e.size>max_output_bytes-out.output_bytes){out.budget_exhausted=true;++out.omitted_count;out.omitted_bytes=e.size>std::numeric_limits<std::uint64_t>::max()-out.omitted_bytes?std::numeric_limits<std::uint64_t>::max():out.omitted_bytes+e.size;continue;}
        auto payload=validated_pck_payload(d,validation.pack,e);if(!payload.ok){out.warnings.push_back("decisive child integrity failed: "+e.path+": "+payload.error);continue;}
        auto rel=safe_path(e.path);if(rel.empty()){out.warnings.push_back("unsafe decisive child path refused: "+e.path);continue;}
        auto dest=dir/rel;auto outkey=output_key(dest);
        if(!output_paths.insert(outkey).second){out.warnings.push_back("duplicate/case-colliding decisive child output refused: "+e.path);continue;}
        if(!prepare_safe_output_parent(dir,rel)||!missing_output(dest)){out.warnings.push_back("existing/non-regular/symlink decisive child output refused: "+dest.string());continue;}
        if(!write_file(dest,payload.bytes)){out.warnings.push_back("write failed: "+dest.string());continue;}
        auto sha=sha256_file(dest);if(sha.empty()){std::filesystem::remove(dest,ec);out.warnings.push_back("post-write SHA-256 failed: "+dest.string());continue;}
        GodotExternalPckMaterializedChild child;child.entry_index=i;child.entry_path=e.path;child.output_path=dest;child.sha256=std::move(sha);
        child.target_coordinate=pck_entry_coordinate(i,e);child.encrypted=e.encrypted;
        child.script=encrypted_script_path(e.path)||std::string_view(e.path).ends_with(".gd");
        if(e.encrypted&&encrypted_script_path(e.path)){
            child.validation_state=validated_godot_script_plaintext(e.path,payload.bytes)?"KEY_VALIDATED_FOR_SCRIPT":"ENCRYPTED_FILE_KEY_VALIDATED";
        }else if(e.encrypted)child.validation_state="ENCRYPTED_FILE_KEY_VALIDATED";
        else child.validation_state="PCK_ENTRY_MD5_VALIDATED";
        out.output_bytes+=payload.bytes.size();out.children.push_back(std::move(child));
    }
    out.success=!out.children.empty()&&!out.budget_exhausted;
    if(!selected)out.error="validated target contains no decisive script/project core entries";
    else if(out.children.empty()&&out.error.empty())out.error="no decisive script/project child passed strict materialization validation";
    else if(out.budget_exhausted)out.error="decisive child materialization budget exhausted";
    return out;
}

GodotPckInfo detect_godot(std::span<const std::uint8_t>d,const PeInfo&pe){
    GodotPckInfo best;std::vector<std::size_t>offs;
    for(std::size_t i=0;;){i=detail::find_exact(d,"GDPC",i);if(i==std::string::npos)break;offs.push_back(i++);}
    for(auto o:offs){auto x=parse_at(d,o,false);if(x&&(!best.valid||x->validated)){best=*x;if(x->validated)break;}}
    // Mutation-resistant PCK header search. For standalone files always test offset 0.
    // For PE-wide scans, require independent Godot anchors first to avoid millions of
    // speculative parse attempts on unrelated large executables.
    if(!best.valid&&d.size()>=100){
        if(auto x=parse_at(d,0,true);x&&x->validated)best=*x;
        if(!best.valid&&pe.valid){
            const std::string_view a1="Godot Engine",a2="encrypted pack",a3="GDScript::";
            const bool anchored=std::search(d.begin(),d.end(),a1.begin(),a1.end())!=d.end()||std::search(d.begin(),d.end(),a2.begin(),a2.end())!=d.end()||std::search(d.begin(),d.end(),a3.begin(),a3.end())!=d.end();
            if(anchored){for(std::size_t o=8;o+100<d.size();o+=8){if(!ascii4(d,o))continue;auto x=parse_at(d,o,true);if(x&&x->validated){best=*x;break;}}}
        }
    }
    auto cands=key_candidates(d,pe);best.key.native_candidate_count=cands.discovered_distinct_value_count;best.key.candidate_budget_exhausted=cands.budget_exhausted;
    if(best.valid&&(best.encrypted_directory||std::any_of(best.entries.begin(),best.entries.end(),[](const auto&e){return e.encrypted;}))){
        if(best.encrypted_directory){
            if(best.file_count==0){
                best.evidence.push_back("encrypted directory has zero entries and no key-dependent ciphertext; directory key validation is not discriminating");
                if(!cands.candidates.empty())set_key_candidate(best.key,cands.candidates.front());
                return best;
            }
            struct Match{std::size_t candidate_index=0;GodotPckInfo pack;};std::vector<Match>matches;
            for(std::size_t ci=0;ci<cands.candidates.size();++ci){
                ++best.key.candidate_validation_attempts;
                auto x=parse_at(d,best.pck_offset,best.modified_magic,cands.candidates[ci].key);
                if(x&&x->validated)matches.push_back({ci,std::move(*x)});
            }
            if(matches.size()==1&&!cands.budget_exhausted){
                auto attempts=best.key.candidate_validation_attempts,discovered=best.key.native_candidate_count;
                best=std::move(matches.front().pack);best.key.native_candidate_count=discovered;best.key.candidate_validation_attempts=attempts;
                set_key_candidate(best.key,cands.candidates[matches.front().candidate_index]);best.key.confirmed=true;best.key.directory_validated=true;best.key.confidence.reset();
                validate_encrypted_scripts(d,best,best.key);best.evidence.push_back("recovered 256-bit key uniquely validated by encrypted-directory MD5 after testing the complete retained candidate set");
                if(best.key.script_validated)best.evidence.push_back("same key decrypted encrypted GDScript plaintext that independently passed structural analysis");
                return best;
            }
            if(matches.size()>1)best.evidence.push_back("multiple distinct retained key values validate the encrypted directory; key state remains unresolved");
            if(matches.size()==1&&cands.budget_exhausted)best.evidence.push_back("a retained key validates the encrypted directory, but candidate-budget exhaustion prevents uniqueness closure");
        }else{
            constexpr std::size_t kMaxProbeEntries=8;std::vector<const GodotPckEntry*>probes;probes.reserve(kMaxProbeEntries);
            // Prefer encrypted GDScript so a successful candidate can immediately receive the
            // stronger independent structural check; then fill the fixed probe budget with
            // other encrypted children. This is a bounded probe set, not all-files Cartesian work.
            for(const auto&e:best.entries)if(e.encrypted&&!e.removal&&!e.delta&&encrypted_script_path(e.path)&&probes.size()<kMaxProbeEntries)probes.push_back(&e);
            for(const auto&e:best.entries)if(e.encrypted&&!e.removal&&!e.delta&&!encrypted_script_path(e.path)&&probes.size()<kMaxProbeEntries)probes.push_back(&e);
            std::vector<std::size_t>matches;
            for(std::size_t ci=0;ci<cands.candidates.size();++ci){
                ++best.key.candidate_validation_attempts;bool accepted=false;
                for(const auto*e:probes){++best.key.encrypted_probe_count;auto dec=decrypt_pck_entry_verified(d,*e,cands.candidates[ci].key);if(dec.ok)accepted=true;}
                if(accepted)matches.push_back(ci);
            }
            if(matches.size()==1&&!cands.budget_exhausted){
                auto attempts=best.key.candidate_validation_attempts,probe_count=best.key.encrypted_probe_count,discovered=best.key.native_candidate_count;
                set_key_candidate(best.key,cands.candidates[matches.front()]);best.key.native_candidate_count=discovered;best.key.candidate_validation_attempts=attempts;best.key.encrypted_probe_count=probe_count;
                best.key.confirmed=true;best.key.encrypted_file_validated=true;best.key.confidence.reset();validate_encrypted_scripts(d,best,best.key);
                best.evidence.push_back("recovered 256-bit key uniquely validated by encrypted-file envelope + PCK-directory plaintext MD5 after testing the complete retained candidate set");
                if(best.key.script_validated)best.evidence.push_back("same key decrypted encrypted GDScript plaintext that independently passed structural analysis");
                return best;
            }
            if(matches.size()>1)best.evidence.push_back("multiple distinct retained key values validate an encrypted child; key state remains unresolved");
            if(matches.size()==1&&cands.budget_exhausted)best.evidence.push_back("a retained key validates an encrypted child, but candidate-budget exhaustion prevents uniqueness closure");
        }
        if(!cands.candidates.empty()){
            auto attempts=best.key.candidate_validation_attempts,probe_count=best.key.encrypted_probe_count,discovered=best.key.native_candidate_count;auto exhausted=best.key.candidate_budget_exhausted;
            set_key_candidate(best.key,cands.candidates.front());best.key.native_candidate_count=discovered;best.key.candidate_budget_exhausted=exhausted;best.key.candidate_validation_attempts=attempts;best.key.encrypted_probe_count=probe_count;
        }
    }
    return best;
}

void analyze_godot_gdextensions(std::span<const std::uint8_t>d,GodotPckInfo&i){
    constexpr std::size_t kMaxDescriptors=64,kMaxScripts=4096;constexpr std::uint64_t kMaxScriptBytes=64ull*1024*1024;
    i.gdextension_state="NOT_PRESENT";i.gdextension_descriptor_candidates=0;i.gdextension_descriptor_processed=0;i.gdextension_script_candidate_count=0;i.gdextension_script_candidate_bytes=0;i.gdextension_analysis_limited=false;i.gdextension_bundle_valid_count=0;i.gdextension_native_analyzed_count=0;i.gdextension_exact_registration_count=0;i.gdextension_bounded_bridge_count=0;i.gdextension_unresolved_count=0;i.gdextension_failed_count=0;i.gdextension_script_analysis_count=0;i.gdextension_super_call_count=0;i.gdextension_script_link_ambiguous_count=0;i.gdextensions.clear();i.gdextension_script_links.clear();
    if(!i.validated||i.entries.empty())return;
    struct Route{std::size_t index=0;std::string path;};std::vector<Route>routes;routes.reserve(i.entries.size());std::map<std::string,std::vector<std::size_t>>by_path;
    for(std::size_t z=0;z<i.entries.size();++z){const auto&e=i.entries[z];if(e.removal||e.delta)continue;if(auto p=normalize_gdextension_resource_path(e.path)){routes.push_back({z,*p});by_path[*p].push_back(z);}}
    std::vector<Route>descriptors;for(const auto&r:routes)if(r.path.size()>=12&&r.path.compare(r.path.size()-12,12,".gdextension")==0)descriptors.push_back(r);i.gdextension_descriptor_candidates=descriptors.size();if(descriptors.empty())return;if(descriptors.size()>kMaxDescriptors)i.gdextension_analysis_limited=true;

    for(std::size_t di=0;di<descriptors.size()&&di<kMaxDescriptors;++di){const auto&dr=descriptors[di];++i.gdextension_descriptor_processed;
        auto dp=validated_pck_payload(d,i,i.entries[dr.index]);
        if(!dp.ok){GDExtensionBundleInfo b;b.descriptor_path=dr.path;b.descriptor_entry_index=dr.index;b.error="descriptor PCK child integrity failed: "+dp.error;i.gdextensions.push_back(std::move(b));++i.gdextension_failed_count;continue;}
        auto parsed=parse_gdextension_descriptor(dp.bytes);std::set<std::string>declared;if(parsed.valid)for(const auto&x:parsed.libraries)if(auto p=normalize_gdextension_resource_path(x.path))declared.insert(std::move(*p));
        struct Owned{std::string path;std::size_t index=0;bool valid=false;std::vector<std::uint8_t>bytes;};std::vector<Owned>owned;
        if(parsed.valid)for(const auto&path:declared){auto it=by_path.find(path);if(it==by_path.end())continue;for(auto entry_index:it->second){auto p=validated_pck_payload(d,i,i.entries[entry_index]);owned.push_back({path,entry_index,p.ok,std::move(p.bytes)});}}
        std::vector<GDExtensionPckChildView>children;children.reserve(owned.size());for(auto&x:owned)children.push_back({x.path,x.bytes,x.index,x.valid});
        GDExtensionPckChildView desc{dr.path,dp.bytes,dr.index,true};auto b=analyze_gdextension_pck_bundle(desc,children);i.gdextension_native_analyzed_count+=b.analyzed_native_count;if(b.valid){++i.gdextension_bundle_valid_count;if(b.state=="BOUNDED_BRIDGE_CANDIDATES")++i.gdextension_bounded_bridge_count;else if(b.state=="EXACT_REGISTRATION")++i.gdextension_exact_registration_count;else ++i.gdextension_unresolved_count;}else ++i.gdextension_failed_count;i.gdextensions.push_back(std::move(b));
    }
    if(i.gdextension_bounded_bridge_count)i.gdextension_state="BOUNDED_BRIDGE_CANDIDATES";else if(i.gdextension_exact_registration_count)i.gdextension_state="EXACT_REGISTRATION";else if(i.gdextension_unresolved_count)i.gdextension_state="UNRESOLVED_REGISTRATION";else i.gdextension_state="FAILED";

    // Script/native correlation is intentionally narrower than token-name matching. It is
    // enabled only when exported project settings and every routed GDScript child close.
    bool context_complete=!i.gdextension_analysis_limited;std::set<std::string>global_classes,autoloads;std::vector<Route>project_bins,scripts;
    for(const auto&r:routes){if(r.path=="res://project.binary")project_bins.push_back(r);if((r.path.size()>=4&&r.path.compare(r.path.size()-4,4,".gdc")==0)||(r.path.size()>=3&&r.path.compare(r.path.size()-3,3,".gd")==0)){++i.gdextension_script_candidate_count;const auto declared=i.entries[r.index].size;if(declared>kMaxScriptBytes||i.gdextension_script_candidate_bytes>kMaxScriptBytes-declared){i.gdextension_script_candidate_bytes=kMaxScriptBytes+1;i.gdextension_analysis_limited=true;}else i.gdextension_script_candidate_bytes+=declared;if(scripts.size()<kMaxScripts)scripts.push_back(r);else i.gdextension_analysis_limited=true;}}
    if(i.gdextension_analysis_limited)return;
    if(project_bins.size()!=1)context_complete=false;else{auto p=validated_pck_payload(d,i,i.entries[project_bins[0].index]);if(!p.ok)context_complete=false;else{auto c=project_binary_context(p.bytes);if(!c.complete)context_complete=false;else autoloads=std::move(c.singleton_autoloads);}}
    struct ScriptCall{std::string path;std::size_t entry_index=0;std::string analysis_set_id;GDScriptNativeSuperCallInfo call;};std::vector<ScriptCall>calls;
    for(const auto&r:scripts){
        if(r.path.size()>=3&&r.path.compare(r.path.size()-3,3,".gd")==0){context_complete=false;continue;}
        auto p=validated_pck_payload(d,i,i.entries[r.index]);if(!p.ok||p.bytes.size()<4||std::memcmp(p.bytes.data(),"GDSC",4)!=0){context_complete=false;continue;}auto a=analyze_gdscript_buffer(p.bytes);if(!a.valid){context_complete=false;continue;}++i.gdextension_script_analysis_count;
        for(const auto&id:a.identifiers)if(id.class_name_identifier_pair_count)global_classes.insert(id.text);
        for(const auto&call:a.native_super_calls)calls.push_back({r.path,r.index,a.analysis_set_id,call});
    }
    i.gdextension_super_call_count=calls.size();if(!context_complete){i.gdextension_script_link_ambiguous_count+=calls.size();return;}
    struct RegRef{const GDExtensionBundleInfo*b=nullptr;const GDExtensionLibraryMatchInfo*l=nullptr;const GDExtensionMethodRegistrationInfo*m=nullptr;};
    for(const auto&sc:calls){
        if(global_classes.count(sc.call.base_class)||autoloads.count(sc.call.base_class)){++i.gdextension_script_link_ambiguous_count;continue;}
        std::vector<RegRef>matches;
        for(const auto&b:i.gdextensions){if(!b.valid)continue;for(const auto&l:b.libraries){if(!l.exact_path_match||!l.child_validated||!l.native_analyzed)continue;std::size_t class_regs=0;for(const auto&c:l.native.classes)if(c.evidence_state=="EXACT_REGISTRATION"&&c.class_name==sc.call.base_class)++class_regs;if(class_regs!=1)continue;for(const auto&m:l.native.methods){if(m.class_name!=sc.call.base_class||m.method_name!=sc.call.method_name)continue;if(m.evidence_state!="EXACT_REGISTRATION"&&m.evidence_state!="BOUNDED_BRIDGE_CANDIDATES")continue;if(!m.method_flags_known||(m.method_flags&32u))continue;matches.push_back({&b,&l,&m});}}}
        if(matches.size()!=1){if(matches.size()>1)++i.gdextension_script_link_ambiguous_count;continue;}const auto&x=matches.front();GodotGDExtensionScriptLinkInfo link;link.script_path=sc.path;link.script_entry_index=sc.entry_index;link.analysis_set_id=sc.analysis_set_id;link.base_class=sc.call.base_class;link.method_name=sc.call.method_name;link.extends_keyword_token_index=sc.call.extends_keyword_token_index;link.extends_identifier_token_index=sc.call.extends_identifier_token_index;link.super_token_index=sc.call.super_token_index;link.method_identifier_token_index=sc.call.method_identifier_token_index;link.effective_line=sc.call.effective_line;link.effective_line_known=sc.call.effective_line_known;link.descriptor_path=x.b->descriptor_path;link.library_path=x.l->matched_child_path;link.registration_state=x.m->evidence_state;link.registration_call_rva=x.m->registration_call_rva;link.bridge_candidate_count=x.m->bridge_candidates.size();i.gdextension_script_links.push_back(std::move(link));
    }
}

GodotExtractResult extract_godot(std::span<const std::uint8_t>d,const GodotPckInfo&i,const std::filesystem::path&dir,bool materialize_script_analysis,bool core_only,std::uint64_t max_output_bytes,std::uint32_t max_output_files){
    GodotExtractResult r;r.output_dir=dir;r.core_only=core_only;if(!i.valid||i.entries.empty()){r.error=i.encrypted_directory&&!i.key.confirmed?"encrypted directory has no validated key":"no validated PCK entries";return r;}std::error_code ec;std::filesystem::create_directories(dir,ec);if(ec){r.error=ec.message();return r;}
    std::set<std::string>native_paths;for(const auto&b:i.gdextensions){if(!b.descriptor_path.empty())native_paths.insert(b.descriptor_path);for(const auto&l:b.libraries)if(l.child_validated&&!l.matched_child_path.empty())native_paths.insert(l.matched_child_path);}
    auto score=[&](std::string path){std::transform(path.begin(),path.end(),path.begin(),[](unsigned char c){return char(std::tolower(c));});auto slash=path.find_last_of('/');auto base=slash==std::string::npos?path:path.substr(slash+1);if(path.ends_with(".gdc"))return 1200;if(path.ends_with(".gd"))return 1150;if(base=="project.binary"||base=="project.godot")return 1100;if(path.ends_with(".gdextension"))return 1050;if(native_paths.count(path)||native_paths.count("res://"+path))return 1000;return 0;};
    std::vector<const GodotPckEntry*>selected;for(const auto&e:i.entries)if(!e.removal&&!e.delta&&(!core_only||score(e.path)))selected.push_back(&e);if(core_only)std::stable_sort(selected.begin(),selected.end(),[&](auto*a,auto*b){auto as=score(a->path),bs=score(b->path);return as!=bs?as>bs:a->path<b->path;});
    if(core_only&&selected.empty()){r.success=true;return r;}
    std::set<std::string>declared_outputs;if(materialize_script_analysis){for(const auto&e:i.entries)if(!e.removal&&!e.delta){auto rel=safe_path(e.path);if(!rel.empty())declared_outputs.insert(output_key(dir/rel));}}
    static constexpr std::string_view sidecar_suffixes[]={".godot-script-info.json",".godot-identifiers.csv",".godot-constants.csv",".godot-lines.csv",".godot-tokens.csv"};
    for(const auto*ep:selected){const auto&e=*ep;if(r.files.size()>=max_output_files||e.size>max_output_bytes-r.output_bytes){r.budget_exhausted=true;++r.omitted_count;r.omitted_bytes=e.size>std::numeric_limits<std::uint64_t>::max()-r.omitted_bytes?std::numeric_limits<std::uint64_t>::max():r.omitted_bytes+e.size;continue;}std::vector<std::uint8_t>plain;std::span<const std::uint8_t>payload;if(e.encrypted){if(!i.key.confirmed){r.warnings.push_back("encrypted file skipped: "+e.path);continue;}auto dec=decrypt_stream(d,e.offset,i.key.key);if(!dec.ok){r.warnings.push_back("encrypted file MD5/decrypt failed: "+e.path);continue;}plain=std::move(dec.plain);payload=plain;}else{if(e.offset+e.size>d.size()){r.warnings.push_back("out-of-bounds file: "+e.path);continue;}payload=d.subspan(e.offset,e.size);if(md5(payload)!=e.md5)r.warnings.push_back("directory MD5 mismatch: "+e.path);}auto rel=safe_path(e.path);if(rel.empty()){r.warnings.push_back("unsafe PCK output path refused: "+e.path);continue;}auto p=dir/rel;if(!write_file(p,payload)){r.warnings.push_back("write failed: "+p.string());continue;}r.files.push_back(p);r.output_bytes+=payload.size();if(materialize_script_analysis&&payload.size()>=4&&payload[0]=='G'&&payload[1]=='D'&&payload[2]=='S'&&payload[3]=='C'){bool collision=false;for(auto suffix:sidecar_suffixes){if(declared_outputs.count(output_key(std::filesystem::path(p.string()+std::string(suffix))))){collision=true;break;}}if(collision){++r.script_analysis_failures;r.warnings.push_back("GDScript sidecar materialization refused due to declared PCK path collision: "+e.path);continue;}auto analysis=analyze_gdscript_buffer(payload);if(!analysis.valid){++r.script_analysis_failures;r.warnings.push_back("GDScript analysis failed for "+e.path+": "+analysis.error);continue;}auto artifacts=materialize_gdscript_analysis(analysis,p);if(!artifacts.success){++r.script_analysis_failures;r.warnings.push_back("GDScript artifact materialization failed for "+e.path+": "+artifacts.error);continue;}++r.script_analysis_count;r.script_artifact_count+=5;}}
    r.success=core_only?(r.files.size()>0):(!r.files.empty()&&!r.budget_exhausted);if(!r.success)r.error=core_only?"no Godot script/project/native core artifacts materialized":"no files extracted";return r;
}

Finding godot_finding(const GodotPckInfo&i){Finding f;f.kind="container";f.family="Godot PCK";if(!i.valid){f.state="FAILED";f.evidence.push_back(i.error);return f;}if(i.validated){f.state="CONFIRMED";f.confidence.reset();}else{f.state="LIKELY";f.confidence=.90;}f.variant="v"+std::to_string(i.format_version);f.evidence=i.evidence;f.fields["engine_version"]=std::to_string(i.engine_major)+"."+std::to_string(i.engine_minor)+"."+std::to_string(i.engine_patch);f.fields["file_count"]=std::to_string(i.file_count);f.fields["encrypted_directory"]=i.encrypted_directory?"true":"false";if(i.modified_magic)f.fields["modified_magic"]="true";if(i.key.found){f.fields["key"]=godot_key_hex(i.key);f.fields["key_state"]=godot_key_state(i.key);f.fields["key_decryption_validated"]=i.key.confirmed?"true":"false";f.fields["key_directory_validated"]=i.key.directory_validated?"true":"false";f.fields["key_encrypted_file_validated"]=i.key.encrypted_file_validated?"true":"false";f.fields["key_script_validated"]=i.key.script_validated?"true":"false";f.fields["key_native_candidate_count"]=std::to_string(i.key.native_candidate_count);f.fields["key_candidate_budget_exhausted"]=i.key.candidate_budget_exhausted?"true":"false";f.fields["key_candidate_validation_attempts"]=std::to_string(i.key.candidate_validation_attempts);f.fields["key_encrypted_probe_count"]=std::to_string(i.key.encrypted_probe_count);f.fields["key_encrypted_script_count"]=std::to_string(i.key.encrypted_script_count);f.fields["key_validated_script_count"]=std::to_string(i.key.validated_script_count);f.fields["key_script_validation_truncated"]=i.key.script_validation_truncated?"true":"false";if(!i.key.validated_script_path.empty())f.fields["key_validated_script_path"]=i.key.validated_script_path;if(!i.key.script_validated)f.negative_evidence.push_back("key evidence does not reach KEY_VALIDATED_FOR_SCRIPT without an encrypted GDScript plaintext that independently passes structural analysis");}f.ranges.push_back({i.pck_offset,0,"PCK"});f.suggested_actions={"extract:godot"};return f;}
Finding godot_gdextension_finding(const GodotPckInfo&i){Finding f;f.kind="native_bridge";f.family="Godot GDExtension registration";f.state=i.gdextension_state;f.fields["descriptor_candidates"]=std::to_string(i.gdextension_descriptor_candidates);f.fields["descriptor_processed"]=std::to_string(i.gdextension_descriptor_processed);f.fields["script_candidate_count"]=std::to_string(i.gdextension_script_candidate_count);f.fields["script_candidate_bytes"]=std::to_string(i.gdextension_script_candidate_bytes);f.fields["analysis_limited"]=i.gdextension_analysis_limited?"true":"false";f.fields["bundle_valid_count"]=std::to_string(i.gdextension_bundle_valid_count);f.fields["native_analyzed_count"]=std::to_string(i.gdextension_native_analyzed_count);f.fields["exact_registration_bundles"]=std::to_string(i.gdextension_exact_registration_count);f.fields["bounded_bridge_bundles"]=std::to_string(i.gdextension_bounded_bridge_count);f.fields["unresolved_bundles"]=std::to_string(i.gdextension_unresolved_count);f.fields["failed_bundles"]=std::to_string(i.gdextension_failed_count);f.fields["script_analysis_count"]=std::to_string(i.gdextension_script_analysis_count);f.fields["native_super_call_count"]=std::to_string(i.gdextension_super_call_count);f.fields["script_registration_link_count"]=std::to_string(i.gdextension_script_links.size());f.fields["script_link_ambiguous_count"]=std::to_string(i.gdextension_script_link_ambiguous_count);f.fields["script_link_basis"]="validated project.binary + complete validated .gdc set + unique top-level extends + explicit super.method + no global-class/autoload conflict + unique class/method registration";f.evidence.push_back(".gdextension descriptors and declared native siblings were admitted only after independent PCK child integrity validation");if(i.gdextension_native_analyzed_count)f.evidence.push_back("descriptor entry/get-proc/registration analysis reached validated PE64 x86-64 sibling images");if(!i.gdextension_script_links.empty())f.evidence.push_back("one or more GDScript super calls uniquely cross-link to native registration records under the strict class+method provenance contract");if(i.gdextension_failed_count)f.negative_evidence.push_back("one or more descriptor/sibling bundles failed child-integrity, descriptor, path, format, or registration closure");if(i.gdextension_script_link_ambiguous_count)f.negative_evidence.push_back("one or more script/native links were suppressed because project/script context or registration identity was ambiguous");if(i.gdextension_analysis_limited)f.negative_evidence.push_back("D21 descriptor/script correlation budget was reached; native facts from processed bundles remain valid but script links are fail-closed");return f;}
std::string godot_key_hex(const GodotKeyInfo&k){return hex(k.key);}
}
