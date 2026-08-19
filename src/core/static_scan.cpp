#include "prts/static_scan.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <future>
#include <queue>
#include <set>
#include <string_view>
namespace prts { namespace {
double ent_counts(const std::array<std::size_t,256>&c,std::size_t n){if(!n)return 0;double e=0;for(auto x:c)if(x){double q=double(x)/double(n);e-=q*std::log2(q);}return e;}
double ent(std::span<const std::uint8_t> v){std::array<std::size_t,256>c{};for(auto b:v)++c[b];return ent_counts(c,v.size());}
bool printable(std::uint8_t b){return b>=0x20&&b<=0x7e;}
enum HintMask : std::uint32_t { H_NONE=0,H_PYINSTALLER=1u<<0,H_NUITKA=1u<<1,H_GODOT=1u<<2,H_UNITY=1u<<3,H_RUST=1u<<4,H_GO=1u<<5,H_RENPY=1u<<6,H_AUTOIT=1u<<7,H_CRYPTO=1u<<8 };
struct AnchorDef { const char* text; std::uint32_t hints; };
static constexpr AnchorDef kAnchors[]={
    {"python",H_NONE},{"pyinstaller",H_PYINSTALLER},{"pyimod",H_PYINSTALLER},{"_mei",H_PYINSTALLER},
    {"nuitka",H_NUITKA},{"__nuitka__",H_NUITKA},{"constant_bin_data",H_NUITKA},
    {"godot",H_GODOT},{"gdscript::",H_GODOT},{"encrypted pack",H_GODOT},
    {"upx",H_NONE},{"vmprotect",H_NONE},{"themida",H_NONE},{"winlicense",H_NONE},{"autoit",H_AUTOIT},{"au3!ea06",H_AUTOIT},{"electron",H_NONE},{"asar",H_NONE},
    {"unity",H_UNITY},{"unityplayer",H_UNITY},{"il2cpp",H_UNITY},{"global-metadata.dat",H_UNITY},{"mono",H_NONE},
    {"rust",H_RUST},{"/rustc/",H_RUST},{".cargo/registry/",H_RUST},{"rust_begin_unwind",H_RUST},{"core::panicking",H_RUST},{"library/core/src/",H_RUST},
    {"golang",H_GO},{"go build",H_GO},{"runtime.main",H_GO},
    {"renpy",H_RENPY},{"ren'py",H_RENPY},{"renpy rpc2",H_RENPY},{"pck",H_NONE}
};
struct ACNode { std::array<int,128> next{}; int fail=0; std::vector<std::uint16_t> out; ACNode(){next.fill(-1);} };
class AnchorAutomaton {
public:
    AnchorAutomaton(){nodes_.emplace_back();for(std::uint16_t id=0;id<std::size(kAnchors);++id){int s=0;for(unsigned char c:std::string_view(kAnchors[id].text)){c=lower(c);if(c>=128)continue;if(nodes_[s].next[c]<0){nodes_[s].next[c]=static_cast<int>(nodes_.size());nodes_.emplace_back();}s=nodes_[s].next[c];}nodes_[s].out.push_back(id);}std::queue<int>q;for(int c=0;c<128;c++){auto x=nodes_[0].next[c];if(x<0)nodes_[0].next[c]=0;else{nodes_[x].fail=0;q.push(x);}}while(!q.empty()){auto v=q.front();q.pop();auto f=nodes_[v].fail;nodes_[v].out.insert(nodes_[v].out.end(),nodes_[f].out.begin(),nodes_[f].out.end());for(int c=0;c<128;c++){auto u=nodes_[v].next[c];if(u<0)nodes_[v].next[c]=nodes_[f].next[c];else{nodes_[u].fail=nodes_[f].next[c];q.push(u);}}}}
    int step(int state,std::uint8_t c)const{if(c>=128)return 0;return nodes_[state].next[lower(c)];}
    const std::vector<std::uint16_t>& outputs(int state)const{return nodes_[state].out;}
private:
    static std::uint8_t lower(std::uint8_t c){return c>='A'&&c<='Z'?std::uint8_t(c+32):c;}
    std::vector<ACNode>nodes_;
};
const AnchorAutomaton& anchors(){static const AnchorAutomaton a;return a;}
void apply_hint_mask(EcosystemHints&h,std::uint32_t m){if(m&H_PYINSTALLER)h.pyinstaller=true;if(m&H_NUITKA)h.nuitka=true;if(m&H_GODOT)h.godot=true;if(m&H_UNITY)h.unity=true;if(m&H_RUST)h.rust=true;if(m&H_GO)h.golang=true;if(m&H_RENPY)h.renpy=true;if(m&H_AUTOIT)h.autoit=true;if(m&H_CRYPTO)h.crypto=true;}
bool rust_mangled_hint(std::string_view s){if(s.rfind("_R",0)==0&&s.size()>8)return true;auto p=s.find("17h");if(p==std::string_view::npos||p+20>s.size())return false;for(std::size_t i=p+3;i<p+19;i++)if(!std::isxdigit(static_cast<unsigned char>(s[i])))return false;return s[p+19]=='E';}
bool classify_anchor_string(std::string_view s,EcosystemHints&h){bool any=false;int state=0;const auto&ac=anchors();for(unsigned char c:s){state=ac.step(state,c);for(auto id:ac.outputs(state)){any=true;apply_hint_mask(h,kAnchors[id].hints);}}if(rust_mangled_hint(s)){h.rust=true;any=true;}return any;}
std::uint32_t u32le(std::span<const std::uint8_t>d,std::size_t o){if(o+4>d.size())return 0;return std::uint32_t(d[o])|(std::uint32_t(d[o+1])<<8)|(std::uint32_t(d[o+2])<<16)|(std::uint32_t(d[o+3])<<24);}
bool valid_pe_at(std::span<const std::uint8_t>d,std::size_t o,std::uint64_t& guessed){if(o+0x40>d.size()||d[o]!='M'||d[o+1]!='Z')return false;auto lf=u32le(d,o+0x3c);if(lf>0x100000||o+lf+24>d.size())return false;if(std::memcmp(d.data()+o+lf,"PE\0\0",4))return false;std::uint16_t ns=d[o+lf+6]|(d[o+lf+7]<<8);std::uint16_t opt=d[o+lf+20]|(d[o+lf+21]<<8);auto st=o+lf+24+opt;if(!ns||ns>96||st+std::size_t(ns)*40>d.size())return false;std::uint64_t end=st+std::size_t(ns)*40;for(std::uint16_t i=0;i<ns;i++){auto sh=st+i*40;auto rs=u32le(d,sh+16),ro=u32le(d,sh+20);if(ro&&rs&&o+std::uint64_t(ro)+rs<=d.size())end=std::max(end,o+std::uint64_t(ro)+rs);}guessed=end-o;return true;}
bool valid_elf_at(std::span<const std::uint8_t>d,std::size_t o){return o+0x34<=d.size()&&d[o]==0x7f&&d[o+1]=='E'&&d[o+2]=='L'&&d[o+3]=='F'&&(d[o+4]==1||d[o+4]==2)&&(d[o+5]==1||d[o+5]==2);}
std::optional<std::size_t> cmp256_len(std::span<const std::uint8_t>d,std::size_t o){
    if(o>=d.size())return{};
    if(d[o]==0x3d){if(o+5<=d.size()&&u32le(d,o+1)==256)return 5;return{};}
    if(d[o]!=0x81||o+2>d.size())return{};auto m=d[o+1];if(((m>>3)&7)!=7)return{};auto mod=m>>6,rm=m&7;std::size_t p=o+2;
    if(mod!=3&&rm==4){if(p>=d.size())return{};auto sib=d[p++];if(mod==0&&(sib&7)==5)p+=4;}
    if(mod==0&&rm==5)p+=4;else if(mod==1)p+=1;else if(mod==2)p+=4;
    if(p+4>d.size()||u32le(d,p)!=256)return{};return p+4-o;
}

struct StringScanPart {std::uint64_t ascii=0,utf16=0;EcosystemHints hints;std::vector<StringHit> interesting;};
struct EmbeddedScanPart {EcosystemHints hints;std::vector<EmbeddedObject> embedded;std::vector<std::uint64_t> crypto_delta_offsets,crypto_rc4_offsets,crypto_aesni_schedule_offsets,crypto_aesni_round_offsets;};
void merge_hints(EcosystemHints&a,const EcosystemHints&b){a.pyinstaller|=b.pyinstaller;a.nuitka|=b.nuitka;a.godot|=b.godot;a.unity|=b.unity;a.rust|=b.rust;a.golang|=b.golang;a.renpy|=b.renpy;a.autoit|=b.autoit;a.crypto|=b.crypto;}
StringScanPart scan_strings_part(std::span<const std::uint8_t>d){StringScanPart r;
    for(std::size_t i=0;i<d.size();){
        if(printable(d[i])){std::size_t st=i;while(i<d.size()&&printable(d[i]))++i;if(i-st>=4){++r.ascii;std::string_view v(reinterpret_cast<const char*>(d.data()+st),i-st);if(classify_anchor_string(v,r.hints)&&r.interesting.size()<256)r.interesting.push_back({st,"ascii",std::string(v.substr(0,512))});}continue;}++i;
    }
    // Check both byte alignments: embedded UTF-16LE strings are not guaranteed to start at an even file offset.
    for(std::size_t i=0;i+1<d.size();){
        if(printable(d[i])&&d[i+1]==0){std::size_t st=i,n=0;std::string v;while(i+1<d.size()&&printable(d[i])&&d[i+1]==0){if(v.size()<512)v.push_back(char(d[i]));i+=2;++n;}if(n>=4){++r.utf16;if(classify_anchor_string(v,r.hints)&&r.interesting.size()<256)r.interesting.push_back({st,"utf16le",v});}continue;}++i;
    }
    return r;
}
std::vector<EntropyRange> scan_entropy_part(std::span<const std::uint8_t>d){std::vector<EntropyRange> out;constexpr std::size_t W=65536,S=16384;EntropyRange cur{};bool have=false;if(d.size()<4096)return out;
    const std::size_t first_n=std::min(W,d.size());std::array<std::size_t,256>hist{};for(std::size_t i=0;i<first_n;i++)++hist[d[i]];std::size_t prev_o=0,prev_n=first_n;
    for(std::size_t o=0;;o+=S){std::size_t n=std::min(W,d.size()-o);if(n<4096)break;if(o){const auto remove_end=std::min(prev_o+S,prev_o+prev_n);for(std::size_t i=prev_o;i<remove_end;i++)--hist[d[i]];const auto old_end=prev_o+prev_n,new_end=o+n;for(std::size_t i=old_end;i<new_end;i++)++hist[d[i]];prev_o=o;prev_n=n;}double e=ent_counts(hist,n);if(e>=7.60){if(have&&o<=cur.offset+cur.size+S){auto xend=std::max<std::uint64_t>(cur.offset+cur.size,o+n);cur.size=xend-cur.offset;cur.entropy=std::max(cur.entropy,e);}else{if(have)out.push_back(cur);cur={o,n,e};have=true;}}else if(have&&o>cur.offset+cur.size){out.push_back(cur);have=false;}if(o+S>=d.size())break;}if(have)out.push_back(cur);return out;
}
EmbeddedScanPart scan_embedded_part(std::span<const std::uint8_t>d){EmbeddedScanPart r;
    if(d.size()>=10&&std::memcmp(d.data(),"RENPY RPC2",10)==0)r.hints.renpy=true;
    if(d.size()>=4&&u32le(d,0)==0xFAB11BAFu)r.hints.unity=true;
    if(d.size()>=4&&d[0]=='R'&&d[1]=='P'&&d[2]=='A'&&d[3]=='-')r.hints.renpy=true;
    // EOCD-driven ZIP discovery avoids rescanning to EOF from every local member header.
    for(std::size_t e=0;e+22<=d.size();++e){if(d[e]!='P'||d[e+1]!='K'||d[e+2]!=5||d[e+3]!=6)continue;auto comment=std::uint16_t(d[e+20])|(std::uint16_t(d[e+21])<<8);if(e+22ull+comment>d.size())continue;auto cdsize=u32le(d,e+12),cdoff=u32le(d,e+16);if(cdsize>e||cdoff>e-cdsize)continue;auto start=e-cdsize-cdoff,cd=start+std::uint64_t(cdoff);if(start+4>d.size()||d[start]!='P'||d[start+1]!='K'||d[start+2]!=3||d[start+3]!=4)continue;if(cd+4>d.size()||d[cd]!='P'||d[cd+1]!='K'||d[cd+2]!=1||d[cd+3]!=2)continue;r.embedded.push_back({"ZIP",start,e+22ull+comment-start,true,"CONFIRMED",std::nullopt,"ZIP central directory and EOCD validated"});}
    for(std::size_t o=0;o+4<d.size();++o){auto c=d[o];
        // Every embedded/crypto signature below has one of these leading bytes.
        // Reject all other bytes before entering the exact per-signature checks.
        switch(c){case 'M':case 0x7f:case 'P':case 'G':case 'K':case 0x6b:case 0xb9:case 0x20:case 0x81:case 0x3d:case 0x0f:case 0xff:case 0xfb:case 0xfa:case 0xf0:case 0xf1:break;default:continue;}
        if(o&&c=='M'&&d[o+1]=='Z'){std::uint64_t sz=0;if(valid_pe_at(d,o,sz))r.embedded.push_back({"PE",o,sz,true,"CONFIRMED",std::nullopt,"validated MZ/PE headers and sections"});}
        else if(o&&c==0x7f&&d[o+1]=='E'&&d[o+2]=='L'&&d[o+3]=='F'&&valid_elf_at(d,o))r.embedded.push_back({"ELF",o,0,true,"CONFIRMED",std::nullopt,"validated ELF ident"});
        else if(c=='P'&&d[o+1]=='Y'&&d[o+2]=='Z'&&d[o+3]==0){r.hints.pyinstaller=true;r.embedded.push_back({"PYZ",o,0,false,"LIKELY",0.90,"PYZ magic candidate; container parser must validate"});}
        else if(c=='G'&&d[o+1]=='D'&&d[o+2]=='P'&&d[o+3]=='C'){r.hints.godot=true;r.embedded.push_back({"GodotPCK",o,0,false,"LIKELY",0.90,"Godot PCK magic candidate; PCK parser must validate"});}
        else if(c=='K'&&d[o+1]=='A'&&(d[o+2]=='X'||d[o+2]=='Y'))r.hints.nuitka=true;
        else if(c==0x6b&&d[o+1]==0x43&&d[o+2]==0xca&&d[o+3]==0x52)r.hints.autoit=true;
        else if((c==0xb9&&d[o+1]==0x79&&d[o+2]==0x37&&d[o+3]==0x9e)||(c==0x47&&d[o+1]==0x86&&d[o+2]==0xc8&&d[o+3]==0x61)||(c==0x20&&d[o+1]==0x37&&d[o+2]==0xef&&d[o+3]==0xc6)){r.hints.crypto=true;if(r.crypto_delta_offsets.size()<512)r.crypto_delta_offsets.push_back(o);}
        else if((c==0x81||c==0x3d)&&cmp256_len(d,o)){r.hints.crypto=true;if(r.crypto_rc4_offsets.size()<512)r.crypto_rc4_offsets.push_back(o);}
        else if(c==0x0f&&o+3<d.size()&&d[o+1]==0x3a&&d[o+2]==0xdf){r.hints.crypto=true;if(r.crypto_aesni_schedule_offsets.size()<512)r.crypto_aesni_schedule_offsets.push_back(o);}
        else if(c==0x0f&&o+3<d.size()&&d[o+1]==0x38&&(d[o+2]==0xdc||d[o+2]==0xdd||d[o+2]==0xde||d[o+2]==0xdf)){r.hints.crypto=true;if(r.crypto_aesni_round_offsets.size()<1024)r.crypto_aesni_round_offsets.push_back(o);}
        else if(c==0xff&&o+14<=d.size()&&std::memcmp(d.data()+o+1," Go buildinf:",13)==0)r.hints.golang=true;
        else if((c==0xfb||c==0xfa||c==0xf0||c==0xf1)&&d[o+1]==0xff&&d[o+2]==0xff&&d[o+3]==0xff&&o+8<=d.size()&&d[o+4]==0&&d[o+5]==0&&(d[o+6]==1||d[o+6]==2||d[o+6]==4)&&(d[o+7]==4||d[o+7]==8))r.hints.golang=true;
        else if(c=='M'&&o+8<=d.size()&&d[o+1]=='E'&&d[o+2]=='I'&&d[o+3]==014&&d[o+4]==013&&d[o+5]==012&&d[o+6]==013&&d[o+7]==016)r.hints.pyinstaller=true;
    }
    return r;
}
}
StaticScanReport scan_static(std::span<const std::uint8_t>d){StaticScanReport r;StringScanPart sp;std::vector<EntropyRange> ep;EmbeddedScanPart bp;
    if(d.size()>=1024*1024){
        auto sf=std::async(std::launch::async,[&]{return scan_strings_part(d);});
        auto ef=std::async(std::launch::async,[&]{return scan_entropy_part(d);});
        bp=scan_embedded_part(d);sp=sf.get();ep=ef.get();
    }else{sp=scan_strings_part(d);ep=scan_entropy_part(d);bp=scan_embedded_part(d);}
    r.ascii_strings=sp.ascii;r.utf16_strings=sp.utf16;r.interesting_strings=std::move(sp.interesting);r.high_entropy=std::move(ep);r.embedded=std::move(bp.embedded);r.crypto_delta_offsets=std::move(bp.crypto_delta_offsets);r.crypto_rc4_offsets=std::move(bp.crypto_rc4_offsets);r.crypto_aesni_schedule_offsets=std::move(bp.crypto_aesni_schedule_offsets);r.crypto_aesni_round_offsets=std::move(bp.crypto_aesni_round_offsets);r.hints=sp.hints;merge_hints(r.hints,bp.hints);return r;
}
std::vector<Finding> detect_common(std::span<const std::uint8_t>d,const PeInfo&pe,const ElfInfo&elf,const StaticScanReport&scan){std::vector<Finding> out;
    auto bytes_text=[&](std::string_view x){return std::search(d.begin(),d.end(),x.begin(),x.end())!=d.end();};
    // Ecosystem/runtime anchors. Strong parsers will refine confidence later.
    for(auto&s:scan.interesting_strings){std::string low=s.value;std::transform(low.begin(),low.end(),low.begin(),[](unsigned char c){return char(std::tolower(c));});
        auto add=[&](std::string fam,std::string ev,double c){for(auto&x:out)if(x.family==fam)return;Finding f;f.kind="ecosystem";f.family=std::move(fam);f.state=c>=0.75?"LIKELY":"SUSPECTED";f.confidence=c;f.evidence.push_back(std::move(ev));f.ranges.push_back({s.offset,s.value.size(),"string"});out.push_back(std::move(f));};
        if(low.find("pyinstaller")!=std::string::npos||low.find("pyimod")!=std::string::npos)add("PyInstaller","PyInstaller bootstrap/string anchor",0.75);
        if(low.find("nuitka")!=std::string::npos)add("Nuitka","Nuitka string anchor",0.72);
        if(low.find("godot")!=std::string::npos||low.find("encrypted pack")!=std::string::npos)add("Godot","Godot engine/pack string anchor",0.78);
        if(low.find("python")!=std::string::npos)add("CPython-derived","Python runtime string anchor",0.55);
        auto add_protector_marker=[&](std::string claimed,std::string ev){for(const auto&x:out){auto it=x.fields.find("claimed_family");if(x.family=="Packer/protector marker"&&it!=x.fields.end()&&it->second==claimed)return;}Finding f;f.kind="packer_hint";f.family="Packer/protector marker";f.variant=claimed;f.state="SUSPECTED";f.confidence=.30;f.evidence.push_back(std::move(ev));f.negative_evidence.push_back("identifier string is not independent structural evidence; family classification intentionally withheld");f.fields["claimed_family"]=std::move(claimed);f.fields["evidence_strength"]="WEAK_MARKER_ONLY";f.ranges.push_back({s.offset,s.value.size(),"identifier string"});out.push_back(std::move(f));};
        if(low.find("vmprotect")!=std::string::npos)add_protector_marker("VMProtect","VMProtect identifier string present");
        if(low.find("themida")!=std::string::npos||low.find("winlicense")!=std::string::npos)add_protector_marker("Themida/WinLicense","Oreans/Themida/WinLicense identifier string present");
    }
    for(auto&e:scan.embedded){if(e.kind=="PYZ"){Finding f;f.kind="container";f.family="PyInstaller";f.state="LIKELY";f.confidence=0.92;f.evidence={"embedded PYZ archive"};f.ranges.push_back({e.offset,e.size,"PYZ"});f.suggested_actions={"extract:pyinstaller"};out.push_back(std::move(f));}else if(e.kind=="GodotPCK"){Finding f;f.kind="container";f.family="Godot PCK";f.state="LIKELY";f.confidence=0.95;f.evidence={"validated GDPC marker"};f.ranges.push_back({e.offset,e.size,"PCK"});f.suggested_actions={"extract:godot"};out.push_back(std::move(f));}}
    return out;
}
}
