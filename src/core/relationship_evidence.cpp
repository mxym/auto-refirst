#include "prts/relationship_evidence.hpp"
#include "prts/report.hpp"
#include "prts/path_utf8.hpp"
#include "prts/gdextension.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>

namespace prts {
namespace {
constexpr std::size_t kTextCap=2u*1024u*1024u;
constexpr std::size_t kNativeCap=32u*1024u*1024u;

std::string lower_ascii(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return char(std::tolower(c));});return s;}
std::string trim(std::string s){auto ws=[](unsigned char c){return std::isspace(c)!=0;};while(!s.empty()&&ws(static_cast<unsigned char>(s.front())))s.erase(s.begin());while(!s.empty()&&ws(static_cast<unsigned char>(s.back())))s.pop_back();return s;}
bool wildcard_or_dynamic(std::string_view s){return s.find('*')!=std::string_view::npos||s.find('?')!=std::string_view::npos||s.find('$')!=std::string_view::npos||s.find('`')!=std::string_view::npos||s.find('%')!=std::string_view::npos;}
bool sane_path_literal(std::string_view s){if(s.empty()||s.size()>1024||wildcard_or_dynamic(s))return false;for(unsigned char c:s)if(c<0x20)return false;return s.find('\0')==std::string_view::npos;}
std::size_t line_of(std::string_view text,std::size_t off){return 1+static_cast<std::size_t>(std::count(text.begin(),text.begin()+static_cast<std::ptrdiff_t>(std::min(off,text.size())),'\n'));}

std::optional<std::string> read_bounded_text(const std::filesystem::path&p){
    std::error_code ec;const auto sz=std::filesystem::file_size(p,ec);if(ec||sz>kTextCap)return{};
    std::ifstream f(p,std::ios::binary);if(!f)return{};std::string s(static_cast<std::size_t>(sz),'\0');if(!s.empty())f.read(s.data(),static_cast<std::streamsize>(s.size()));s.resize(static_cast<std::size_t>(std::max<std::streamsize>(0,f.gcount())));if(s.empty())return{};
    std::size_t printable=0;for(unsigned char c:s)if(c==9||c==10||c==13||(c>=32&&c<127))++printable;if(printable*100<s.size()*90)return{};return s;
}

std::optional<std::pair<std::string,std::size_t>> parse_quoted(std::string_view s,std::size_t at){
    while(at<s.size()&&std::isspace(static_cast<unsigned char>(s[at])))++at;
    if(at<s.size()&&(s[at]=='f'||s[at]=='F'||s[at]=='r'||s[at]=='R'))++at;
    if(at>=s.size()||(s[at]!='\''&&s[at]!='\"'))return{};
    const char q=s[at++];std::string out;
    for(;at<s.size();++at){char c=s[at];if(c==q)return std::pair<std::string,std::size_t>{out,at+1};if(c=='\\'){if(at+1>=s.size())return{};char n=s[++at];switch(n){case 'n':out.push_back('\n');break;case 'r':out.push_back('\r');break;case 't':out.push_back('\t');break;default:out.push_back(n);break;}}else out.push_back(c);}
    return{};
}

bool python_code_position(std::string_view text,std::size_t target){
    enum class S{Code,Single,Double,TripleSingle,TripleDouble,Comment};S st=S::Code;bool esc=false;
    for(std::size_t i=0;i<target&&i<text.size();++i){const char c=text[i];
        if(st==S::Comment){if(c=='\n')st=S::Code;continue;}
        if(st==S::Single||st==S::Double){if(esc){esc=false;continue;}if(c=='\\'){esc=true;continue;}if((st==S::Single&&c=='\'')||(st==S::Double&&c=='\"'))st=S::Code;else if(c=='\n')st=S::Code;continue;}
        if(st==S::TripleSingle||st==S::TripleDouble){const char q=st==S::TripleSingle?'\'':'\"';if(c=='\\'){++i;continue;}if(c==q&&i+2<text.size()&&text[i+1]==q&&text[i+2]==q){i+=2;st=S::Code;}continue;}
        if(c=='#'){st=S::Comment;continue;}
        if(c=='\''||c=='\"'){if(i+2<text.size()&&text[i+1]==c&&text[i+2]==c){st=c=='\''?S::TripleSingle:S::TripleDouble;i+=2;}else st=c=='\''?S::Single:S::Double;}
    }
    return st==S::Code;
}
bool python_module_level_position(std::string_view text,std::size_t at){
    if(!python_code_position(text,at))return false;
    auto ls=text.rfind('\n',at);ls=ls==std::string_view::npos?0:ls+1;auto prefix=text.substr(ls,at-ls);auto first=prefix.find_first_not_of(" \t");return prefix.empty()||first==0;
}

std::map<std::string,std::string> python_constants(std::string_view text){
    std::map<std::string,std::string> out;std::size_t pos=0;
    while(pos<text.size()){
        auto end=text.find('\n',pos);if(end==std::string_view::npos)end=text.size();auto line=text.substr(pos,end-pos);std::size_t i=0;while(i<line.size()&&std::isspace(static_cast<unsigned char>(line[i])))++i;
        if(i!=0||!python_code_position(text,pos)){pos=end==text.size()?end:end+1;continue;}
        std::size_t b=i;if(i<line.size()&&(std::isalpha(static_cast<unsigned char>(line[i]))||line[i]=='_')){++i;while(i<line.size()&&(std::isalnum(static_cast<unsigned char>(line[i]))||line[i]=='_'))++i;auto name=std::string(line.substr(b,i-b));while(i<line.size()&&std::isspace(static_cast<unsigned char>(line[i])))++i;if(i<line.size()&&line[i]=='='){auto q=parse_quoted(line,i+1);if(q){auto tail=trim(std::string(line.substr(q->second)));if(tail.empty()||tail[0]=='#')out[name]=q->first;}}}
        pos=end==text.size()?end:end+1;
    }return out;
}

std::optional<std::string> exact_fstring(std::string v,const std::map<std::string,std::string>& constants){
    std::string out;for(std::size_t i=0;i<v.size();){if(v[i]!='{'){out.push_back(v[i++]);continue;}auto e=v.find('}',i+1);if(e==std::string::npos)return{};auto name=trim(v.substr(i+1,e-i-1));if(name.empty()||name.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")!=std::string::npos)return{};auto it=constants.find(name);if(it==constants.end())return{};out+=it->second;i=e+1;}return out;
}

std::vector<std::string> shell_words(std::string_view s){
    std::vector<std::string> out;std::string cur;char quote=0;bool esc=false;
    for(char c:s){if(esc){cur.push_back(c);esc=false;continue;}if(c=='\\'&&quote!='\''){esc=true;continue;}if(quote){if(c==quote)quote=0;else cur.push_back(c);continue;}if(c=='\''||c=='\"'){quote=c;continue;}if(std::isspace(static_cast<unsigned char>(c))){if(!cur.empty()){out.push_back(cur);cur.clear();}continue;}if(c==';'||c=='|'||c=='&'||c=='<'||c=='>')return{};cur.push_back(c);}if(esc||quote)return{};if(!cur.empty())out.push_back(cur);return out;
}
bool pathish_runner_word(std::string_view w){if(w.empty()||w[0]=='-')return false;if(w.find('/')!=std::string_view::npos||w.find('\\')!=std::string_view::npos)return true;if(w.size()>2&&std::isalpha(static_cast<unsigned char>(w[0]))&&w[1]==':')return true;return false;}
bool absolute_declared(std::string_view s){return (!s.empty()&&(s[0]=='/'||s[0]=='\\'))||(s.size()>2&&std::isalpha(static_cast<unsigned char>(s[0]))&&s[1]==':');}

void add_fact(std::vector<RelationshipReferenceEvidence>&out,std::set<std::string>&seen,RelationshipReferenceEvidence f){auto k=f.kind+"\n"+f.reference+"\n"+f.source_coordinate;if(seen.insert(k).second)out.push_back(std::move(f));}

void extract_python(std::string_view text,std::vector<RelationshipReferenceEvidence>&out){
    std::set<std::string> seen;const auto constants=python_constants(text);
    // Direct literal open() consumption.  A path-looking string elsewhere is intentionally ignored.
    std::size_t pos=0;while((pos=text.find("open",pos))!=std::string_view::npos){const auto start=pos;const bool left=pos==0||(!(std::isalnum(static_cast<unsigned char>(text[pos-1]))||text[pos-1]=='_')&&text[pos-1]!='.');pos+=4;if(!left||!python_module_level_position(text,start))continue;std::size_t p=pos;while(p<text.size()&&std::isspace(static_cast<unsigned char>(text[p])))++p;if(p>=text.size()||text[p]!='(')continue;auto q=parse_quoted(text,p+1);if(!q||!sane_path_literal(q->first))continue;
        RelationshipReferenceEvidence f;f.kind="script_literal_data_dependency";f.evidence_level="R3_EXACT_DATA_DEPENDENCY";f.semantic_relevance="DATA_DEPENDENCY";f.reference=q->first;f.resolution_mode=absolute_declared(f.reference)?"EXACT_ABSOLUTE_PATH":"EXACT_RELATIVE_PATH";f.source_coordinate="current_input_file:line="+std::to_string(line_of(text,start))+":open_literal";f.evidence_basis="literal path is the first argument of a direct open() call; unrelated path strings are not accepted";f.evidence_source="bounded Python source syntax";f.source_relation_role="data_consumer";f.target_relation_role="consumed_sidecar";f.source_priority_delta=15;f.target_priority_delta=50;f.priority_cap=60;add_fact(out,seen,std::move(f));
    }
    // Exact os.system command after bounded constant/f-string substitution.
    pos=0;while((pos=text.find("os.system",pos))!=std::string_view::npos){const auto start=pos;pos+=9;if(!python_module_level_position(text,start))continue;std::size_t p=pos;while(p<text.size()&&std::isspace(static_cast<unsigned char>(text[p])))++p;if(p>=text.size()||text[p]!='(')continue;auto q=parse_quoted(text,p+1);if(!q)continue;auto cmd=exact_fstring(q->first,constants);if(!cmd||wildcard_or_dynamic(*cmd))continue;auto words=shell_words(*cmd);if(words.empty())continue;for(const auto&w:words){if(!pathish_runner_word(w)||!sane_path_literal(w))continue;RelationshipReferenceEvidence f;f.kind="script_runner_argv";f.evidence_level="R2_STRUCTURAL_RELATION";f.semantic_relevance="STRUCTURAL";f.reference=w;f.resolution_mode=absolute_declared(w)?"DECLARED_BASENAME_VALIDATED_IMAGE":"EXACT_RELATIVE_PATH";f.source_coordinate="current_input_file:line="+std::to_string(line_of(text,start))+":os.system_argv";f.evidence_basis="runner command closes to an exact static argv token after constant-only f-string substitution";f.evidence_source="bounded Python os.system syntax/dataflow";f.source_relation_role="runner";f.target_relation_role="launched_stage";f.source_priority_delta=20;f.target_priority_delta=20;f.priority_cap=30;f.target_must_be_validated_image=true;add_fact(out,seen,std::move(f));}}

    // Common subprocess list form: subprocess.run(["./payload", ...]) / Popen([...]).
    static const std::array<std::string_view,3> calls={"subprocess.run","subprocess.Popen","Popen"};for(auto call:calls){pos=0;while((pos=text.find(call,pos))!=std::string_view::npos){const auto start=pos;pos+=call.size();if(!python_module_level_position(text,start))continue;std::size_t p=pos;while(p<text.size()&&std::isspace(static_cast<unsigned char>(text[p])))++p;if(p>=text.size()||text[p]!='(')continue;++p;while(p<text.size()&&std::isspace(static_cast<unsigned char>(text[p])))++p;if(p>=text.size()||text[p]!='[')continue;++p;for(int item=0;item<32&&p<text.size();++item){while(p<text.size()&&(std::isspace(static_cast<unsigned char>(text[p]))||text[p]==','))++p;if(p<text.size()&&text[p]==']')break;auto q=parse_quoted(text,p);if(!q)break;p=q->second;if(!pathish_runner_word(q->first)||!sane_path_literal(q->first))continue;RelationshipReferenceEvidence f;f.kind="script_runner_argv";f.evidence_level="R2_STRUCTURAL_RELATION";f.semantic_relevance="STRUCTURAL";f.reference=q->first;f.resolution_mode=absolute_declared(f.reference)?"DECLARED_BASENAME_VALIDATED_IMAGE":"EXACT_RELATIVE_PATH";f.source_coordinate="current_input_file:line="+std::to_string(line_of(text,start))+":subprocess_argv";f.evidence_basis="literal subprocess argv member is statically exact";f.evidence_source="bounded Python subprocess list syntax";f.source_relation_role="runner";f.target_relation_role="launched_stage";f.source_priority_delta=20;f.target_priority_delta=20;f.priority_cap=30;f.target_must_be_validated_image=true;add_fact(out,seen,std::move(f));}}}
}

void extract_gdextension_descriptor(const AnalysisReport&r,std::vector<RelationshipReferenceEvidence>&out){
    const auto&d=r.gdextension_descriptor;if(!d.valid)return;
    for(const auto&decl:d.libraries){
        auto normalized=normalize_gdextension_resource_path(decl.path);if(!normalized)continue;
        RelationshipReferenceEvidence f;f.kind="godot_gdextension_library_reference";f.evidence_level="R2_STRUCTURAL_RELATION";f.semantic_relevance="STRUCTURAL";
        f.reference=*normalized;f.resolution_mode="GODOT_RES_PATH";f.target_symbol=d.entry_symbol;f.feature_key=decl.feature_key;
        f.source_coordinate="current_input_file:line="+std::to_string(decl.line)+":libraries."+decl.feature_key+";entry_symbol="+d.entry_symbol;
        f.evidence_basis="strictly validated .gdextension configuration.entry_symbol plus exact safe res:// library declaration";
        f.evidence_source="Godot GDExtension descriptor parser";f.source_relation_role="gdextension_descriptor";f.target_relation_role="native_extension";
        f.source_priority_delta=20;f.target_priority_delta=45;f.priority_cap=50;f.target_must_be_validated_image=true;out.push_back(std::move(f));
    }
}

void extract_linker_script(std::string_view text,std::vector<RelationshipReferenceEvidence>&out){
    static const std::regex keep_re(R"(KEEP\s*\(\s*([A-Za-z0-9_./+@-]+\.o)\s*\()",std::regex::ECMAScript);std::set<std::string> refs;
    const std::string s(text);for(std::sregex_iterator it(s.begin(),s.end(),keep_re),end;it!=end;++it){auto ref=(*it)[1].str();if(!sane_path_literal(ref)||!refs.insert(ref).second)continue;RelationshipReferenceEvidence f;f.kind="manifest_declared_member";f.evidence_level="R2_STRUCTURAL_RELATION";f.semantic_relevance="STRUCTURAL";f.reference=ref;f.resolution_mode="EXACT_RELATIVE_PATH";f.source_coordinate="current_input_file:line="+std::to_string(line_of(text,static_cast<std::size_t>(it->position())))+":GNU_ld_KEEP";f.evidence_basis="GNU ld KEEP() explicitly names this input object; bare filename resemblance is not used";f.evidence_source="bounded GNU ld linker-script syntax";f.source_relation_role="manifest_reference_source";f.target_relation_role="declared_member";f.target_priority_delta=12;f.priority_cap=20;out.push_back(std::move(f));}
}

struct Decoded{std::uint64_t va=0;ZydisDecodedInstruction ins{};std::array<ZydisDecodedOperand,ZYDIS_MAX_OPERAND_COUNT> ops{};};
ZydisRegister reg64(ZydisRegister r){return r==ZYDIS_REGISTER_NONE?r:ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64,r);}
std::optional<std::pair<std::size_t,std::size_t>> va_extent(const ElfInfo&e,std::uint64_t va,std::size_t n){for(const auto&s:e.segments){if(s.type!=1||va<s.address)continue;auto d=va-s.address;if(d>=s.file_size||s.offset>n||d>n-s.offset)continue;auto off=s.offset+d;if(off>=n)return{};auto avail=std::min<std::uint64_t>(s.file_size-d,n-off);return std::pair<std::size_t,std::size_t>{static_cast<std::size_t>(off),static_cast<std::size_t>(avail)};}return{};}
std::optional<std::uint64_t> add_signed(std::uint64_t b,std::int64_t d){if(d>=0){auto u=static_cast<std::uint64_t>(d);if(b>std::numeric_limits<std::uint64_t>::max()-u)return{};return b+u;}auto m=static_cast<std::uint64_t>(-(d+1))+1;if(b<m)return{};return b-m;}
std::optional<std::uint64_t> rip_mem(const Decoded&x,const ZydisDecodedOperand&o){if(o.type!=ZYDIS_OPERAND_TYPE_MEMORY||o.mem.index!=ZYDIS_REGISTER_NONE||reg64(o.mem.base)!=ZYDIS_REGISTER_RIP)return{};auto d=o.mem.disp.has_displacement?o.mem.disp.value:0;return add_signed(x.va+x.ins.length,d);}
std::optional<std::uint64_t> rel_target(const Decoded&x){for(std::uint8_t i=0;i<x.ins.operand_count_visible;++i){auto&o=x.ops[i];if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative)return add_signed(x.va+x.ins.length,o.imm.value.s);}return{};}
std::optional<Decoded> decode_one(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va){auto ex=va_extent(e,va,d.size());if(!ex)return{};ZydisDecoder dec;if(!ZYAN_SUCCESS(ZydisDecoderInit(&dec,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64)))return{};Decoded x;x.va=va;auto n=std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,ex->second);if(!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec,d.data()+ex->first,n,&x.ins,x.ops.data()))||!x.ins.length)return{};return x;}
std::vector<Decoded> decode_range(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t begin,std::uint64_t end){std::vector<Decoded>out;if(end<=begin||end-begin>(1u<<20))return out;for(auto va=begin;va<end&&out.size()<8192;){auto x=decode_one(d,e,va);if(!x)return{};va+=x->ins.length;out.push_back(*x);}return out;}
std::map<std::uint64_t,std::string> got_names(const ElfInfo&e){std::map<std::uint64_t,std::string>out;if(e.dynamic.state!="RESOLVED")return out;for(const auto&r:e.dynamic.relocations){if(r.symbol_index>=e.dynamic.symbols.size())continue;const auto&s=e.dynamic.symbols[r.symbol_index];if(s.imported&&!s.name.empty())out.emplace(r.target_va,s.name);}return out;}
std::optional<std::string> plt_name(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va,const std::map<std::uint64_t,std::string>&got){for(int i=0;i<2;++i){auto x=decode_one(d,e,va);if(!x)return{};if(x->ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR&&x->ins.operand_count_visible){auto slot=rip_mem(*x,x->ops[0]);if(!slot)return{};auto it=got.find(*slot);return it==got.end()?std::optional<std::string>{}:std::optional<std::string>{it->second};}if(x->ins.mnemonic!=ZYDIS_MNEMONIC_ENDBR64&&x->ins.mnemonic!=ZYDIS_MNEMONIC_NOP)return{};va+=x->ins.length;}return{};}
std::optional<std::string> call_name(std::span<const std::uint8_t>d,const ElfInfo&e,const Decoded&x,const std::map<std::uint64_t,std::string>&got){if(x.ins.meta.category!=ZYDIS_CATEGORY_CALL||!x.ins.operand_count_visible)return{};auto&o=x.ops[0];if(auto slot=rip_mem(x,o)){auto it=got.find(*slot);if(it!=got.end())return it->second;}if(o.type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&o.imm.is_relative){if(auto t=rel_target(x))return plt_name(d,e,*t,got);}return{};}
std::optional<std::uint64_t> pointer_arg_before(const std::vector<Decoded>&ins,std::size_t at,ZydisRegister wanted){auto cur=reg64(wanted);std::size_t seen=0;for(std::size_t z=at;z-->0&&seen++<96;){const auto&x=ins[z];if(x.ins.meta.category==ZYDIS_CATEGORY_CALL)return{};if(!x.ins.operand_count_visible||x.ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER||reg64(x.ops[0].reg.value)!=cur||(x.ops[0].actions&ZYDIS_OPERAND_ACTION_WRITE)==0)continue;if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_REGISTER){cur=reg64(x.ops[1].reg.value);continue;}if(x.ins.mnemonic==ZYDIS_MNEMONIC_LEA&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_MEMORY){auto&m=x.ops[1].mem;if(m.index==ZYDIS_REGISTER_NONE&&reg64(m.base)==ZYDIS_REGISTER_RIP)return add_signed(x.va+x.ins.length,m.disp.has_displacement?m.disp.value:0);}if(x.ins.mnemonic==ZYDIS_MNEMONIC_MOV&&x.ins.operand_count_visible>=2&&x.ops[1].type==ZYDIS_OPERAND_TYPE_IMMEDIATE&&!x.ops[1].imm.is_relative)return x.ops[1].imm.value.u;return{};}return{};}
std::optional<std::string> cstring_at(std::span<const std::uint8_t>d,const ElfInfo&e,std::uint64_t va){auto ex=va_extent(e,va,d.size());if(!ex||!ex->second)return{};const auto max=std::min<std::size_t>(ex->second,1024);std::string s;for(std::size_t i=0;i<max;++i){char c=static_cast<char>(d[ex->first+i]);if(!c)return sane_path_literal(s)?std::optional<std::string>{s}:std::optional<std::string>{};if(static_cast<unsigned char>(c)<0x20||static_cast<unsigned char>(c)>=0x7f)return{};s.push_back(c);}return{};}

void extract_native_elf(const AnalysisReport&r,std::vector<RelationshipReferenceEvidence>&out){
    const auto&e=r.elf;if(!e.valid||!e.elf64||!e.little_endian||e.machine!=62||e.dynamic.state!="RESOLVED")return;std::error_code ec;auto sz=std::filesystem::file_size(r.input,ec);if(ec||sz>kNativeCap)return;std::ifstream f(r.input,std::ios::binary);if(!f)return;std::vector<std::uint8_t>d(static_cast<std::size_t>(sz));if(!d.empty())f.read(reinterpret_cast<char*>(d.data()),static_cast<std::streamsize>(d.size()));d.resize(static_cast<std::size_t>(std::max<std::streamsize>(0,f.gcount())));if(d.empty())return;
    const auto got=got_names(e);if(got.empty())return;
    // Recover the common glibc x86-64 main pointer only when the ELF entry makes
    // an exact call through the __libc_start_main relocation. This avoids
    // promoting literal open() calls in disconnected/dead functions.
    std::vector<Decoded> entry;auto cur=e.entry;for(int i=0;i<48;++i){auto x=decode_one(d,e,cur);if(!x)break;entry.push_back(*x);cur+=x->ins.length;if(x->ins.meta.category==ZYDIS_CATEGORY_RET)break;}
    std::optional<std::uint64_t> main_va;for(std::size_t i=0;i<entry.size();++i){auto n=call_name(d,e,entry[i],got);if(!n||*n!="__libc_start_main")continue;main_va=pointer_arg_before(entry,i,ZYDIS_REGISTER_RDI);break;}if(!main_va)return;
    const ElfUnwindFde* main_fde=nullptr;for(const auto&fde:e.unwind.fdes)if(fde.function_file_backed&&fde.function_start_va<=*main_va&&*main_va<fde.function_end_va){main_fde=&fde;break;}if(!main_fde||main_fde->function_size>(1u<<20))return;auto ins=decode_range(d,e,main_fde->function_start_va,main_fde->function_end_va);if(ins.empty())return;
    std::set<std::string> seen;for(std::size_t i=0;i<ins.size();++i){auto n=call_name(d,e,ins[i],got);if(!n||(*n!="open"&&*n!="open64"&&*n!="fopen"&&*n!="fopen64"))continue;auto ptr=pointer_arg_before(ins,i,ZYDIS_REGISTER_RDI);if(!ptr)continue;auto s=cstring_at(d,e,*ptr);if(!s||!seen.insert(*s).second)continue;RelationshipReferenceEvidence x;x.kind="native_literal_data_dependency";x.evidence_level="R3_EXACT_DATA_DEPENDENCY";x.semantic_relevance="DATA_DEPENDENCY";x.reference=*s;x.resolution_mode=absolute_declared(*s)?"EXACT_ABSOLUTE_PATH":"EXACT_RELATIVE_PATH";std::ostringstream c;c<<"current_input_image:VA=0x"<<std::hex<<ins[i].va<<":"<<*n<<"(literal_path)";x.source_coordinate=c.str();x.evidence_basis="entry -> exact __libc_start_main(main) closure + main FDE + exact imported file-open call + exact argument-0 literal pointer";x.evidence_source="ELF PT_LOAD/dynamic relocations + x86-64 bounded Zydis dataflow";x.source_relation_role="data_consumer";x.target_relation_role="consumed_sidecar";x.source_priority_delta=10;x.target_priority_delta=50;x.priority_cap=60;out.push_back(std::move(x));}
}
}

std::vector<RelationshipReferenceEvidence> extract_relationship_reference_evidence(const AnalysisReport&r){
    std::vector<RelationshipReferenceEvidence> out;
    auto ext=lower_ascii(path_utf8(r.input.extension()));
    if(auto t=read_bounded_text(r.input)){if(ext==".py"||t->rfind("#!",0)==0)extract_python(*t,out);if(ext==".ld"||t->find("SECTIONS")!=std::string::npos)extract_linker_script(*t,out);}
    extract_gdextension_descriptor(r,out);
    extract_native_elf(r,out);
    return out;
}
}
