#include "prts/dwarf_expression_surface.hpp"
#include "prts/elf.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace prts {
namespace {
constexpr std::uint64_t kMaxDebugSection=16ull*1024*1024;
constexpr std::size_t kMaxUnits=4096;
constexpr std::size_t kMaxAbbrevs=65536;
constexpr std::size_t kMaxDies=262144;
constexpr std::size_t kMaxAttrs=256;
constexpr std::size_t kMaxExpr=4096;
constexpr std::size_t kMaxLineRecords=65536;
constexpr std::size_t kMaxCandidates=32;
constexpr std::size_t kMaxExactHex=8192;

struct View { const std::uint8_t* p=nullptr; std::size_t n=0; std::uint64_t file=0; };
std::optional<View> section_view(std::span<const std::uint8_t>d,const ElfInfo&elf,std::string_view name) {
    for(const auto&s:elf.sections)if(s.name==name){
        if(s.type==8||s.size>kMaxDebugSection||s.offset>d.size()||s.size>d.size()-s.offset)return{};
        return View{d.data()+static_cast<std::size_t>(s.offset),static_cast<std::size_t>(s.size),s.offset};
    }
    return{};
}
bool rd16(const View&v,std::size_t o,std::uint16_t&x){if(o>v.n||2>v.n-o)return false;x=std::uint16_t(v.p[o])|(std::uint16_t(v.p[o+1])<<8);return true;}
bool rd32(const View&v,std::size_t o,std::uint32_t&x){if(o>v.n||4>v.n-o)return false;x=std::uint32_t(v.p[o])|(std::uint32_t(v.p[o+1])<<8)|(std::uint32_t(v.p[o+2])<<16)|(std::uint32_t(v.p[o+3])<<24);return true;}
std::optional<std::uint64_t> uintn(const View&v,std::size_t&o,std::size_t width,std::size_t end){if(width>8||o>end||width>end-o)return{};std::uint64_t x=0;for(std::size_t i=0;i<width;++i)x|=std::uint64_t(v.p[o+i])<<(8*i);o+=width;return x;}
std::optional<std::uint64_t> uleb(const View&v,std::size_t&o,std::size_t end){std::uint64_t x=0;unsigned sh=0;for(unsigned i=0;i<10&&o<end;++i){const auto b=v.p[o++];if(sh>=64&&b)return{};x|=std::uint64_t(b&0x7f)<<sh;if(!(b&0x80))return x;sh+=7;}return{};}
std::optional<std::int64_t> sleb(const View&v,std::size_t&o,std::size_t end){std::uint64_t x=0;unsigned sh=0;std::uint8_t b=0;for(unsigned i=0;i<10&&o<end;++i){b=v.p[o++];x|=std::uint64_t(b&0x7f)<<sh;sh+=7;if(!(b&0x80)){if(sh<64&&(b&0x40))x|=(~std::uint64_t(0))<<sh;return static_cast<std::int64_t>(x);}}return{};}
std::string hex_bytes(const std::uint8_t*p,std::size_t n){if(n>kMaxExactHex)return{};std::ostringstream q;q<<std::hex<<std::setfill('0');for(std::size_t i=0;i<n;++i)q<<std::setw(2)<<unsigned(p[i]);return q.str();}
std::string hx(std::uint64_t x){std::ostringstream q;q<<"0x"<<std::hex<<x;return q.str();}
bool executable_va(const ElfInfo&elf,std::uint64_t va){for(const auto&s:elf.segments)if(s.type==1&&(s.flags&1u)&&va>=s.address&&va-s.address<s.memory_size)return true;return false;}

struct AttrSpec{std::uint64_t name=0,form=0;std::int64_t implicit=0;};
struct Abbrev{std::uint64_t code=0,tag=0;bool children=false;std::vector<AttrSpec>attrs;};
using AbbrevTable=std::map<std::uint64_t,Abbrev>;
std::optional<AbbrevTable> parse_abbrevs(const View&ab,std::size_t start,bool&limited){
    if(start>=ab.n)return{};
    AbbrevTable t;std::size_t p=start;
    while(p<ab.n&&t.size()<kMaxAbbrevs){auto code=uleb(ab,p,ab.n);if(!code)return{};if(!*code)break;auto tag=uleb(ab,p,ab.n);if(!tag||p>=ab.n)return{};Abbrev a;a.code=*code;a.tag=*tag;a.children=ab.p[p++]!=0;
        for(std::size_t ai=0;ai<kMaxAttrs;++ai){auto name=uleb(ab,p,ab.n),form=uleb(ab,p,ab.n);if(!name||!form)return{};if(!*name&&!*form)break;if(!*name||!*form)return{};AttrSpec s;s.name=*name;s.form=*form;if(s.form==0x21){auto v=sleb(ab,p,ab.n);if(!v)return{};s.implicit=*v;}a.attrs.push_back(s);if(ai+1==kMaxAttrs){limited=true;return{};}}
        t.emplace(a.code,std::move(a));
    }
    if(t.size()>=kMaxAbbrevs){limited=true;return{};}return t;
}

struct FormValue{bool ok=false;std::optional<std::uint64_t>u;std::optional<std::pair<std::size_t,std::size_t>>block;};
FormValue read_form(const View&info,std::size_t&p,std::size_t end,std::uint64_t form,std::uint8_t addr_size,std::uint16_t version,std::size_t depth=0){
    FormValue r;if(depth>2)return r;
    auto fixed=[&](std::size_t n)->bool{if(p>end||n>end-p)return false;p+=n;return true;};
    auto fixed_u=[&](std::size_t n)->bool{auto x=uintn(info,p,n,end);if(!x)return false;r.u=*x;return true;};
    switch(form){
    case 0x01: if(!fixed_u(addr_size))return r;break; // addr
    case 0x03:{auto n=uintn(info,p,2,end);if(!n||*n>end-p)return r;r.block={{p,static_cast<std::size_t>(*n)}};p+=*n;break;}
    case 0x04:{auto n=uintn(info,p,4,end);if(!n||*n>end-p)return r;r.block={{p,static_cast<std::size_t>(*n)}};p+=*n;break;}
    case 0x05: if(!fixed_u(2))return r;break;
    case 0x06: if(!fixed_u(4))return r;break;
    case 0x07: if(!fixed_u(8))return r;break;
    case 0x08:{while(p<end&&info.p[p])++p;if(p>=end)return r;++p;break;}
    case 0x09:{auto n=uleb(info,p,end);if(!n||*n>end-p)return r;r.block={{p,static_cast<std::size_t>(*n)}};p+=*n;break;}
    case 0x0a:{auto n=uintn(info,p,1,end);if(!n||*n>end-p)return r;r.block={{p,static_cast<std::size_t>(*n)}};p+=*n;break;}
    case 0x0b: if(!fixed_u(1))return r;break;
    case 0x0c: if(!fixed_u(1))return r;break;
    case 0x0d:{auto x=sleb(info,p,end);if(!x)return r;break;}
    case 0x0e: if(!fixed_u(4))return r;break; // strp, 32-bit DWARF only
    case 0x0f:{auto x=uleb(info,p,end);if(!x)return r;r.u=*x;break;}
    case 0x10: if(!fixed(version<=2?addr_size:4))return r;break;
    case 0x11: if(!fixed_u(1))return r;break;
    case 0x12: if(!fixed_u(2))return r;break;
    case 0x13: if(!fixed_u(4))return r;break;
    case 0x14: if(!fixed_u(8))return r;break;
    case 0x15:{auto x=uleb(info,p,end);if(!x)return r;r.u=*x;break;}
    case 0x16:{auto actual=uleb(info,p,end);if(!actual)return r;return read_form(info,p,end,*actual,addr_size,version,depth+1);}
    case 0x17: if(!fixed_u(4))return r;break; // sec_offset
    case 0x18:{auto n=uleb(info,p,end);if(!n||*n>kMaxExpr||*n>end-p)return r;r.block={{p,static_cast<std::size_t>(*n)}};p+=*n;break;}
    case 0x19: break; // flag_present
    case 0x1a: case 0x1b: case 0x22: case 0x23:{auto x=uleb(info,p,end);if(!x)return r;r.u=*x;break;}
    case 0x1c: if(!fixed(4))return r;break;
    case 0x1d: if(!fixed(4))return r;break;
    case 0x1e: if(!fixed(16))return r;break;
    case 0x1f: if(!fixed(4))return r;break;
    case 0x20: if(!fixed(8))return r;break;
    case 0x21: break; // implicit_const lives in abbrev
    case 0x24: if(!fixed(8))return r;break;
    case 0x25: case 0x29: if(!fixed(1))return r;break;
    case 0x26: case 0x2a: if(!fixed(2))return r;break;
    case 0x27: case 0x2b: if(!fixed(3))return r;break;
    case 0x28: case 0x2c: if(!fixed(4))return r;break;
    default:return r;
    }
    r.ok=true;return r;
}

struct ExprScan{bool parsed=false,vendor=false;std::uint8_t opcode=0;};
ExprScan scan_expr(const std::uint8_t*p,std::size_t n,std::uint8_t addr_size){
    ExprScan r;if(!n||n>kMaxExpr)return r;std::size_t o=0;
    auto bytes=[&](std::size_t k){if(o>n||k>n-o)return false;o+=k;return true;};
    auto ul=[&](){for(unsigned i=0;i<10&&o<n;++i){auto b=p[o++];if(!(b&0x80))return true;}return false;};
    auto sl=ul;
    while(o<n){const auto op=p[o++];if(op>=0xe0){r.parsed=true;r.vendor=true;r.opcode=op;return r;}
        if((op>=0x30&&op<=0x6f)||op==0x06||op==0x12||op==0x13||op==0x14||op==0x16||op==0x17||op==0x18||op==0x19||op==0x1a||op==0x1b||op==0x1c||op==0x1d||op==0x1e||op==0x1f||op==0x20||op==0x21||op==0x22||op==0x24||op==0x25||op==0x26||op==0x27||op==0x29||op==0x2a||op==0x2b||op==0x2c||op==0x2d||op==0x2e||op==0x96||op==0x97||op==0x9b||op==0x9c||op==0x9f)continue;
        bool ok=true;
        if(op>=0x70&&op<=0x8f)ok=sl();
        else switch(op){
        case 0x03:ok=bytes(addr_size);break;case 0x08:case 0x09:case 0x15:case 0x94:case 0x95:ok=bytes(1);break;
        case 0x0a:case 0x0b:case 0x28:case 0x2f:case 0x98:ok=bytes(2);break;
        case 0x0c:case 0x0d:case 0x99:ok=bytes(4);break;case 0x0e:case 0x0f:ok=bytes(8);break;
        case 0x10:case 0x23:case 0x90:case 0x93:case 0xa1:case 0xa2:case 0xa8:case 0xa9:ok=ul();break;
        case 0x11:case 0x91:ok=sl();break;
        case 0x92:ok=ul()&&sl();break;
        case 0x9a:ok=bytes(4);break;
        case 0x9d:ok=ul()&&ul();break;
        case 0x9e:case 0xa3:{std::size_t before=o;ok=ul();if(ok){std::uint64_t len=0;unsigned sh=0;for(std::size_t i=before;i<o;++i){auto b=p[i];len|=std::uint64_t(b&0x7f)<<sh;sh+=7;}ok=len<=kMaxExpr&&bytes(static_cast<std::size_t>(len));}break;}
        case 0xa0:ok=bytes(4)&&sl();break;
        case 0xa4:{ok=ul();if(ok&&o<n){auto sz=p[o++];ok=bytes(sz);}else ok=false;break;}
        case 0xa5:ok=ul()&&ul();break;
        case 0xa6:case 0xa7:ok=bytes(1)&&ul();break;
        default:ok=false;break;
        }
        if(!ok)return r;
    }
    r.parsed=true;return r;
}

struct CuScan { std::set<std::uint64_t> stmt_lists; std::vector<DwarfVendorProgramFact> expr; std::uint64_t standard=0,malformed=0; bool limited=false; std::string error; };
CuScan scan_info(const View&info,const View&ab,const std::string&artifact){
    CuScan out;std::map<std::uint64_t,AbbrevTable>tables;std::size_t u=0,units=0,dies=0;
    while(u+11<=info.n&&units++<kMaxUnits){std::uint32_t len=0;if(!rd32(info,u,len)||!len)break;if(len==0xffffffffu){out.error="DWARF64 units are outside the bounded AS parser";break;}const std::uint64_t e64=std::uint64_t(u)+4+len;if(e64>info.n){out.error=".debug_info unit exceeds section";break;}const auto end=static_cast<std::size_t>(e64);std::uint16_t ver=0;if(!rd16(info,u+4,ver)){out.error="truncated CU header";break;}std::uint32_t aoff=0;std::uint8_t asz=0;std::size_t p=0;
        if(ver>=2&&ver<=4){if(!rd32(info,u+6,aoff)||u+10>=end){out.error="truncated DWARF2-4 CU header";break;}asz=info.p[u+10];p=u+11;}
        else if(ver==5){if(u+12>end||!rd32(info,u+8,aoff)){out.error="truncated DWARF5 CU header";break;}const auto unit_type=info.p[u+6];asz=info.p[u+7];if(unit_type!=1){u=end;continue;}p=u+12;}
        else {u=end;continue;}
        if(asz!=4&&asz!=8){out.error="unsupported CU address size";u=end;continue;}
        auto ti=tables.find(aoff);if(ti==tables.end()){bool lim=false;auto t=parse_abbrevs(ab,aoff,lim);out.limited|=lim;if(!t){out.error="bounded .debug_abbrev parse failed";u=end;continue;}ti=tables.emplace(aoff,std::move(*t)).first;}
        while(p<end&&dies++<kMaxDies){const auto die=p;auto code=uleb(info,p,end);if(!code){out.error="malformed DIE abbrev code";break;}if(!*code)continue;auto ai=ti->second.find(*code);if(ai==ti->second.end()){out.error="DIE references unknown abbreviation";break;}const auto&av=ai->second;
            for(const auto&s:av.attrs){auto fv=read_form(info,p,end,s.form,asz,ver);if(!fv.ok){out.error="unsupported or malformed DIE form in bounded parser";p=end;break;}
                if(av.tag==0x11&&s.name==0x10&&fv.u)out.stmt_lists.insert(*fv.u); // CU -> .debug_line
                if((av.tag==0x34||av.tag==0x05)&&s.name==0x02&&s.form==0x18&&fv.block){const auto [bo,bn]=*fv.block;auto es=scan_expr(info.p+bo,bn,asz);if(!es.parsed){++out.malformed;continue;}if(!es.vendor){++out.standard;continue;}if(out.expr.size()>=kMaxCandidates){out.limited=true;continue;}DwarfVendorProgramFact f;f.carrier="DWARF_EXPRESSION";f.section=".debug_info";f.consumer_relation=av.tag==0x34?"DW_TAG_variable DW_AT_location":"DW_TAG_formal_parameter DW_AT_location";f.semantic_state="REQUIRES_VENDOR_EXPRESSION_SEMANTICS";f.unit_offset=u;f.die_offset=die;f.file_offset=info.file+bo;f.size=bn;f.vendor_record_count=1;f.vendor_byte_count=bn;f.vendor_opcodes=hx(es.opcode);f.exact_bytes_hex=hex_bytes(info.p+bo,bn);out.expr.push_back(std::move(f));}
            }
        }
        if(dies>=kMaxDies){out.limited=true;break;}u=end;
    }
    if(units>=kMaxUnits&&u<info.n)out.limited=true;
    (void)artifact;return out;
}

struct LineCandidate { DwarfVendorProgramFact fact; bool malformed=false; };
std::optional<LineCandidate> scan_line_unit(const View&line,const ElfInfo&elf,std::uint64_t off){
    if(off>line.n||line.n-off<10)return{};
    const auto u=static_cast<std::size_t>(off);std::uint32_t len=0;if(!rd32(line,u,len)||!len||len==0xffffffffu)return{};const auto e64=std::uint64_t(u)+4+len;if(e64>line.n)return LineCandidate{DwarfVendorProgramFact{},true};const auto end=static_cast<std::size_t>(e64);std::uint16_t ver=0;if(!rd16(line,u+4,ver)||ver<2||ver>4)return{};std::uint32_t hlen=0;if(!rd32(line,u+6,hlen))return LineCandidate{DwarfVendorProgramFact{},true};const auto hend64=std::uint64_t(u)+10+hlen;if(hend64>end)return LineCandidate{DwarfVendorProgramFact{},true};const auto hend=static_cast<std::size_t>(hend64);std::size_t fixed=u+10;std::uint8_t opbase=0;std::size_t lengths=0;
    if(ver==4){if(fixed+6>hend)return LineCandidate{DwarfVendorProgramFact{},true};opbase=line.p[fixed+5];lengths=fixed+6;}
    else {if(fixed+5>hend)return LineCandidate{DwarfVendorProgramFact{},true};opbase=line.p[fixed+4];lengths=fixed+5;}
    if(!opbase||lengths+std::size_t(opbase-1)>hend)return LineCandidate{DwarfVendorProgramFact{},true};
    std::vector<std::uint8_t>argc(opbase);for(std::size_t i=1;i<opbase;++i)argc[i]=line.p[lengths+i-1];
    std::size_t p=hend,records=0;std::uint64_t vendor_count=0,vendor_bytes=0;std::set<unsigned>vendor_ops;bool endseq=false,exec_addr=false;const auto addr_size=elf.elf64?8u:4u;
    while(p<end&&records++<kMaxLineRecords){const auto rec=p;const auto op=line.p[p++];if(op==0){auto n=uleb(line,p,end);if(!n||!*n||*n>end-p)return LineCandidate{DwarfVendorProgramFact{},true};const auto payload=p;const auto ext=line.p[payload];if(ext==1)endseq=true;else if(ext==2&&*n>=1+addr_size){std::uint64_t a=0;for(unsigned i=0;i<addr_size;++i)a|=std::uint64_t(line.p[payload+1+i])<<(8*i);exec_addr|=executable_va(elf,a);}else if(ext>4){++vendor_count;vendor_ops.insert(ext);vendor_bytes+=std::uint64_t(p+*n-rec);}p+=static_cast<std::size_t>(*n);continue;}
        if(op<opbase){if(op==9){if(p>end||2>end-p)return LineCandidate{DwarfVendorProgramFact{},true};p+=2;continue;}for(unsigned k=0;k<argc[op];++k){if(op==3){if(!sleb(line,p,end))return LineCandidate{DwarfVendorProgramFact{},true};}else if(!uleb(line,p,end))return LineCandidate{DwarfVendorProgramFact{},true};}}
    }
    if(records>=kMaxLineRecords&&p<end)return LineCandidate{DwarfVendorProgramFact{},true};
    if(!vendor_count)return{};
    DwarfVendorProgramFact f;f.carrier="DWARF_LINE_PROGRAM";f.section=".debug_line";f.consumer_relation="DW_TAG_compile_unit DW_AT_stmt_list -> this line unit";f.semantic_state="REQUIRES_VENDOR_EXPRESSION_SEMANTICS";f.unit_offset=off;f.file_offset=line.file+hend;f.size=end-hend;f.vendor_record_count=vendor_count;f.vendor_byte_count=vendor_bytes;f.executable_address_relation=exec_addr;std::ostringstream ops;bool first=true;for(auto x:vendor_ops){if(!first)ops<<',';first=false;ops<<"0x"<<std::hex<<x;}f.vendor_opcodes=ops.str();f.exact_bytes_hex=hex_bytes(line.p+hend,end-hend);
    // Unknown line extensions are common enough that mere presence is not a
    // product signal. Require a closed standard envelope plus material vendor
    // density and an executable-address relation in the same consumed unit.
    if(!endseq||!exec_addr||vendor_count<4||vendor_bytes<16)return{};
    return LineCandidate{std::move(f),false};
}
}

DwarfVendorSurfaceInfo analyze_dwarf_vendor_surface(
    std::span<const std::uint8_t> data,const ElfInfo&elf,const std::string&artifact_identity){
    DwarfVendorSurfaceInfo out;if(!elf.valid||!elf.little_endian||!elf.section_table_present)return out;auto info=section_view(data,elf,".debug_info"),ab=section_view(data,elf,".debug_abbrev");if(!info||!ab)return out;auto cu=scan_info(*info,*ab,artifact_identity);out.analysis_limited=cu.limited;out.error=cu.error;out.standard_expression_count=cu.standard;out.malformed_expression_count=cu.malformed;for(auto&f:cu.expr)out.candidates.push_back(std::move(f));
    if(auto line=section_view(data,elf,".debug_line")){for(const auto off:cu.stmt_lists){if(out.candidates.size()>=kMaxCandidates){out.analysis_limited=true;break;}auto c=scan_line_unit(*line,elf,off);if(c&&c->malformed){if(out.error.empty())out.error="malformed consumed .debug_line unit";continue;}if(c)out.candidates.push_back(std::move(c->fact));}}
    if(!out.candidates.empty())out.state=out.analysis_limited?"PARTIAL":"RESOLVED";else if(out.analysis_limited||!out.error.empty())out.state="PARTIAL";return out;
}

std::vector<Finding> compose_dwarf_vendor_surfaces(
    std::span<const std::uint8_t> data,const ElfInfo&elf,const std::string&artifact_identity){
    std::vector<Finding> out;auto s=analyze_dwarf_vendor_surface(data,elf,artifact_identity);
    // Ambiguity is a false-positive guard, not an invitation to choose a favorite
    // DIE/unit. Research output retains candidates; product guidance requires one.
    if(s.analysis_limited||s.candidates.size()!=1)return out;
    const auto&x=s.candidates.front();Finding f;f.kind="execution_surface";f.family="Exceptional execution surface";f.variant="ELF bounded DWARF vendor program surface";f.state="CONFIRMED";f.confidence=0.88;
    f.evidence.push_back("one consumer-related "+x.carrier+" contains structurally bounded vendor opcode data inside a valid DWARF envelope");
    f.evidence.push_back("carrier="+x.carrier+", vendor_opcodes="+x.vendor_opcodes+", vendor_records="+std::to_string(x.vendor_record_count)+", vendor_bytes="+std::to_string(x.vendor_byte_count));
    f.evidence.push_back("consumer relation: "+x.consumer_relation);
    if(x.executable_address_relation)f.evidence.push_back("the same consumed line program contains a standard set-address relation into executable image code");
    f.negative_evidence.push_back("vendor opcode semantics are unauthenticated and are not executed or guessed; no checker result, value, location, or flag is derived");
    f.negative_evidence.push_back("multiple candidate vendor programs, malformed envelopes, dead debug sections, and isolated unknown bytes are refused by the product gate");
    f.ranges.push_back(file_offset_range(x.file_offset,x.size,x.carrier+" exact bounded program bytes",CoordinateBasis::CURRENT_INPUT_FILE,artifact_identity));
    f.fields["surface_state"]="REVIEW_ALTERNATE_SURFACE";f.fields["semantic_state"]="REQUIRES_VENDOR_EXPRESSION_SEMANTICS";f.fields["static_control_relation"]="BOUNDED_DWARF_VENDOR_PROGRAM_CONSUMER_RELATION";f.fields["runtime_confirmation"]="NOT_OBSERVED";f.fields["carrier_kind"]=x.carrier;f.fields["section"]=x.section;f.fields["unit_offset"]=hx(x.unit_offset);f.fields["die_offset"]=hx(x.die_offset);f.fields["program_file_offset"]=hx(x.file_offset);f.fields["program_size"]=std::to_string(x.size);f.fields["vendor_opcodes"]=x.vendor_opcodes;f.fields["vendor_record_count"]=std::to_string(x.vendor_record_count);f.fields["vendor_byte_count"]=std::to_string(x.vendor_byte_count);f.fields["vendor_semantics"]="UNKNOWN_UNAUTHENTICATED";f.fields["consumer_relation"]=x.consumer_relation;f.fields["exact_program_bytes_hex"]=x.exact_bytes_hex;f.fields["standard_expression_count"]=std::to_string(s.standard_expression_count);f.fields["malformed_expression_count"]=std::to_string(s.malformed_expression_count);
    f.suggested_actions.push_back("inspect the exact ranged DWARF program and identify an authenticated consumer/vendor specification before assigning opcode semantics");f.suggested_actions.push_back("if no ecosystem-wide authenticated semantics are available, preserve REQUIRES_VENDOR_EXPRESSION_SEMANTICS rather than implementing a VM solver");out.push_back(std::move(f));return out;
}
}
