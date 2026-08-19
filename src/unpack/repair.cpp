#include "prts/repair.hpp"
#include "prts/sha256.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <optional>
#include <sstream>
#include <system_error>
#ifndef _WIN32
#include <cerrno>
#include <unistd.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace prts { namespace {
constexpr std::uint32_t kPe32MachineI386=0x14c;
constexpr std::uint32_t kImageScnMemExecute=0x20000000u;
constexpr std::size_t kPackHeaderSize=32;
constexpr std::uint8_t kUpxFormatWin32Pe=9;
constexpr std::array<std::uint8_t,4> kUpxMagic{{'U','P','X','!'}};
constexpr std::array<std::uint8_t,4> kUpx0{{'U','P','X','0'}};
constexpr std::array<std::uint8_t,4> kUpx1{{'U','P','X','1'}};

struct RawPe {
    std::uint32_t lfanew=0;
    std::uint16_t nsec=0,opt_size=0;
    std::size_t opt=0,section_table=0,security_directory=0;
    std::uint32_t file_alignment=0,section_alignment=0;
    std::uint32_t cert_offset=0,cert_size=0;
    bool cert_directory_available=false;
};
struct PackHeader {
    std::size_t offset=0;
    std::array<std::uint8_t,4> magic{};
    std::uint8_t version=0,format=0,method=0,level=0;
    std::uint32_t u_adler=0,c_adler=0,u_len=0,c_len=0,u_file_size=0;
    std::uint8_t filter=0,filter_cto=0,unused=0,header_checksum=0;
};

template<class T> bool rd(std::span<const std::uint8_t>d,std::size_t off,T&v){
    if(off>d.size()||sizeof(T)>d.size()-off)return false;
    std::memcpy(&v,d.data()+off,sizeof(T));return true;
}
bool bytes_eq(std::span<const std::uint8_t>d,std::size_t off,std::span<const std::uint8_t> want){
    return off<=d.size()&&want.size()<=d.size()-off&&std::equal(want.begin(),want.end(),d.begin()+static_cast<std::ptrdiff_t>(off));
}
std::string hex_bytes(std::span<const std::uint8_t>b){
    std::ostringstream o;o<<std::hex<<std::setfill('0');for(auto x:b)o<<std::setw(2)<<unsigned(x);return o.str();
}
std::string json_escape(std::string_view s){
    std::ostringstream o;for(unsigned char c:s){switch(c){case '"':o<<"\\\"";break;case '\\':o<<"\\\\";break;case '\b':o<<"\\b";break;case '\f':o<<"\\f";break;case '\n':o<<"\\n";break;case '\r':o<<"\\r";break;case '\t':o<<"\\t";break;default:if(c<0x20)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(c)<<std::dec;else o<<char(c);}}return o.str();
}
std::uint32_t adler32(std::span<const std::uint8_t>d){
    constexpr std::uint32_t mod=65521;std::uint32_t a=1,b=0;std::size_t i=0;
    while(i<d.size()){auto n=std::min<std::size_t>(5552,d.size()-i);for(std::size_t j=0;j<n;++j){a+=d[i+j];b+=a;}a%=mod;b%=mod;i+=n;}return (b<<16)|a;
}
std::uint64_t align_up(std::uint64_t v,std::uint64_t a){if(!a)return v;auto r=v%a;return r?v+(a-r):v;}
std::optional<RawPe> raw_pe(std::span<const std::uint8_t>d){
    RawPe r;if(d.size()<0x40||d[0]!='M'||d[1]!='Z'||!rd(d,0x3c,r.lfanew))return std::nullopt;
    if(r.lfanew>d.size()||24>d.size()-r.lfanew||!bytes_eq(d,r.lfanew,std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>("PE\0\0"),4)))return std::nullopt;
    if(!rd(d,r.lfanew+6,r.nsec)||!rd(d,r.lfanew+20,r.opt_size))return std::nullopt;
    r.opt=std::size_t(r.lfanew)+24;if(r.opt>d.size()||r.opt_size>d.size()-r.opt)return std::nullopt;
    std::uint16_t magic=0;if(!rd(d,r.opt,magic)||magic!=0x10b)return std::nullopt;
    if(!rd(d,r.opt+32,r.section_alignment)||!rd(d,r.opt+36,r.file_alignment))return std::nullopt;
    r.section_table=r.opt+r.opt_size;if(r.section_table>d.size()||std::size_t(r.nsec)>((d.size()-r.section_table)/40))return std::nullopt;
    std::uint32_t dirs=0;if(rd(d,r.opt+92,dirs)&&dirs>4){auto dd=r.opt+96; if(dd<=r.opt+r.opt_size&&40<=r.opt+r.opt_size-dd){r.security_directory=dd+32;r.cert_directory_available=true;rd(d,r.security_directory,r.cert_offset);rd(d,r.security_directory+4,r.cert_size);}}
    return r;
}
std::optional<PackHeader> pack_header(std::span<const std::uint8_t>d,std::size_t off){
    if(off>d.size()||kPackHeaderSize>d.size()-off)return std::nullopt;
    PackHeader h;h.offset=off;std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(off),4,h.magic.begin());
    h.version=d[off+4];h.format=d[off+5];h.method=d[off+6];h.level=d[off+7];
    rd(d,off+8,h.u_adler);rd(d,off+12,h.c_adler);rd(d,off+16,h.u_len);rd(d,off+20,h.c_len);rd(d,off+24,h.u_file_size);h.filter=d[off+28];h.filter_cto=d[off+29];h.unused=d[off+30];h.header_checksum=d[off+31];return h;
}
bool recognized_method(std::uint8_t m){return m==2||m==5||m==8||m==14;}
bool strict_raw_geometry(std::span<const std::uint8_t>d,const PeInfo&pe,std::string&why){
    if(!pe.valid){why="base PE parse failed";return false;}for(std::size_t i=0;i<pe.sections.size();++i){const auto&s=pe.sections[i];if(!s.raw_size)continue;const auto end=std::uint64_t(s.raw_offset)+s.raw_size;if(end>d.size()){why="section "+std::to_string(i)+" declared raw range exceeds observed file bytes";return false;}}return true;
}
bool range_executable(const PeInfo&pe,std::uint64_t off,std::uint64_t size){
    if(!size)return false;
    const auto end=off+size;
    for(const auto&s:pe.sections){if(!(s.characteristics&kImageScnMemExecute)||!s.raw_size)continue;const std::uint64_t a=s.raw_offset,b=a+s.raw_size;if(off<b&&a<end)return true;}
    return false;
}
void validation(RepairProposal&p,RepairValidationStage stage,RepairValidationState state,ModelEvidenceLevel level,std::string detail){p.validations.push_back({stage,state,level,std::move(detail)});if(level>p.evidence_ceiling)p.evidence_ceiling=level;}
void append_terminal_not_run(RepairProposal&p){
    validation(p,RepairValidationStage::NativeBoundary,RepairValidationState::NotRun,ModelEvidenceLevel::None,"static repair producer never executes a candidate");
    validation(p,RepairValidationStage::ResultSemanticClosure,RepairValidationState::NotRun,ModelEvidenceLevel::None,"no downstream decoded-image or behavior oracle is part of the product repair gate");
}
RepairProposal base(const std::filesystem::path&input,std::span<const std::uint8_t>d,RepairClass c){RepairProposal p;p.input_path=input;p.input_size=d.size();p.input_sha256=sha256_bytes(d);p.repair_class=c;p.automatic_runtime_execution_eligible=false;return p;}
void reject(RepairProposal&p,std::string why){p.state=RepairState::Rejected;p.decision_reason=std::move(why);p.static_reanalysis_eligible=false;}
void ambiguous(RepairProposal&p,std::string why){p.state=RepairState::Ambiguous;p.decision_reason=why;p.ambiguity.push_back(std::move(why));p.static_reanalysis_eligible=false;}
void add_change(RepairProposal&p,std::span<const std::uint8_t>d,std::uint64_t off,std::span<const std::uint8_t>after,std::string reason,const PeInfo&pe,bool cert_overlap){
    RepairChangedRange r;r.file_offset=off;r.before_bytes.assign(d.begin()+static_cast<std::ptrdiff_t>(off),d.begin()+static_cast<std::ptrdiff_t>(off+after.size()));r.after_bytes.assign(after.begin(),after.end());r.before_sha256=sha256_bytes(r.before_bytes);r.after_sha256=sha256_bytes(r.after_bytes);r.reason=std::move(reason);r.executable_bytes=range_executable(pe,off,after.size());r.embedded_signature_overlap=cert_overlap;p.changed_ranges.push_back(std::move(r));
}
void add_field_diff(RepairProposal&p,std::span<const std::uint8_t>d,std::uint64_t off,std::span<const std::uint8_t>target,std::string reason,const PeInfo&pe,bool cert_overlap){
    if(off>d.size()||target.size()>d.size()-off)return;
    std::size_t i=0;
    while(i<target.size()){
        if(d[off+i]==target[i]){++i;continue;}
        const auto begin=i;++i;while(i<target.size()&&d[off+i]!=target[i])++i;
        add_change(p,d,off+begin,target.subspan(begin,i-begin),reason,pe,cert_overlap);
    }
}
std::vector<std::uint8_t> candidate_bytes(const RepairProposal&p,std::span<const std::uint8_t>d,bool&ok){std::vector<std::uint8_t>out(d.begin(),d.end());ok=true;for(const auto&r:p.changed_ranges){if(r.file_offset>out.size()||r.before_bytes.size()>out.size()-r.file_offset||r.before_bytes.size()!=r.after_bytes.size()||!std::equal(r.before_bytes.begin(),r.before_bytes.end(),out.begin()+static_cast<std::ptrdiff_t>(r.file_offset))){ok=false;return{};}std::copy(r.after_bytes.begin(),r.after_bytes.end(),out.begin()+static_cast<std::ptrdiff_t>(r.file_offset));}return out;}
bool existing_symlink(const std::filesystem::path&p){std::error_code ec;auto s=std::filesystem::symlink_status(p,ec);return !ec&&s.type()==std::filesystem::file_type::symlink;}
bool write_atomic(const std::filesystem::path&dest,std::span<const std::uint8_t>d,std::string&err){
    if(existing_symlink(dest)){err="refused symlink output path";return false;}auto part=dest;part += ".part";if(existing_symlink(part)){err="refused symlink temporary output path";return false;}std::error_code ec;if(std::filesystem::exists(part,ec)){if(ec||!std::filesystem::is_regular_file(part,ec)){err="unsafe pre-existing temporary output";return false;}std::filesystem::remove(part,ec);if(ec){err="cannot remove stale temporary output: "+ec.message();return false;}}
    std::ofstream f(part,std::ios::binary|std::ios::trunc);if(!f){err="cannot create temporary repair artifact";return false;}f.write(reinterpret_cast<const char*>(d.data()),static_cast<std::streamsize>(d.size()));f.close();if(!f){std::filesystem::remove(part,ec);err="repair artifact write failed";return false;}
#ifndef _WIN32
    std::filesystem::permissions(part,std::filesystem::perms::owner_read|std::filesystem::perms::owner_write,std::filesystem::perm_options::replace,ec);if(ec){std::filesystem::remove(part,ec);err="cannot make repair artifact non-executable";return false;}
#endif
    if(std::filesystem::exists(dest,ec)){if(ec||!std::filesystem::is_regular_file(dest,ec)){std::filesystem::remove(part,ec);err="unsafe pre-existing repair artifact";return false;}auto h=sha256_file(dest);if(h==sha256_bytes(d)){std::filesystem::remove(part,ec);return true;}std::filesystem::remove(part,ec);err="refused to overwrite non-identical repair artifact";return false;}
#ifndef _WIN32
    // Publish a fully-written inode with no-replace semantics. link(2) is atomic
    // and fails with EEXIST if another writer/symlink appears after our checks.
    if(::link(part.c_str(),dest.c_str())!=0){const auto saved=errno;std::filesystem::remove(part,ec);err=saved==EEXIST?"repair destination appeared concurrently; refused overwrite":"cannot atomically publish repair artifact";return false;}
    std::filesystem::remove(part,ec);if(ec){err="published repair artifact but could not remove temporary hard link: "+ec.message();return false;}
#else
    // MoveFileW has no replace flag here: if a destination appears concurrently,
    // publication fails instead of overwriting it.
    if(!::MoveFileW(part.c_str(),dest.c_str())){const auto winerr=::GetLastError();std::filesystem::remove(part,ec);err=(winerr==ERROR_ALREADY_EXISTS||winerr==ERROR_FILE_EXISTS)?"repair destination appeared concurrently; refused overwrite":"cannot atomically publish repair artifact";return false;}
#endif
    return true;
}
}

std::string_view to_string(RepairClass v){switch(v){case RepairClass::MetadataNormalization:return"R1_METADATA_NORMALIZATION";case RepairClass::LayoutReconstruction:return"R2_LAYOUT_RECONSTRUCTION";case RepairClass::DeterministicBytePatch:return"R3_DETERMINISTIC_BYTE_PATCH";case RepairClass::DecompressUnpackHandoff:return"R4_DECOMPRESS_UNPACK_HANDOFF";case RepairClass::RuntimeDerivedRepair:return"R5_RUNTIME_DERIVED_REPAIR";}return"UNKNOWN";}
std::string_view to_string(RepairState v){switch(v){case RepairState::Proposed:return"PROPOSED";case RepairState::Bounded:return"BOUNDED";case RepairState::Validated:return"VALIDATED";case RepairState::Rejected:return"REJECTED";case RepairState::Ambiguous:return"AMBIGUOUS";}return"UNKNOWN";}
std::string_view to_string(RepairValidationStage v){switch(v){case RepairValidationStage::InternalStructure:return"V1_INTERNAL_STRUCTURE";case RepairValidationStage::FormatPackerInvariant:return"V2_FORMAT_PACKER_INVARIANT";case RepairValidationStage::ExactReferenceChosenInputOracle:return"V3_EXACT_REFERENCE_OR_CHOSEN_INPUT_ORACLE";case RepairValidationStage::NativeBoundary:return"V4_NATIVE_BOUNDARY";case RepairValidationStage::ResultSemanticClosure:return"V5_RESULT_SEMANTIC_CLOSURE";}return"UNKNOWN";}
std::string_view to_string(RepairValidationState v){switch(v){case RepairValidationState::NotRun:return"NOT_RUN";case RepairValidationState::Pass:return"PASS";case RepairValidationState::Fail:return"FAIL";}return"UNKNOWN";}
std::string_view repair_evidence_level_name(ModelEvidenceLevel v){switch(v){case ModelEvidenceLevel::None:return"NONE";case ModelEvidenceLevel::ModelInternalRoundTrip:return"MODEL_INTERNAL_ROUND_TRIP";case ModelEvidenceLevel::OfflineModel:return"OFFLINE_MODEL";case ModelEvidenceLevel::ChosenInputOracle:return"CHOSEN_INPUT_ORACLE";case ModelEvidenceLevel::ExactKnownGoodReference:return"EXACT_KNOWN_GOOD_REFERENCE";case ModelEvidenceLevel::LowDisturbanceNativeBoundary:return"LOW_DISTURBANCE_NATIVE_BOUNDARY";case ModelEvidenceLevel::OriginalNativeResult:return"ORIGINAL_NATIVE_RESULT";}return"UNKNOWN";}

RepairProposal assess_upx_metadata_repair(const std::filesystem::path&input,std::span<const std::uint8_t>d,const PeInfo&pe,const RepairLimits&limits){
    auto p=base(input,d,RepairClass::MetadataNormalization);p.semantic_scope="UPX Win32 PE packer-surface metadata";p.mechanism="strict_upx_pe32_packheader_normalization";
    p.integrity_semantics="DERIVED_ARTIFACT; repaired bytes have a distinct SHA256 and never inherit pristine-signature semantics from the parent";
    if(d.empty()||d.size()>limits.max_input_bytes||d.size()>limits.max_output_bytes||limits.max_candidate_count==0){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"input/output is empty or exceeds bounded repair budget, or candidate budget is zero");reject(p,"INPUT_OUTPUT_OR_CANDIDATE_BUDGET");append_terminal_not_run(p);return p;}
    auto rp=raw_pe(d);std::string gw;if(!rp||!pe.valid||pe.pe64||pe.machine!=kPe32MachineI386||pe.sections.size()<2||!strict_raw_geometry(d,pe,gw)){
        validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,rp?gw:"not a structurally readable PE32 image");reject(p,"V1_PE32_STRUCTURE_NOT_CLOSED");append_terminal_not_run(p);return p;
    }
    if(!rp->file_alignment||!rp->section_alignment||rp->section_alignment<rp->file_alignment){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"invalid PE file/section alignment");reject(p,"V1_ALIGNMENT_INVALID");append_terminal_not_run(p);return p;}
    if(rp->cert_offset||rp->cert_size){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"embedded PE Attribute Certificate Table is declared; header repair would create content distinct from the signed parent and is not auto-materialized");p.integrity_semantics="REPAIR_REFUSED_SIGNED_PARENT; any header/section-name mutation changes signed-content identity";reject(p,"EMBEDDED_AUTHENTICODE_REPAIR_REFUSED");append_terminal_not_run(p);return p;}
    if(pe.overlay_size){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"post-section overlay is present; first product gate refuses to normalize packer metadata across an unmodeled overlay");reject(p,"OVERLAY_REQUIRES_STRONGER_VALIDATION");append_terminal_not_run(p);return p;}
    std::size_t packed_index=pe.sections.size();for(std::size_t i=0;i<pe.sections.size();++i){const auto&s=pe.sections[i];const auto span=std::max(s.vsize,s.raw_size);if(pe.entry_rva>=s.rva&&std::uint64_t(pe.entry_rva)<std::uint64_t(s.rva)+span){packed_index=i;break;}}
    if(packed_index==0||packed_index>=pe.sections.size()){
        validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"declared entry is not in a section immediately following an unpack-to-empty candidate");reject(p,"UPX_ENTRY_SECTION_GEOMETRY_ABSENT");append_terminal_not_run(p);return p;}
    const auto&empty=pe.sections[packed_index-1];const auto&packed=pe.sections[packed_index];
    const bool pair_geom=empty.raw_size==0&&empty.vsize>=0x1000&&(empty.characteristics&kImageScnMemExecute)&&packed.raw_size>=0x400&&packed.raw_offset>=kPackHeaderSize&&(packed.characteristics&kImageScnMemExecute)&&align_up(std::uint64_t(empty.rva)+empty.vsize,rp->section_alignment)==packed.rva;
    const auto ep_delta=pe.entry_rva>=packed.rva?std::uint64_t(pe.entry_rva-packed.rva):std::numeric_limits<std::uint64_t>::max();
    if(!pair_geom||ep_delta>=packed.raw_size){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"entry/empty-section/packed-section relation does not satisfy strict contiguous UPX PE geometry");reject(p,"UPX_STRICT_PAIR_GEOMETRY_ABSENT");append_terminal_not_run(p);return p;}
    auto h=pack_header(d,packed.raw_offset-kPackHeaderSize);if(!h){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"32-byte legacy PackHeader is not file-backed immediately before packed section data");reject(p,"PACKHEADER_RANGE_ABSENT");append_terminal_not_run(p);return p;}
    validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Pass,ModelEvidenceLevel::ModelInternalRoundTrip,"all declared PE raw ranges are observed; entry is file-backed in a packed executable section immediately after a raw-empty executable section; bounded 32-byte PackHeader location is file-backed");
    const auto sec0_off=rp->section_table+(packed_index-1)*40,sec1_off=rp->section_table+packed_index*40;
    if(sec0_off+8>d.size()||sec1_off+8>d.size()){reject(p,"SECTION_NAME_RANGE_NOT_FILE_BACKED");append_terminal_not_run(p);return p;}
    const auto magic_ok=std::equal(h->magic.begin(),h->magic.end(),kUpxMagic.begin());
    const auto sec0_ok=bytes_eq(d,sec0_off,kUpx0)&&std::all_of(d.begin()+static_cast<std::ptrdiff_t>(sec0_off+4),d.begin()+static_cast<std::ptrdiff_t>(sec0_off+8),[](std::uint8_t x){return x==0;});
    const auto sec1_ok=bytes_eq(d,sec1_off,kUpx1)&&std::all_of(d.begin()+static_cast<std::ptrdiff_t>(sec1_off+4),d.begin()+static_cast<std::ptrdiff_t>(sec1_off+8),[](std::uint8_t x){return x==0;});
    std::array<std::uint8_t,31> csum_bytes{};std::copy_n(d.begin()+static_cast<std::ptrdiff_t>(h->offset+4),31,csum_bytes.begin());std::uint32_t sum=0;for(std::size_t i=0;i<27;i++)sum+=csum_bytes[i];const bool hdr_checksum=(sum%251)==h->header_checksum;
    const bool hdr_fields=h->version>9&&h->version<=32&&h->format==kUpxFormatWin32Pe&&recognized_method(h->method)&&h->level>=1&&h->level<=10&&h->u_len>0&&h->u_file_size>0&&h->u_len<=512u*1024u*1024u&&h->u_file_size<=512u*1024u*1024u&&h->c_len>=2&&h->c_len<=packed.raw_size&&std::uint64_t(packed.raw_offset)+h->c_len<=d.size();
    bool payload_checksum=false;if(hdr_fields)payload_checksum=adler32(d.subspan(packed.raw_offset,h->c_len))==h->c_adler;
    if(!hdr_checksum||!hdr_fields||!payload_checksum){std::string detail="legacy UPX PackHeader invariant failed:";if(!hdr_fields)detail+=" field-domain/bounds";if(!hdr_checksum)detail+=" header-checksum";if(!payload_checksum)detail+=" compressed-payload-Adler";validation(p,RepairValidationStage::FormatPackerInvariant,RepairValidationState::Fail,ModelEvidenceLevel::OfflineModel,std::move(detail));reject(p,"V2_PACKHEADER_OR_PAYLOAD_BINDING_FAILED");append_terminal_not_run(p);return p;}
    p.evidence.push_back("legacy 32-byte UPX PackHeader checksum closes independently of its 4-byte magic");p.evidence.push_back("PackHeader compressed-length and Adler32 bind the declared packed payload to the observed packed-section bytes");p.evidence.push_back("entry is file-backed in the packed executable section immediately after a contiguous raw-empty executable section");
    validation(p,RepairValidationStage::FormatPackerInvariant,RepairValidationState::Pass,ModelEvidenceLevel::OfflineModel,"legacy UPX Win32/PE format/method/level domains, PackHeader checksum, packed payload bounds, compressed Adler32, and section/entry geometry all close");
    if(magic_ok&&sec0_ok){
        reject(p,sec1_ok?"NO_REPAIR_NEEDED_STANDARD_UPX":"NO_REPAIR_NEEDED_UPX_HANDOFF_SURFACE");
        p.integrity_semantics="ORIGINAL_UNCHANGED; required UPX handoff surface is already canonical";
        append_terminal_not_run(p);return p;
    }
    const auto prefix_byte=[](std::uint8_t c){return (c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_';};
    const bool sec0_role_shape=!sec0_ok&&prefix_byte(d[sec0_off])&&prefix_byte(d[sec0_off+1])&&prefix_byte(d[sec0_off+2])&&d[sec0_off+3]=='0'&&std::all_of(d.begin()+static_cast<std::ptrdiff_t>(sec0_off+4),d.begin()+static_cast<std::ptrdiff_t>(sec0_off+8),[](std::uint8_t x){return x==0;});
    const bool systematic_pair=sec0_role_shape&&!sec1_ok&&prefix_byte(d[sec1_off])&&prefix_byte(d[sec1_off+1])&&prefix_byte(d[sec1_off+2])&&d[sec1_off+3]=='1'&&std::equal(d.begin()+static_cast<std::ptrdiff_t>(sec0_off),d.begin()+static_cast<std::ptrdiff_t>(sec0_off+3),d.begin()+static_cast<std::ptrdiff_t>(sec1_off))&&std::all_of(d.begin()+static_cast<std::ptrdiff_t>(sec1_off+4),d.begin()+static_cast<std::ptrdiff_t>(sec1_off+8),[](std::uint8_t x){return x==0;});
    const bool sec0_repairable=sec0_role_shape&&(sec1_ok||systematic_pair);
    if(!magic_ok&&(sec0_ok||sec0_repairable)){
        add_field_diff(p,d,h->offset,kUpxMagic,"normalize only bytes that differ from the exact 4-byte UPX PackHeader magic; checksum-covered fields, compressed bytes, and PE geometry already validate",pe,false);
    }
    if(!sec0_ok&&sec0_repairable){
        add_field_diff(p,d,sec0_off,kUpx0,"normalize only bytes that differ in the raw-empty UPX0 role name; the sibling role-name relation and packer header/payload independently validate this role",pe,false);
    }
    if(!magic_ok&&sec0_repairable)p.mechanism="upx_combined_minimal_handoff_normalization";
    else if(!magic_ok&&sec0_ok)p.mechanism="upx_packheader_magic_normalization";
    else if(magic_ok&&sec0_repairable)p.mechanism="upx_empty_section_role_normalization";
    else{ambiguous(p,"packer invariants close but the noncanonical surface is not one bounded supported mutation family (PackHeader magic and/or evidenced raw-empty UPX0 role)");append_terminal_not_run(p);return p;}
    std::uint64_t changed=0;for(const auto&r:p.changed_ranges){changed+=r.after_bytes.size();if(r.executable_bytes||r.embedded_signature_overlap){reject(p,"R1_RANGE_TOUCHES_EXECUTABLE_OR_CERTIFICATE_BYTES");append_terminal_not_run(p);return p;}}
    if(p.changed_ranges.empty()||p.changed_ranges.size()>limits.max_changed_ranges||changed>limits.max_changed_bytes){reject(p,"REPAIR_RANGE_BUDGET_EXCEEDED");append_terminal_not_run(p);return p;}
    p.state=RepairState::Bounded;p.decision_reason="EXACT_NONEXECUTABLE_RANGES_BOUNDED";
    bool ok=false;auto cand=candidate_bytes(p,d,ok);if(!ok){reject(p,"CANDIDATE_CONSTRUCTION_FAILED");append_terminal_not_run(p);return p;}auto cpe=parse_pe(cand);std::string cgw;if(!cpe.valid||!strict_raw_geometry(cand,cpe,cgw)){validation(p,RepairValidationStage::ExactReferenceChosenInputOracle,RepairValidationState::Fail,ModelEvidenceLevel::ExactKnownGoodReference,"canonicalized candidate does not preserve strict PE structure");reject(p,"V3_CANONICAL_CANDIDATE_STRUCTURE_FAILED");append_terminal_not_run(p);return p;}
    // Re-check the exact same PackHeader payload binding after normalization.  The
    // canonical constants are the official UPX format surface; no external tool
    // is invoked and no challenge identity/hash participates in the decision.
    auto ch=pack_header(cand,packed.raw_offset-kPackHeaderSize);const bool canonical=ch&&std::equal(ch->magic.begin(),ch->magic.end(),kUpxMagic.begin())&&bytes_eq(cand,sec0_off,kUpx0)&&adler32(std::span<const std::uint8_t>(cand).subspan(packed.raw_offset,ch->c_len))==ch->c_adler;
    if(!canonical){validation(p,RepairValidationStage::ExactReferenceChosenInputOracle,RepairValidationState::Fail,ModelEvidenceLevel::ExactKnownGoodReference,"candidate failed the minimal canonical official UPX handoff surface (UPX! PackHeader magic + raw-empty UPX0 role) or payload-binding revalidation");reject(p,"V3_CANONICAL_UPX_REFERENCE_FAILED");append_terminal_not_run(p);return p;}
    p.proposed_result_sha256=sha256_bytes(cand);p.state=RepairState::Validated;p.decision_reason="STRICT_UPX_METADATA_NORMALIZATION_VALIDATED";p.static_reanalysis_eligible=true;
    validation(p,RepairValidationStage::ExactReferenceChosenInputOracle,RepairValidationState::Pass,ModelEvidenceLevel::ExactKnownGoodReference,"candidate is canonical at the minimal official UPX handoff surface (UPX! PackHeader magic and raw-empty UPX0 role); all other bytes, including a nonessential renamed packed-section label, remain parent-derived; strict PackHeader/payload/PE invariants revalidate after the exact edit");
    append_terminal_not_run(p);return p;
}

RepairProposal assess_pe_layout_reconstruction(const std::filesystem::path&input,std::span<const std::uint8_t>d,const PeInfo&pe,const RepairLimits&limits){
    auto p=base(input,d,RepairClass::LayoutReconstruction);p.semantic_scope="PE section/raw layout reconstruction";p.mechanism="strict_observed_bytes_geometry_boundary";p.integrity_semantics="NO_REPAIRED_ARTIFACT; missing bytes are never synthesized";
    if(d.empty()||d.size()>limits.max_input_bytes||d.size()>limits.max_output_bytes||limits.max_candidate_count==0||!pe.valid){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,"input/output unavailable/out of budget, candidate budget zero, or not a readable PE");reject(p,"R2_INPUT_NOT_ELIGIBLE");append_terminal_not_run(p);return p;}
    std::vector<std::size_t>missing;std::uint64_t missing_bytes=0;for(std::size_t i=0;i<pe.sections.size();++i){const auto&s=pe.sections[i];if(!s.raw_size)continue;auto end=std::uint64_t(s.raw_offset)+s.raw_size;if(end>d.size()){missing.push_back(i);missing_bytes=std::max(missing_bytes,end-d.size());}}
    if(missing.empty()){validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Pass,ModelEvidenceLevel::ModelInternalRoundTrip,"all declared section raw ranges are already observed in the file");reject(p,"NO_PROVEN_LAYOUT_RECONSTRUCTION_NEEDED");append_terminal_not_run(p);return p;}
    std::ostringstream e;e<<missing.size()<<" declared PE section raw range(s) extend beyond observed EOF; at least "<<missing_bytes<<" byte(s) are physically unobserved";p.evidence.push_back(e.str());validation(p,RepairValidationStage::InternalStructure,RepairValidationState::Fail,ModelEvidenceLevel::ModelInternalRoundTrip,e.str());
    p.ambiguity.push_back("shrinking metadata to observed EOF and restoring the originally declared payload are different semantics that both fit the surviving header evidence");p.ambiguity.push_back("R2 may repair metadata that describes existing bytes, but cannot create unobserved code/data/resource bytes without an independent oracle");ambiguous(p,"PHYSICALLY_MISSING_SECTION_BYTES_NO_UNIQUE_RECONSTRUCTION");append_terminal_not_run(p);return p;
}

std::filesystem::path default_repair_root(const std::filesystem::path&input){auto p=input;p += ".auto-refirst";return p/"repair";}

bool materialize_validated_repair(RepairProposal&p,std::span<const std::uint8_t>original,const std::filesystem::path&requested_root){
    constexpr std::uint64_t kHardMaxArtifactBytes=64ull*1024ull*1024ull;
    constexpr std::size_t kHardMaxRanges=8;
    constexpr std::uint64_t kHardMaxChangedBytes=64;
    p.materialized=false;p.original_unchanged=false;p.result_path.clear();p.provenance_path.clear();p.result_sha256.clear();p.materialization_error.clear();
    if(p.state!=RepairState::Validated||p.proposed_result_sha256.empty()||!p.static_reanalysis_eligible){p.materialization_error="proposal is not strict VALIDATED/static-reanalysis eligible";return false;}
    auto passed=[&](RepairValidationStage stage){return std::any_of(p.validations.begin(),p.validations.end(),[&](const RepairValidation&v){return v.stage==stage&&v.state==RepairValidationState::Pass;});};
    if(!passed(RepairValidationStage::InternalStructure)||!passed(RepairValidationStage::FormatPackerInvariant)||!passed(RepairValidationStage::ExactReferenceChosenInputOracle)){p.materialization_error="validated proposal lacks required V1/V2/V3 PASS evidence";return false;}
    if(original.size()>kHardMaxArtifactBytes||p.input_size>kHardMaxArtifactBytes){p.materialization_error="parent/output exceeds hard materialization byte bound";return false;}
    if(sha256_bytes(original)!=p.input_sha256||original.size()!=p.input_size){p.materialization_error="supplied parent bytes do not match proposal identity";return false;}
    if(p.changed_ranges.empty()||p.changed_ranges.size()>kHardMaxRanges){p.materialization_error="changed-range contract is empty or exceeds hard materialization bound";return false;}
    std::uint64_t changed_bytes=0;for(const auto&r:p.changed_ranges){if(r.before_bytes.size()!=r.after_bytes.size()||r.before_bytes.size()>kHardMaxChangedBytes-changed_bytes){p.materialization_error="changed bytes exceed hard materialization bound";return false;}changed_bytes+=r.before_bytes.size();}
    auto live_before=sha256_file(p.input_path);if(live_before.empty()||live_before!=p.input_sha256){p.materialization_error="input path no longer matches proposal parent SHA256";return false;}
    bool ok=false;auto cand=candidate_bytes(p,original,ok);if(!ok||sha256_bytes(cand)!=p.proposed_result_sha256){p.materialization_error="candidate bytes no longer close against proposal ranges/result SHA256";return false;}
    auto root=requested_root.empty()?default_repair_root(p.input_path):requested_root;if(root==p.input_path||root.parent_path()==p.input_path){p.materialization_error="refused repair root aliasing original input";return false;}std::error_code ec;
    if(existing_symlink(root)){p.materialization_error="refused symlink repair root";return false;}std::filesystem::create_directories(root,ec);if(ec){p.materialization_error="cannot create repair root: "+ec.message();return false;}
    auto dir=root/p.proposed_result_sha256;if(existing_symlink(dir)){p.materialization_error="refused symlink repair result directory";return false;}std::filesystem::create_directories(dir,ec);if(ec){p.materialization_error="cannot create repair result directory: "+ec.message();return false;}
    auto base_name=p.input_path.filename().string();if(base_name.empty())base_name="artifact.bin";auto out=dir/(base_name+".repaired");const bool output_preexisting=std::filesystem::is_regular_file(out,ec)&&!ec;ec.clear();std::string err;if(!write_atomic(out,cand,err)){p.materialization_error=err;return false;}if(sha256_file(out)!=p.proposed_result_sha256){if(!output_preexisting)std::filesystem::remove(out,ec);p.materialization_error="persisted repaired artifact SHA256 mismatch";return false;}
    p.result_path=out;p.result_sha256=p.proposed_result_sha256;p.provenance_path=dir/"provenance.json";
    auto live_after=sha256_file(p.input_path);if(live_after!=p.input_sha256){if(!output_preexisting)std::filesystem::remove(out,ec);p.result_path.clear();p.result_sha256.clear();p.provenance_path.clear();p.materialization_error="original input identity changed concurrently; derived artifact not admitted";return false;}
    p.original_unchanged=true;p.materialized=true;p.static_reanalysis_eligible=true;p.automatic_runtime_execution_eligible=false;
    auto prov=render_repair_json(p);std::vector<std::uint8_t>pb(prov.begin(),prov.end());if(!write_atomic(p.provenance_path,pb,err)){if(!output_preexisting)std::filesystem::remove(out,ec);p.materialized=false;p.original_unchanged=false;p.static_reanalysis_eligible=false;p.result_path.clear();p.result_sha256.clear();p.provenance_path.clear();p.materialization_error="provenance persistence failed: "+err;return false;}return true;
}

std::string render_repair_json(const RepairProposal&p){
    std::ostringstream o;o<<"{\n";
    auto s=[&](std::string_view k,std::string_view v,bool comma=true){o<<"  \""<<k<<"\": \""<<json_escape(v)<<"\""<<(comma?",":"")<<"\n";};
    o<<"  \"provenance_version\": 1,\n";s("transformation_relation","REPAIRED_FROM");s("input",p.input_path.string());s("parent_sha256",p.input_sha256);o<<"  \"parent_size\": "<<p.input_size<<",\n";s("repair_class",to_string(p.repair_class));s("state",to_string(p.state));s("semantic_scope",p.semantic_scope);s("mechanism",p.mechanism);s("decision_reason",p.decision_reason);s("evidence_ceiling",repair_evidence_level_name(p.evidence_ceiling));s("integrity_semantics",p.integrity_semantics);s("proposed_result_sha256",p.proposed_result_sha256);s("result_path",p.result_path.string());s("result_sha256",p.result_sha256);s("provenance_path",p.provenance_path.string());
    o<<"  \"materialized\": "<<(p.materialized?"true":"false")<<",\n  \"original_unchanged\": "<<(p.original_unchanged?"true":"false")<<",\n  \"static_reanalysis_eligible\": "<<(p.static_reanalysis_eligible?"true":"false")<<",\n  \"automatic_runtime_execution_eligible\": "<<(p.automatic_runtime_execution_eligible?"true":"false")<<",\n";s("materialization_error",p.materialization_error);
    o<<"  \"changed_range_count\": "<<p.changed_ranges.size()<<",\n  \"changed_ranges\": [";for(std::size_t i=0;i<p.changed_ranges.size();++i){if(i)o<<',';const auto&r=p.changed_ranges[i];o<<"{\"file_offset\":"<<r.file_offset<<",\"size\":"<<r.before_bytes.size()<<",\"before_bytes\":\""<<hex_bytes(r.before_bytes)<<"\",\"after_bytes\":\""<<hex_bytes(r.after_bytes)<<"\",\"before_sha256\":\""<<r.before_sha256<<"\",\"after_sha256\":\""<<r.after_sha256<<"\",\"reason\":\""<<json_escape(r.reason)<<"\",\"executable_bytes\":"<<(r.executable_bytes?"true":"false")<<",\"embedded_signature_overlap\":"<<(r.embedded_signature_overlap?"true":"false")<<'}';}o<<"],\n";
    o<<"  \"validations\": [";for(std::size_t i=0;i<p.validations.size();++i){if(i)o<<',';const auto&v=p.validations[i];o<<"{\"stage\":\""<<to_string(v.stage)<<"\",\"state\":\""<<to_string(v.state)<<"\",\"evidence_level\":\""<<repair_evidence_level_name(v.evidence_level)<<"\",\"detail\":\""<<json_escape(v.detail)<<"\"}";}o<<"],\n";
    o<<"  \"evidence\": [";for(std::size_t i=0;i<p.evidence.size();++i){if(i)o<<',';o<<'"'<<json_escape(p.evidence[i])<<'"';}o<<"],\n  \"ambiguity\": [";for(std::size_t i=0;i<p.ambiguity.size();++i){if(i)o<<',';o<<'"'<<json_escape(p.ambiguity[i])<<'"';}o<<"]\n}\n";return o.str();
}

}
