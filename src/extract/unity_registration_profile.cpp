#include "unity_registration_profile.hpp"
#include <string>
#include <algorithm>
#include <limits>
#include <optional>
#include <vector>

namespace prts {
namespace {
int unity_channel_rank(char channel) {
    switch(channel) {
        case 'a': return 0; case 'b': return 1; case 'c': return 2;
        case 'f': return 3; case 'p': return 4; case 'x': return 5;
        default: return -1;
    }
}
bool unity_version_at_least(const UnityEngineVersionValue&v,std::uint32_t major,std::uint32_t minor,
                            std::uint32_t patch,char channel,std::uint32_t channel_number) {
    const auto rank=unity_channel_rank(v.channel),target_rank=unity_channel_rank(channel);
    if(rank<0||target_rank<0)return false;
    if(v.major!=major)return v.major>major;
    if(v.minor!=minor)return v.minor>minor;
    if(v.patch!=patch)return v.patch>patch;
    if(rank!=target_rank)return rank>target_rank;
    return v.channel_number>=channel_number;
}
const char* engine_hint_name(UnityMetadataRegistrationEngineHint hint) {
    switch(hint) {
        case UnityMetadataRegistrationEngineHint::Traditional106:return "106";
        case UnityMetadataRegistrationEngineHint::Extended1061:return "106.1";
        case UnityMetadataRegistrationEngineHint::None:return "";
    }
    return "";
}
}

UnityMetadataRegistrationEngineHint unity_metadata_registration_engine_hint(
    int declared_version,const UnityEngineVersionValue&engine_version) {
    if(declared_version==106)
        return unity_version_at_least(engine_version,6000,6,0,'a',6)
            ?UnityMetadataRegistrationEngineHint::Extended1061
            :UnityMetadataRegistrationEngineHint::Traditional106;
    if(declared_version==107)
        return engine_version.major>6000||(engine_version.major==6000&&engine_version.minor>=6)
            ?UnityMetadataRegistrationEngineHint::Extended1061
            :UnityMetadataRegistrationEngineHint::Traditional106;
    return UnityMetadataRegistrationEngineHint::None;
}

UnityMetadataRegistrationProfileDecision decide_unity_metadata_registration_profile(
    int declared_version, UnityMetadataRegistrationTailEvidence tail_evidence,
    UnityMetadataRegistrationEngineHint engine_hint) {
    UnityMetadataRegistrationProfileDecision out;out.engine_hint=engine_hint_name(engine_hint);
    if (declared_version < 23 || declared_version > 108) {
        out.detail = "declared metadata version is outside the supported profile range";
        return out;
    }
    if (declared_version == 108) {
        out.state = "RESOLVED";out.profile = "v108 compact-7pair";out.normalized_variant = "108";out.role_count = 7;
        out.detail = "v108 removes genericMethodTable/methodSpecs from MetadataRegistration and retains always-init usages";
        out.include_always_init = true;return out;
    }
    if (declared_version != 106 && declared_version != 107) {
        out.state = "RESOLVED";out.profile = "traditional-8pair";out.normalized_variant = std::to_string(declared_version);out.role_count = 8;
        out.detail = "declared metadata version has a single validated pre-v108 MetadataRegistration profile";return out;
    }

    out.role_count = 8; // Safe common prefix shared by 106.0, 106.1, and both declared-v107 branches.
    if(engine_hint==UnityMetadataRegistrationEngineHint::Traditional106) {
        if(tail_evidence==UnityMetadataRegistrationTailEvidence::StrongExtended) {
            out.state="CONFLICT";out.profile="common-8pair; structure-engine-conflict";out.normalized_variant="106|106.1";
            out.detail="engine version maps to 106.0, but the ninth pair independently validates as a 106.1 always-init extension";return out;
        }
        out.state="RESOLVED";out.profile="traditional-8pair";out.normalized_variant="106";
        out.detail=tail_evidence==UnityMetadataRegistrationTailEvidence::NotFileBacked
            ?"engine version and ninth-pair file boundary independently support the traditional 106.0 layout"
            :"engine version maps this declared metadata version to 106.0; bytes after the validated common 8-pair prefix are not part of MetadataRegistration";
        return out;
    }
    if(engine_hint==UnityMetadataRegistrationEngineHint::Extended1061) {
        if(tail_evidence==UnityMetadataRegistrationTailEvidence::StrongExtended) {
            out.state="RESOLVED";out.profile="extended-9pair";out.normalized_variant="106.1";out.role_count=9;out.include_always_init=true;
            out.detail="engine version and ninth always-init pair independently support the 106.1 layout";return out;
        }
        if(tail_evidence==UnityMetadataRegistrationTailEvidence::ZeroPair) {
            out.state="RESOLVED";out.profile="extended-9pair; zero always-init extension";out.normalized_variant="106.1";out.role_count=9;out.include_always_init=true;
            out.detail="engine version maps to 106.1 and disambiguates the structurally valid zero/zero ninth extension";return out;
        }
        out.state="INVALID";out.profile="common-8pair; required 106.1 extension invalid";out.normalized_variant="106|106.1";
        out.detail=tail_evidence==UnityMetadataRegistrationTailEvidence::NotFileBacked
            ?"engine version requires a 106.1 ninth pair, but the pair cannot fit in the file-backed MetadataRegistration span"
            :"engine version requires a 106.1 ninth pair, but the extension is missing or fails pointer/slot/encoding validation";
        return out;
    }

    switch (tail_evidence) {
        case UnityMetadataRegistrationTailEvidence::NotFileBacked:
            out.state = "RESOLVED";out.profile = "traditional-8pair";out.normalized_variant = "106";
            out.detail = "a ninth count/pointer pair cannot fit in the file-backed MetadataRegistration span";return out;
        case UnityMetadataRegistrationTailEvidence::StrongExtended:
            out.state = "RESOLVED";out.profile = "extended-9pair";out.normalized_variant = "106.1";out.role_count = 9;out.include_always_init = true;
            out.detail = "ninth always-init metadata-usage pair has a fully validated pointer/slot/encoding contract";return out;
        case UnityMetadataRegistrationTailEvidence::ZeroPair:
            out.state = "AMBIGUOUS";out.profile = "common-8pair; tail-zero-ambiguous";out.normalized_variant = "106|106.1";
            out.detail = "zero ninth pair is compatible with both a zero-valued 106.1 extension and unrelated zero bytes after a 106.0 struct";return out;
        case UnityMetadataRegistrationTailEvidence::Unresolved:
        case UnityMetadataRegistrationTailEvidence::NotApplicable:
            out.state = "AMBIGUOUS";out.profile = "common-8pair; tail-unresolved";out.normalized_variant = "106|106.1";
            out.detail = "ninth pair is file-backed but lacks enough positive evidence to distinguish 106.0 from 106.1";return out;
    }
    return out;
}

std::string unity_code_registration_layout_profile(int declared_version) {
    if (declared_version == 106 || declared_version == 107)
        return "106-compatible";
    return std::to_string(declared_version);
}

bool unity_validate_1061_always_init_encoded_slots(
    std::span<const std::uint32_t> encoded_slots, std::uint64_t type_count,
    std::uint64_t method_count, std::uint64_t string_count, std::uint64_t method_spec_count) {
    if (encoded_slots.empty() || encoded_slots.size() > 1000000)
        return false;
    for (const auto encoded : encoded_slots) {
        const auto raw = (encoded >> 29) & 7u;
        const auto kind = raw > 1 ? raw + 1 : raw; // 106.1 removes the old enum value 2.
        const auto source = (encoded & 0x1fffffffu) >> 1;
        if (kind < 1 || kind > 7)
            return false;
        if ((kind == 1 || kind == 2) && source >= type_count)
            return false;
        if (kind == 3 && source >= method_count)
            return false;
        if (kind == 5 && source >= string_count)
            return false;
        if (kind == 6 && source >= method_spec_count)
            return false;
        if ((kind == 4 || kind == 7) && source > 2000000)
            return false;
    }
    return true;
}
}

namespace {
std::uint64_t read_qword(std::span<const std::uint8_t> d, std::size_t off) {
    if (off > d.size() || 8 > d.size() - off) return 0;
    std::uint64_t value=0;
    for (int i=7;i>=0;--i) value=(value<<8)|d[off+static_cast<std::size_t>(i)];
    return value;
}
std::optional<std::size_t> mapped_offset(const prts::PeInfo& pe,std::uint64_t va,std::size_t n) {
    if (!pe.valid || va<pe.image_base) return {};
    const auto r=va-pe.image_base;
    if (r<pe.headers_size) {
        if (r<n) return static_cast<std::size_t>(r);
        return {};
    }
    for (const auto& sec:pe.sections) {
        const auto span=std::max(sec.vsize,sec.raw_size);
        if (r<sec.rva || r>=std::uint64_t(sec.rva)+span) continue;
        const auto delta=r-sec.rva;
        if (delta>=sec.raw_size) return {};
        const auto off=std::uint64_t(sec.raw_offset)+delta;
        if (off<n) return static_cast<std::size_t>(off);
        return {};
    }
    return {};
}
bool mapped_span_local(std::span<const std::uint8_t>d,const prts::PeInfo&pe,std::uint64_t va,std::uint64_t size) {
    if (!pe.valid || va<pe.image_base) return false;
    const auto r=va-pe.image_base;
    if (r<pe.headers_size) return r<=d.size() && size<=d.size()-r && size<=pe.headers_size-r;
    for (const auto& sec:pe.sections) {
        if (r<sec.rva) continue;
        const auto delta=r-sec.rva;
        if (delta>=sec.raw_size) continue;
        if (size>sec.raw_size-delta) return false;
        const auto off=std::uint64_t(sec.raw_offset)+delta;
        return off<=d.size() && size<=d.size()-off;
    }
    return false;
}
const prts::PeSection* section_for_va(const prts::PeInfo& pe,std::uint64_t va) {
    if (!pe.valid || va<pe.image_base) return nullptr;
    const auto r=va-pe.image_base;
    for (const auto& sec:pe.sections) {
        const auto span=std::max(sec.vsize,sec.raw_size);
        if (r>=sec.rva && r<std::uint64_t(sec.rva)+span) return &sec;
    }
    return nullptr;
}
}

namespace prts {
UnityMetadataRegistrationTailProbe probe_unity_metadata_registration_tail(
    std::span<const std::uint8_t> image, const PeInfo& pe, std::uint64_t tail_va,
    std::uint64_t type_count, std::uint64_t method_count,
    std::uint64_t string_count, std::uint64_t method_spec_count) {
    UnityMetadataRegistrationTailProbe out;
    if (!mapped_span_local(image,pe,tail_va,16)) {
        out.evidence=UnityMetadataRegistrationTailEvidence::NotFileBacked;
        out.detail="ninth MetadataRegistration pair is not fully file-backed";
        return out;
    }
    auto tail=mapped_offset(pe,tail_va,image.size());
    if (!tail) {
        out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
        out.detail="ninth MetadataRegistration pair has no raw mapping";
        return out;
    }
    out.count=read_qword(image,*tail);
    out.pointer_va=read_qword(image,*tail+8);
    if (!out.count && !out.pointer_va) {
        out.evidence=UnityMetadataRegistrationTailEvidence::ZeroPair;
        out.detail="ninth MetadataRegistration pair is zero/zero";
        return out;
    }
    if (!out.count || out.count>1000000 || !out.pointer_va || out.count>std::numeric_limits<std::uint64_t>::max()/8 ||
        !mapped_span_local(image,pe,out.pointer_va,out.count*8)) {
        out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
        out.detail="ninth pair count/pointer geometry is not a bounded file-backed pointer array";
        return out;
    }
    auto table=mapped_offset(pe,out.pointer_va,image.size());
    if (!table) {
        out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
        out.detail="ninth pair pointer array has no raw mapping";
        return out;
    }
    std::vector<std::uint32_t> encoded;
    encoded.reserve(static_cast<std::size_t>(out.count));
    for (std::uint64_t i=0;i<out.count;++i) {
        const auto slot_va=read_qword(image,*table+static_cast<std::size_t>(i*8));
        const auto* sec=section_for_va(pe,slot_va);
        if (!slot_va || (slot_va&7u) || !sec || (sec->characteristics&0x80000000u)==0 ||
            !mapped_span_local(image,pe,slot_va,8)) {
            out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
            out.detail="always-init storage slot is null, unaligned, non-writable, or not file-backed";
            return out;
        }
        auto slot=mapped_offset(pe,slot_va,image.size());
        if (!slot) {
            out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
            out.detail="always-init storage slot has no raw mapping";
            return out;
        }
        const auto value=read_qword(image,*slot);
        if (value>>32) {
            out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
            out.detail="always-init storage slot has nonzero high32 before initialization";
            return out;
        }
        encoded.push_back(static_cast<std::uint32_t>(value));
    }
    if (!unity_validate_1061_always_init_encoded_slots(encoded,type_count,method_count,string_count,method_spec_count)) {
        out.evidence=UnityMetadataRegistrationTailEvidence::Unresolved;
        out.detail="always-init storage encodings fail 106.1 usage-kind/source bounds";
        return out;
    }
    out.evidence=UnityMetadataRegistrationTailEvidence::StrongExtended;
    out.detail="ninth pair has a bounded pointer array to writable file-backed slots with valid 106.1 encodings";
    return out;
}
}
