#pragma once
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace prts {
enum class CoordinateSpace : std::uint8_t {
    UNKNOWN=0,
    FILE_OFFSET,
    RVA,
    VA,
    SERIALIZED_OFFSET,
    MEMORY_REGION_RELATIVE,
    TOKEN,
    INDEX,
};
inline const char* coordinate_space_name(CoordinateSpace s) {
    switch(s){
        case CoordinateSpace::FILE_OFFSET:return "FILE_OFFSET";
        case CoordinateSpace::RVA:return "RVA";
        case CoordinateSpace::VA:return "VA";
        case CoordinateSpace::SERIALIZED_OFFSET:return "SERIALIZED_OFFSET";
        case CoordinateSpace::MEMORY_REGION_RELATIVE:return "MEMORY_REGION_RELATIVE";
        case CoordinateSpace::TOKEN:return "TOKEN";
        case CoordinateSpace::INDEX:return "INDEX";
        case CoordinateSpace::UNKNOWN:return "UNKNOWN";
    }
    return "UNKNOWN";
}
enum class CoordinateBasis : std::uint8_t {
    UNKNOWN=0,
    CURRENT_INPUT_FILE,
    CURRENT_INPUT_IMAGE,
    ARTIFACT_FILE,
    ARTIFACT_IMAGE,
    PROCESS_IMAGE,
    MEMORY_REGION,
};
inline const char* coordinate_basis_name(CoordinateBasis b) {
    switch(b){
        case CoordinateBasis::CURRENT_INPUT_FILE:return "CURRENT_INPUT_FILE";
        case CoordinateBasis::CURRENT_INPUT_IMAGE:return "CURRENT_INPUT_IMAGE";
        case CoordinateBasis::ARTIFACT_FILE:return "ARTIFACT_FILE";
        case CoordinateBasis::ARTIFACT_IMAGE:return "ARTIFACT_IMAGE";
        case CoordinateBasis::PROCESS_IMAGE:return "PROCESS_IMAGE";
        case CoordinateBasis::MEMORY_REGION:return "MEMORY_REGION";
        case CoordinateBasis::UNKNOWN:return "UNKNOWN";
    }
    return "UNKNOWN";
}
// The first three members intentionally retain the historical layout and a matching
// three-argument constructor so existing {offset,size,label} initializers keep compiling. New producers must set
// coordinate_space/basis explicitly when the coordinate is actually known; UNKNOWN
// is safer than inferring a space from labels or surrounding wording.
struct RangeRef {
    std::uint64_t offset=0;
    std::uint64_t size=0;
    std::string label;
    CoordinateSpace coordinate_space=CoordinateSpace::UNKNOWN;
    CoordinateBasis basis=CoordinateBasis::UNKNOWN;
    std::string artifact_identity;
    std::optional<std::uint64_t> process_uid;
    std::optional<std::uint64_t> image_base;
    RangeRef()=default;
    RangeRef(std::uint64_t value,std::uint64_t byte_size,std::string range_label)
        : offset(value),size(byte_size),label(std::move(range_label)) {}
};
inline RangeRef typed_range(std::uint64_t value,std::uint64_t size,std::string label,
                            CoordinateSpace space,CoordinateBasis basis=CoordinateBasis::UNKNOWN,std::string artifact_identity={},
                            std::optional<std::uint64_t> process_uid={},std::optional<std::uint64_t> image_base={}) {
    RangeRef r(value,size,std::move(label));r.coordinate_space=space;r.basis=basis;
    r.artifact_identity=std::move(artifact_identity);r.process_uid=process_uid;r.image_base=image_base;return r;
}
inline RangeRef file_offset_range(std::uint64_t value,std::uint64_t size,std::string label,CoordinateBasis basis=CoordinateBasis::CURRENT_INPUT_FILE,std::string artifact_identity={},std::optional<std::uint64_t> process_uid={}) {
    return typed_range(value,size,std::move(label),CoordinateSpace::FILE_OFFSET,basis,std::move(artifact_identity),process_uid);
}
inline RangeRef rva_range(std::uint64_t value,std::uint64_t size,std::string label,CoordinateBasis basis=CoordinateBasis::CURRENT_INPUT_IMAGE,std::string artifact_identity={},std::optional<std::uint64_t> process_uid={},std::optional<std::uint64_t> image_base={}) {
    return typed_range(value,size,std::move(label),CoordinateSpace::RVA,basis,std::move(artifact_identity),process_uid,image_base);
}
inline RangeRef va_range(std::uint64_t value,std::uint64_t size,std::string label,CoordinateBasis basis=CoordinateBasis::PROCESS_IMAGE,std::string artifact_identity={},std::optional<std::uint64_t> process_uid={},std::optional<std::uint64_t> image_base={}) {
    return typed_range(value,size,std::move(label),CoordinateSpace::VA,basis,std::move(artifact_identity),process_uid,image_base);
}
inline RangeRef memory_relative_range(std::uint64_t value,std::uint64_t size,std::string label,CoordinateBasis basis=CoordinateBasis::MEMORY_REGION,std::string artifact_identity={},std::optional<std::uint64_t> process_uid={}) {
    return typed_range(value,size,std::move(label),CoordinateSpace::MEMORY_REGION_RELATIVE,basis,std::move(artifact_identity),process_uid);
}

struct Finding {
    std::string kind;
    std::string family;
    std::string variant;
    std::string state="SUSPECTED"; // SUSPECTED, LIKELY, CONFIRMED, FAILED, UNPACKED_VALIDATED
    std::optional<double> confidence;
    std::vector<std::string> evidence;
    std::vector<std::string> negative_evidence;
    std::vector<RangeRef> ranges;
    std::map<std::string,std::string> fields;
    std::vector<std::string> suggested_actions;
};
struct EmbeddedObject {
    std::string kind;
    std::uint64_t offset=0;
    std::uint64_t size=0;
    bool validated=false;
    std::string state="SUSPECTED"; // SUSPECTED, LIKELY, CONFIRMED, FAILED, UNPACKED_VALIDATED
    std::optional<double> confidence;
    std::string detail;
};
struct EntropyRange { std::uint64_t offset=0,size=0; double entropy=0.0; };
struct StringHit { std::uint64_t offset=0; std::string encoding; std::string value; };
struct EcosystemHints {
    bool pyinstaller=false,nuitka=false,godot=false,unity=false,rust=false,golang=false,renpy=false,autoit=false,crypto=false;
};
struct StaticScanReport {
    std::uint64_t ascii_strings=0, utf16_strings=0;
    EcosystemHints hints;
    std::vector<StringHit> interesting_strings;
    std::vector<EntropyRange> high_entropy;
    std::vector<EmbeddedObject> embedded;
    std::vector<std::uint64_t> crypto_delta_offsets;
    std::vector<std::uint64_t> crypto_rc4_offsets;
    std::vector<std::uint64_t> crypto_aesni_schedule_offsets;
    std::vector<std::uint64_t> crypto_aesni_round_offsets;
};
}
