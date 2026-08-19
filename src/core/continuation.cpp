#include "prts/continuation.hpp"

#include <fstream>
#include <sstream>

namespace prts {
namespace {
std::string csvq(const std::string& s) {
    std::string out(1, '"');
    for (const char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}
}

ContinuationExtractResult extract_continuations(
    const ContinuationInfo& info,
    const std::filesystem::path& csv) {
    ContinuationExtractResult out;
    if (info.entries.empty()) {
        out.error = "continuation plane is not present";
        return out;
    }
    std::ofstream f(csv, std::ios::binary | std::ios::trunc);
    if (!f) {
        out.error = "cannot create continuation CSV";
        return out;
    }
    f << "index,format,architecture,coroutine_identity,compiler_profile,evidence_state,priority,"
         "creator_va,creator_file_offset,frame_allocation_site_va,frame_allocation_site_file_offset,"
         "frame_size_exact,frame_size,frame_storage,frame_control_pointers_writable,resume_target_va,"
         "resume_target_file_offset,destroy_target_va,destroy_target_file_offset,state_frame_offset,"
         "state_width,final_clears_resume_pointer,destroy_consumes_common_frame,promise_relation,"
         "coordinate_provenance,suspend_site_count,detail\n";
    for (const auto& x : info.entries) {
        f << x.index << ',' << csvq(x.format) << ',' << csvq(x.architecture) << ','
          << csvq(x.coroutine_identity) << ',' << csvq(x.compiler_profile) << ','
          << csvq(x.evidence_state) << ',' << csvq(x.priority) << ','
          << "0x" << std::hex << x.creator_va << ',' << "0x" << x.creator_file_offset << ','
          << "0x" << x.frame_allocation_site_va << ',' << "0x" << x.frame_allocation_site_file_offset << std::dec << ','
          << (x.frame_size_exact ? 1 : 0) << ',' << x.frame_size << ',' << csvq(x.frame_storage) << ','
          << (x.frame_control_pointers_writable ? 1 : 0) << ','
          << "0x" << std::hex << x.resume_target_va << ',' << "0x" << x.resume_target_file_offset << ','
          << "0x" << x.destroy_target_va << ',' << "0x" << x.destroy_target_file_offset << std::dec << ','
          << x.state_frame_offset << ',' << x.state_width << ','
          << (x.final_clears_resume_pointer ? 1 : 0) << ','
          << (x.destroy_consumes_common_frame ? 1 : 0) << ',' << csvq(x.promise_relation) << ','
          << csvq(x.coordinate_provenance) << ',' << x.suspend_sites.size() << ',' << csvq(x.detail) << '\n';
    }
    f.close();
    if (!f) {
        out.error = "write continuation CSV failed";
        std::error_code ec;
        std::filesystem::remove(csv, ec);
        return out;
    }
    out.success = true;
    out.csv = csv;
    out.row_count = info.entries.size();
    return out;
}
} // namespace prts
