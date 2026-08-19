#include "prts/control_record.hpp"

#include <fstream>
#include <iomanip>
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

std::string field_list(const std::vector<ControlRecordField>& fields) {
    std::ostringstream out;
    bool first = true;
    for (const auto& f : fields) {
        if (!first) out << ';';
        first = false;
        out << f.role << "@0x" << std::hex << f.offset << std::dec << ':' << f.width << ':' << f.evidence_state;
    }
    return out.str();
}

} // namespace

ControlRecordExtractResult extract_control_records(
    const ControlRecordInfo& info,
    const std::filesystem::path& csv) {
    ControlRecordExtractResult out;
    if (info.tables.empty()) {
        out.error = "control-record plane is not present";
        return out;
    }
    std::ofstream f(csv, std::ios::binary | std::ios::trunc);
    if (!f) {
        out.error = "cannot create control-record CSV";
        return out;
    }
    f << "index,format,architecture,evidence_state,priority,table_va,table_file_offset,record_stride,record_count,table_size,"
         "stride_evidence_state,count_evidence_state,consumer_va,consumer_file_offset,consumer_profile,indirect_dispatch_count,mutable,mutability_basis,fields,coordinate_provenance,detail\n";
    for (const auto& x : info.tables) {
        f << x.index << ',' << csvq(x.format) << ',' << csvq(x.architecture) << ',' << csvq(x.evidence_state) << ',' << csvq(x.priority) << ','
          << "0x" << std::hex << x.table_va << ',' << "0x" << x.table_file_offset << std::dec << ','
          << x.record_stride << ',' << x.record_count << ',' << x.table_size << ','
          << csvq(x.stride_evidence_state) << ',' << csvq(x.count_evidence_state) << ','
          << "0x" << std::hex << x.consumer_va << ',' << "0x" << x.consumer_file_offset << std::dec << ','
          << csvq(x.consumer_profile) << ',' << x.indirect_dispatch_count << ',' << (x.mutable_storage ? 1 : 0) << ','
          << csvq(x.mutability_basis) << ',' << csvq(field_list(x.fields)) << ',' << csvq(x.coordinate_provenance) << ',' << csvq(x.detail) << '\n';
    }
    f.close();
    if (!f) {
        out.error = "write control-record CSV failed";
        std::error_code ec;
        std::filesystem::remove(csv, ec);
        return out;
    }
    out.success = true;
    out.csv = csv;
    out.row_count = info.tables.size();
    return out;
}

} // namespace prts
