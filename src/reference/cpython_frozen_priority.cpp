#include "prts/cpython_frozen_priority.hpp"
#include <algorithm>
#include <tuple>
namespace prts {
CPythonFrozenPriorityInfo build_cpython_frozen_priority(const CPythonFrozenInfo&frozen,
                                                        bool pyinstaller_user_payload_present,
                                                        std::size_t max_candidates){
    CPythonFrozenPriorityInfo out;std::vector<CPythonFrozenPriorityCandidate>all;
    for(const auto&t:frozen.tables)for(const auto&m:t.modules){
        if(m.state!="RAW_MARSHAL"||m.reference_state!="REFERENCE_DIFF"||m.reference_match_mode!="DIFFERENT")continue;
        if(!m.raw_code_size||!m.raw_code_rva||!m.raw_code_file_offset)continue;
        all.push_back({t.export_name,m.name,m.reference_version,m.raw_code_file_offset,m.raw_code_rva,m.raw_code_size,
                       m.raw_sha256,m.reference_raw_sha256,m.semantic_sha256,m.reference_semantic_sha256});
    }
    std::sort(all.begin(),all.end(),[](const auto&a,const auto&b){
        return std::tie(a.file_offset,a.table,a.module,a.rva)<std::tie(b.file_offset,b.table,b.module,b.rva);
    });
    out.mismatch_count=static_cast<std::uint32_t>(std::min<std::size_t>(all.size(),0xffffffffu));
    const auto keep=std::min(max_candidates,all.size());out.candidates.assign(all.begin(),all.begin()+keep);out.candidates_truncated=keep<all.size();
    out.preferred_target=!all.empty()?"FROZEN_REFERENCE_DIFF":(pyinstaller_user_payload_present?"PYINSTALLER_USER_PAYLOAD":"NONE");
    return out;
}
}
