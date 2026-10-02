#include "prts/materialization_graph.hpp"
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>

namespace {
prts::TimelineEvent event(std::uint64_t seq,prts::TimelineKind kind,std::string subject){
    prts::TimelineEvent e;e.seq=seq;e.process_uid=1;e.pid=123;e.kind=kind;e.process_image="/sample";e.subject=std::move(subject);return e;
}
}

int main(){
    prts::AnalysisReport report;
    auto start=event(1,prts::TimelineKind::ProcessStart,"/sample");
    report.runtime.timeline.push_back(start);
    auto create=event(2,prts::TimelineKind::FileCreate,"/tmp/payload.so");
    create.fields["backing_kind"]="runtime_released_file";
    report.runtime.timeline.push_back(create);
    auto write=event(3,prts::TimelineKind::FileWrite,"/tmp/payload.so");
    write.fields["backing_kind"]="runtime_released_file";
    report.runtime.timeline.push_back(write);
    auto load=event(4,prts::TimelineKind::ModuleLoad,"/tmp/payload.so");
    load.fields["base"]="0x400000";
    report.runtime.timeline.push_back(load);

    auto alloc=event(5,prts::TimelineKind::MemoryAllocate,"memfd_create");
    alloc.fields["backing_kind"]="runtime_memfd";alloc.fields["backing_id"]="7";alloc.fields["backing_path"]="/memfd:payload";
    report.runtime.timeline.push_back(alloc);
    auto exec=event(6,prts::TimelineKind::MaterializedExecute,"0x700000");
    exec.fields["backing_kind"]="runtime_memfd";exec.fields["backing_id"]="7";exec.fields["backing_write_bytes"]="128";exec.fields["address"]="0x700000";
    report.runtime.timeline.push_back(exec);

    auto mutate=event(7,prts::TimelineKind::MemoryWrite,"original executable image");
    mutate.fields["source"]="remote_image_baseline_diff";mutate.fields["state"]="CONFIRMED";mutate.fields["changed_bytes"]="3";mutate.fields["changed_ranges"]="rva 0x120+0x2;rva 0x400+0x1";
    report.runtime.timeline.push_back(mutate);

    const auto root=std::filesystem::temp_directory_path()/"auto-refirst-materialization-graph-unit";
    std::error_code ec;std::filesystem::remove_all(root,ec);
    prts::finalize_materialization_graph(report,root);
    std::filesystem::remove_all(root,ec);

    const auto module=std::find_if(report.findings.begin(),report.findings.end(),[](const auto&f){return f.family=="Runtime-created module load";});
    const auto executable=std::find_if(report.findings.begin(),report.findings.end(),[](const auto&f){return f.family=="Runtime-created executable";});
    const auto mutation=std::find_if(report.findings.begin(),report.findings.end(),[](const auto&f){return f.family=="Runtime executable mutation";});
    if(module==report.findings.end()||module->state!="CONFIRMED"||module->ranges.empty()||module->ranges.front().offset!=0x400000)return 1;
    if(executable==report.findings.end()||executable->state!="CONFIRMED"||executable->ranges.empty()||executable->ranges.front().offset!=0x700000)return 2;
    if(mutation==report.findings.end()||mutation->ranges.size()!=2||mutation->ranges.front().offset!=0x120||mutation->ranges.back().offset!=0x400)return 3;
    std::cout<<"[PASS] runtime actionable findings\n";
    return 0;
}
