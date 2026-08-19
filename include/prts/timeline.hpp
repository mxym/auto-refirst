#pragma once
#include <cstdint>
#include <map>
#include <string>
namespace prts {
enum class TimelineKind {
 ProcessStart, ProcessExit,
 ModuleLoad, ModuleUnload,
 FileCreate, FileOpen, FileWrite, FileRename, FileDelete,
 MemoryAllocate, MemoryProtect, MemoryWrite, MaterializedExecute,
 PreEntryExecute, OepCandidate, DumpCreated,
 ConsoleStdout, ConsoleStderr
};
struct TimelineEvent {
 std::uint64_t seq=0;
 std::uint64_t t_us=0;               // monotonic, relative to root launch
 std::uint64_t process_uid=0;        // never reused inside one run
 std::uint64_t parent_uid=0;
 std::uint32_t pid=0;
 std::uint32_t ppid=0;
 TimelineKind kind=TimelineKind::ProcessStart;
 std::string process_image;
 std::string command_line;
 std::string subject;                // module/path/address/dump path/etc.
 std::map<std::string,std::string> fields;
};
const char* timeline_kind_name(TimelineKind k);
}
