#include "prts/mapped_file.hpp"
#include "prts/sha256.hpp"
#include <chrono>
#include <limits>
#include <system_error>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace prts {
namespace {
#if !defined(_WIN32) || !defined(_MSC_VER)
std::optional<std::filesystem::file_time_type> native_write_time(std::int64_t seconds,std::int64_t nanos){
    using Time=std::filesystem::file_time_type;
    using Duration=Time::duration;
    const auto base=Time::clock::from_sys(std::chrono::sys_seconds{std::chrono::seconds{seconds}});
    // Check representability before the integral duration conversion. Leave an
    // unrepresentable timestamp absent without discarding readable file bytes.
    const auto ticks=std::chrono::duration<long double,Duration::period>(base.time_since_epoch()).count();
    const auto margin=std::chrono::duration<long double,Duration::period>(std::chrono::seconds{1}).count();
    if(ticks<static_cast<long double>(std::numeric_limits<Duration::rep>::lowest())+margin||
       ticks>static_cast<long double>(std::numeric_limits<Duration::rep>::max())-margin)return {};
    return Time{std::chrono::duration_cast<Duration>(base.time_since_epoch())+
                std::chrono::duration_cast<Duration>(std::chrono::nanoseconds{nanos})};
}
#endif
}
MappedFile::MappedFile(const std::filesystem::path& path) {
    metadata_.path=path;
#ifdef _WIN32
    HANDLE f=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE){error_="CreateFileW failed";return;} file_=f;
    BY_HANDLE_FILE_INFORMATION info{};
    if(GetFileType(f)!=FILE_TYPE_DISK||!GetFileInformationByHandle(f,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)){
        error_="opened input is not a readable regular disk file";reset();return;
    }
    const auto size=(std::uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    if(size>std::numeric_limits<std::size_t>::max()){error_="input exceeds addressable mapping size";reset();return;}
    size_=static_cast<std::size_t>(size);metadata_.exists=true;metadata_.size=size_;
    const auto ticks=(std::uint64_t(info.ftLastWriteTime.dwHighDateTime)<<32)|info.ftLastWriteTime.dwLowDateTime;
#ifdef _MSC_VER
    // Microsoft file_clock uses native FILETIME's 1601 epoch and 100 ns ticks.
    if(ticks<=static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
        metadata_.write_time=std::filesystem::file_time_type{std::filesystem::file_time_type::duration{static_cast<std::int64_t>(ticks)}};
#else
    metadata_.write_time=native_write_time(static_cast<std::int64_t>(ticks/10000000)-11644473600LL,static_cast<std::int64_t>(ticks%10000000)*100);
#endif
    if(size_==0)return;
    HANDLE m=CreateFileMappingW(f,nullptr,PAGE_READONLY,0,0,nullptr); if(!m){error_="CreateFileMappingW failed";reset();return;} mapping_=m;
    void* v=MapViewOfFile(m,FILE_MAP_READ,0,0,0); if(!v){error_="MapViewOfFile failed";reset();return;} data_=static_cast<const std::uint8_t*>(v);
#else
    fd_=::open(path.c_str(),O_RDONLY|O_CLOEXEC); if(fd_<0){error_="open failed";return;}
    struct stat st{}; if(fstat(fd_,&st)!=0||st.st_size<0||!S_ISREG(st.st_mode)){error_="opened input is not a readable regular file";reset();return;}
    if(static_cast<std::uintmax_t>(st.st_size)>std::numeric_limits<std::size_t>::max()){error_="input exceeds addressable mapping size";reset();return;}
    size_=static_cast<std::size_t>(st.st_size);metadata_.exists=true;metadata_.size=size_;
#ifdef __APPLE__
    metadata_.write_time=native_write_time(st.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec);
#else
    metadata_.write_time=native_write_time(st.st_mtim.tv_sec,st.st_mtim.tv_nsec);
#endif
    if(size_==0)return;
    void* v=mmap(nullptr,size_,PROT_READ,MAP_PRIVATE,fd_,0); if(v==MAP_FAILED){data_=nullptr;error_="mmap failed";reset();return;} data_=static_cast<const std::uint8_t*>(v);
#endif
}
MappedFile::~MappedFile(){reset();}
FileSnapshot MappedFile::snapshot() const {
    auto result=metadata_;
    if(!valid()||!result.exists){result.exists=false;return result;}
    result.sha256=sha256_bytes(bytes());
    return result;
}
MappedFile::MappedFile(MappedFile&& o) noexcept { *this=std::move(o); }
MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if(this==&o) return *this;
    reset(); data_=o.data_;size_=o.size_;error_=std::move(o.error_);o.data_=nullptr;o.size_=0;
    metadata_=std::move(o.metadata_);o.metadata_.exists=false;
#ifdef _WIN32
    file_=o.file_;mapping_=o.mapping_;o.file_=reinterpret_cast<void*>(-1);o.mapping_=nullptr;
#else
    fd_=o.fd_;o.fd_=-1;
#endif
    return *this;
}
void MappedFile::reset() noexcept {
#ifdef _WIN32
    if(data_)UnmapViewOfFile(data_);
    data_=nullptr;
    if(mapping_)CloseHandle(static_cast<HANDLE>(mapping_));
    mapping_=nullptr;
    if(file_!=reinterpret_cast<void*>(-1))CloseHandle(static_cast<HANDLE>(file_));
    file_=reinterpret_cast<void*>(-1);
#else
    if(data_&&size_) munmap(const_cast<std::uint8_t*>(data_),size_);
    data_=nullptr;
    if(fd_>=0) ::close(fd_);
    fd_=-1;
#endif
    size_=0;
    metadata_.exists=false;
}
}
