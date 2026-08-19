#include "prts/mapped_file.hpp"
#include <system_error>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace prts {
MappedFile::MappedFile(const std::filesystem::path& path) {
#ifdef _WIN32
    HANDLE f=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(f==INVALID_HANDLE_VALUE){error_="CreateFileW failed";return;} file_=f;
    LARGE_INTEGER sz{}; if(!GetFileSizeEx(f,&sz)||sz.QuadPart<0){error_="GetFileSizeEx failed";reset();return;}
    size_=static_cast<std::size_t>(sz.QuadPart); if(size_==0)return;
    HANDLE m=CreateFileMappingW(f,nullptr,PAGE_READONLY,0,0,nullptr); if(!m){error_="CreateFileMappingW failed";reset();return;} mapping_=m;
    void* v=MapViewOfFile(m,FILE_MAP_READ,0,0,0); if(!v){error_="MapViewOfFile failed";reset();return;} data_=static_cast<const std::uint8_t*>(v);
#else
    fd_=::open(path.c_str(),O_RDONLY|O_CLOEXEC); if(fd_<0){error_="open failed";return;}
    struct stat st{}; if(fstat(fd_,&st)!=0||st.st_size<0){error_="fstat failed";reset();return;}
    size_=static_cast<std::size_t>(st.st_size); if(size_==0)return;
    void* v=mmap(nullptr,size_,PROT_READ,MAP_PRIVATE,fd_,0); if(v==MAP_FAILED){data_=nullptr;error_="mmap failed";reset();return;} data_=static_cast<const std::uint8_t*>(v);
#endif
}
MappedFile::~MappedFile(){reset();}
MappedFile::MappedFile(MappedFile&& o) noexcept { *this=std::move(o); }
MappedFile& MappedFile::operator=(MappedFile&& o) noexcept {
    if(this==&o) return *this;
    reset(); data_=o.data_;size_=o.size_;error_=std::move(o.error_);o.data_=nullptr;o.size_=0;
#ifdef _WIN32
    file_=o.file_;mapping_=o.mapping_;o.file_=reinterpret_cast<void*>(-1);o.mapping_=nullptr;
#else
    fd_=o.fd_;o.fd_=-1;
#endif
    return *this;
}
void MappedFile::reset() noexcept {
#ifdef _WIN32
    if(data_)UnmapViewOfFile(data_); data_=nullptr;
    if(mapping_)CloseHandle(static_cast<HANDLE>(mapping_)); mapping_=nullptr;
    if(file_!=reinterpret_cast<void*>(-1))CloseHandle(static_cast<HANDLE>(file_)); file_=reinterpret_cast<void*>(-1);
#else
    if(data_&&size_) munmap(const_cast<std::uint8_t*>(data_),size_);
    data_=nullptr;
    if(fd_>=0) ::close(fd_);
    fd_=-1;
#endif
    size_=0;
}
}
