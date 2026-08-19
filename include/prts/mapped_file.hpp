#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
namespace prts {
class MappedFile {
public:
    explicit MappedFile(const std::filesystem::path& path);
    ~MappedFile();
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    MappedFile(MappedFile&& other) noexcept;
    MappedFile& operator=(MappedFile&& other) noexcept;
    bool valid() const noexcept { return data_ != nullptr || size_ == 0; }
    std::span<const std::uint8_t> bytes() const noexcept { return {data_, size_}; }
    std::size_t size() const noexcept { return size_; }
    const std::string& error() const noexcept { return error_; }
private:
    void reset() noexcept;
    const std::uint8_t* data_{nullptr};
    std::size_t size_{0};
    std::string error_;
#ifdef _WIN32
    void* file_{reinterpret_cast<void*>(-1)};
    void* mapping_{nullptr};
#else
    int fd_{-1};
#endif
};
}
