#include "prts/dart.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace prts {
namespace {

constexpr std::uint32_t kSnapshotMagic = 0xdcdcf5f5u;
constexpr std::uint32_t kKernelMagic = 0x90abcdefu;
constexpr std::uint64_t kSnapshotHeaderSize = 20;
constexpr std::uint64_t kSnapshotHashSize = 32;
constexpr std::uint64_t kMaxFeatures = 8192;
constexpr std::uint32_t PT_LOAD = 1;
constexpr std::uint32_t PT_DYNAMIC = 2;
constexpr std::uint32_t PF_X = 1;
constexpr std::uint32_t PF_W = 2;
constexpr std::uint32_t PF_R = 4;
constexpr std::int64_t DT_NULL = 0;
constexpr std::int64_t DT_HASH = 4;
constexpr std::int64_t DT_STRTAB = 5;
constexpr std::int64_t DT_SYMTAB = 6;
constexpr std::int64_t DT_STRSZ = 10;
constexpr std::int64_t DT_SYMENT = 11;
constexpr std::int64_t DT_GNU_HASH = 0x6ffffef5;

std::string snapshot_kind_name(std::int64_t kind) {
    switch (kind) {
        case 0: return "None";
        case 1: return "Full";
        case 2: return "FullAOT";
        case 3: return "FullJIT";
        case 4: return "Message";
        case 5: return "Module";
        case 6: return "Invalid";
        default: return "Unknown";
    }
}

bool lower_hex32(std::span<const std::uint8_t> x) {
    if (x.size() != 32) return false;
    return std::all_of(x.begin(), x.end(), [](std::uint8_t c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

bool printable_feature_char(std::uint8_t c) {
    return c >= 0x20 && c <= 0x7e;
}

std::vector<std::string> split_features(std::string_view s) {
    std::vector<std::string> out;
    std::size_t p = 0;
    while (p < s.size()) {
        while (p < s.size() && s[p] == ' ') ++p;
        if (p == s.size()) break;
        const auto e = s.find(' ', p);
        const auto end = e == std::string_view::npos ? s.size() : e;
        if (end > p) out.emplace_back(s.substr(p, end - p));
        p = end;
    }
    return out;
}

std::string elf_arch(std::uint16_t machine) {
    switch (machine) {
        case 3: return "ia32";       // EM_386
        case 40: return "arm";       // EM_ARM
        case 62: return "x64";       // EM_X86_64
        case 183: return "arm64";    // EM_AARCH64
        case 243: return "riscv64";  // EM_RISCV (Dart currently targets 64-bit profile)
        default: return {};
    }
}

struct Reader {
    std::span<const std::uint8_t> d;
    bool little = true;
    bool elf64 = true;

    bool range(std::uint64_t off, std::uint64_t size) const {
        return off <= d.size() && size <= d.size() - off;
    }
    std::uint16_t u16(std::uint64_t off) const {
        if (!range(off, 2)) return 0;
        if (little) return std::uint16_t(d[off]) | (std::uint16_t(d[off + 1]) << 8);
        return (std::uint16_t(d[off]) << 8) | std::uint16_t(d[off + 1]);
    }
    std::uint32_t u32(std::uint64_t off) const {
        if (!range(off, 4)) return 0;
        if (little) {
            return std::uint32_t(d[off]) | (std::uint32_t(d[off + 1]) << 8) |
                   (std::uint32_t(d[off + 2]) << 16) | (std::uint32_t(d[off + 3]) << 24);
        }
        return (std::uint32_t(d[off]) << 24) | (std::uint32_t(d[off + 1]) << 16) |
               (std::uint32_t(d[off + 2]) << 8) | std::uint32_t(d[off + 3]);
    }
    std::uint64_t u64(std::uint64_t off) const {
        if (!range(off, 8)) return 0;
        if (little) return std::uint64_t(u32(off)) | (std::uint64_t(u32(off + 4)) << 32);
        return (std::uint64_t(u32(off)) << 32) | std::uint64_t(u32(off + 4));
    }
    std::int64_t s(std::uint64_t off, unsigned bytes) const {
        if (bytes == 8) return static_cast<std::int64_t>(u64(off));
        return static_cast<std::int32_t>(u32(off));
    }
};

struct DartLoadSegment {
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t file_size = 0;
    std::uint64_t memory_size = 0;
};

struct DartElfLayout {
    bool valid = false;
    std::vector<DartLoadSegment> segments;
    std::string error;
    std::uint64_t error_offset = 0;
};

bool power_of_two(std::uint64_t x) { return x != 0 && (x & (x - 1)) == 0; }

DartElfLayout parse_program_layout(std::span<const std::uint8_t> data, const ElfInfo& elf) {
    DartElfLayout out;
    Reader r{data, elf.little_endian, elf.elf64};
    const auto phoff = elf.elf64 ? r.u64(0x20) : r.u32(0x1c);
    const auto phentsize = r.u16(elf.elf64 ? 0x36 : 0x2a);
    const auto phnum = r.u16(elf.elf64 ? 0x38 : 0x2c);
    const auto expected = elf.elf64 ? 56u : 32u;
    if (phentsize != expected || phnum == 0 || phnum == 0xffff) {
        out.error = "Dart AOT requires directly bounded standard ELF program headers";
        out.error_offset = elf.elf64 ? 0x36 : 0x2a;
        return out;
    }
    if (phoff > data.size() || std::uint64_t(phnum) * phentsize > data.size() - phoff) {
        out.error = "ELF program-header table exceeds file while routing Dart AOT";
        out.error_offset = phoff;
        return out;
    }
    out.segments.reserve(phnum);
    for (std::uint16_t i = 0; i < phnum; ++i) {
        const auto at = phoff + std::uint64_t(i) * phentsize;
        DartLoadSegment seg;
        seg.type = r.u32(at);
        if (elf.elf64) {
            seg.flags = r.u32(at + 4);
            seg.offset = r.u64(at + 8);
            seg.vaddr = r.u64(at + 16);
            seg.file_size = r.u64(at + 32);
            seg.memory_size = r.u64(at + 40);
            const auto align = r.u64(at + 48);
            if (align > 1 && (!power_of_two(align) || (seg.vaddr % align) != (seg.offset % align))) {
                out.error = "ELF program-header alignment is invalid for Dart AOT";
                out.error_offset = at + 48;
                return out;
            }
        } else {
            seg.offset = r.u32(at + 4);
            seg.vaddr = r.u32(at + 8);
            seg.file_size = r.u32(at + 16);
            seg.memory_size = r.u32(at + 20);
            seg.flags = r.u32(at + 24);
            const auto align = r.u32(at + 28);
            if (align > 1 && (!power_of_two(align) || (seg.vaddr % align) != (seg.offset % align))) {
                out.error = "ELF program-header alignment is invalid for Dart AOT";
                out.error_offset = at + 28;
                return out;
            }
        }
        if (seg.file_size > seg.memory_size || seg.offset > data.size() || seg.file_size > data.size() - seg.offset) {
            out.error = "ELF program-header file/memory geometry is invalid for Dart AOT";
            out.error_offset = at;
            return out;
        }
        if (seg.type == PT_LOAD || seg.type == PT_DYNAMIC) out.segments.push_back(seg);
    }
    // Cross-check all load/dynamic file geometry already accepted by the common ELF parser.
    for (const auto& raw : out.segments) {
        const auto it = std::find_if(elf.segments.begin(), elf.segments.end(), [&](const ElfSegment& x) {
            return x.type == raw.type && x.offset == raw.offset && x.file_size == raw.file_size &&
                   x.memory_size == raw.memory_size && x.flags == raw.flags;
        });
        if (it == elf.segments.end()) {
            out.error = "raw ELF program header disagrees with validated common ELF model";
            out.error_offset = raw.offset;
            return out;
        }
    }
    if (std::none_of(out.segments.begin(), out.segments.end(), [](const auto& x){ return x.type == PT_LOAD; })) {
        out.error = "Dart AOT ELF has no PT_LOAD segment";
        return out;
    }
    out.valid = true;
    return out;
}

struct FileMap {
    bool ok = false;
    std::uint64_t off = 0;
    std::uint64_t available = 0;
    std::uint32_t flags = 0;
};

FileMap map_va(const DartElfLayout& layout, std::uint64_t va) {
    for (const auto& seg : layout.segments) {
        if (seg.type != PT_LOAD || va < seg.vaddr) continue;
        const auto delta = va - seg.vaddr;
        if (delta >= seg.file_size) continue;
        return {true, seg.offset + delta, seg.file_size - delta, seg.flags};
    }
    return {};
}

bool contained_in_load(const DartElfLayout& layout, std::uint64_t va, std::uint64_t size,
                       bool file_backed, std::uint32_t* flags = nullptr) {
    for (const auto& seg : layout.segments) {
        if (seg.type != PT_LOAD || va < seg.vaddr) continue;
        const auto delta = va - seg.vaddr;
        const auto limit = file_backed ? seg.file_size : seg.memory_size;
        if (delta > limit || size > limit - delta) continue;
        if (flags) *flags = seg.flags;
        return true;
    }
    return false;
}

struct DynamicLayout {
    bool present = false;
    bool valid = false;
    bool used_sysv_hash = false;
    bool used_gnu_hash = false;
    std::uint64_t strtab = 0;
    std::uint64_t strsz = 0;
    std::uint64_t symtab = 0;
    std::uint64_t syment = 0;
    std::uint64_t hash = 0;
    std::uint64_t gnu_hash = 0;
    std::uint64_t symbol_count = 0;
    std::string error;
    std::uint64_t error_offset = 0;
};

std::uint64_t gnu_hash_count(const Reader& r, const DartElfLayout& layout, std::uint64_t va,
                             std::string& error, std::uint64_t& error_offset) {
    const auto m = map_va(layout, va);
    if (!m.ok || m.available < 16) {
        error = "DT_GNU_HASH is not fully file-backed";
        error_offset = m.ok ? m.off : 0;
        return 0;
    }
    const auto nbuckets = r.u32(m.off);
    const auto symoffset = r.u32(m.off + 4);
    const auto bloom_size = r.u32(m.off + 8);
    if (nbuckets == 0 || bloom_size == 0 || nbuckets > 1000000 || bloom_size > 1000000) {
        error = "invalid GNU hash table header";
        error_offset = m.off;
        return 0;
    }
    const auto word = r.elf64 ? 8u : 4u;
    const auto buckets_off = m.off + 16 + std::uint64_t(bloom_size) * word;
    if (!r.range(buckets_off, std::uint64_t(nbuckets) * 4)) {
        error = "truncated GNU hash buckets";
        error_offset = buckets_off;
        return 0;
    }
    const auto chains_off = buckets_off + std::uint64_t(nbuckets) * 4;
    std::uint64_t max_count = symoffset;
    for (std::uint32_t i = 0; i < nbuckets; ++i) {
        const auto bucket = r.u32(buckets_off + std::uint64_t(i) * 4);
        if (bucket == 0) continue;
        if (bucket < symoffset) {
            error = "GNU hash bucket precedes symbol offset";
            error_offset = buckets_off + std::uint64_t(i) * 4;
            return 0;
        }
        std::uint64_t index = bucket;
        for (std::uint64_t steps = 0; steps < 1000000; ++steps, ++index) {
            const auto chain_index = index - symoffset;
            const auto at = chains_off + chain_index * 4;
            if (!r.range(at, 4)) {
                error = "truncated GNU hash chain";
                error_offset = at;
                return 0;
            }
            const auto h = r.u32(at);
            max_count = std::max(max_count, index + 1);
            if (h & 1u) break;
            if (steps == 999999) {
                error = "unreasonable GNU hash chain length";
                error_offset = at;
                return 0;
            }
        }
    }
    return max_count;
}

DynamicLayout parse_dynamic(std::span<const std::uint8_t> data, const ElfInfo& elf, const DartElfLayout& layout) {
    DynamicLayout out;
    Reader r{data, elf.little_endian, elf.elf64};
    const DartLoadSegment* dyn = nullptr;
    for (const auto& seg : layout.segments) {
        if (seg.type == PT_DYNAMIC) {
            if (dyn) {
                out.present = true;
                out.error = "multiple PT_DYNAMIC segments";
                out.error_offset = seg.offset;
                return out;
            }
            dyn = &seg;
        }
    }
    if (!dyn) return out;
    out.present = true;
    const auto entsz = elf.elf64 ? 16u : 8u;
    if (dyn->file_size == 0 || dyn->file_size % entsz != 0 || !r.range(dyn->offset, dyn->file_size)) {
        out.error = "invalid PT_DYNAMIC file geometry";
        out.error_offset = dyn->offset;
        return out;
    }
    bool terminated = false;
    for (std::uint64_t p = dyn->offset; p < dyn->offset + dyn->file_size; p += entsz) {
        const auto tag = r.s(p, elf.elf64 ? 8 : 4);
        const auto val = elf.elf64 ? r.u64(p + 8) : r.u32(p + 4);
        if (tag == DT_NULL) { terminated = true; break; }
        if (tag == DT_HASH) out.hash = val;
        else if (tag == DT_GNU_HASH) out.gnu_hash = val;
        else if (tag == DT_STRTAB) out.strtab = val;
        else if (tag == DT_STRSZ) out.strsz = val;
        else if (tag == DT_SYMTAB) out.symtab = val;
        else if (tag == DT_SYMENT) out.syment = val;
    }
    if (!terminated) {
        out.error = "PT_DYNAMIC is not DT_NULL terminated";
        out.error_offset = dyn->offset + dyn->file_size - entsz;
        return out;
    }
    if (!out.strtab || !out.strsz || !out.symtab || !out.syment) {
        out.error = "PT_DYNAMIC lacks required symbol/string table tags";
        out.error_offset = dyn->offset;
        return out;
    }
    const auto expected = elf.elf64 ? 24u : 16u;
    if (out.syment != expected) {
        out.error = "unexpected ELF dynamic symbol entry size";
        out.error_offset = dyn->offset;
        return out;
    }
    const auto sm = map_va(layout, out.strtab);
    const auto ym = map_va(layout, out.symtab);
    if (!sm.ok || out.strsz > sm.available) {
        out.error = "dynamic string table is not fully file-backed";
        out.error_offset = sm.ok ? sm.off : dyn->offset;
        return out;
    }
    if (!ym.ok || out.syment > ym.available) {
        out.error = "dynamic symbol table is not file-backed";
        out.error_offset = ym.ok ? ym.off : dyn->offset;
        return out;
    }
    if (out.hash) {
        const auto hm = map_va(layout, out.hash);
        if (!hm.ok || hm.available < 8) {
            out.error = "DT_HASH is not file-backed";
            out.error_offset = hm.ok ? hm.off : dyn->offset;
            return out;
        }
        const auto nbucket = r.u32(hm.off);
        const auto nchain = r.u32(hm.off + 4);
        if (nbucket == 0 || nchain == 0 || nbucket > 1000000 || nchain > 10000000 ||
            8ull + 4ull * nbucket + 4ull * nchain > hm.available) {
            out.error = "invalid SysV ELF hash table geometry";
            out.error_offset = hm.off;
            return out;
        }
        out.symbol_count = nchain;
        out.used_sysv_hash = true;
    }
    if (out.gnu_hash) {
        std::string error;
        std::uint64_t error_offset = 0;
        const auto count = gnu_hash_count(r, layout, out.gnu_hash, error, error_offset);
        if (!error.empty()) {
            out.error = std::move(error);
            out.error_offset = error_offset;
            return out;
        }
        if (out.symbol_count && count > out.symbol_count) {
            out.error = "GNU hash refers beyond SysV dynamic symbol count";
            out.error_offset = map_va(layout, out.gnu_hash).off;
            return out;
        }
        if (!out.symbol_count) out.symbol_count = count;
        out.used_gnu_hash = true;
    }
    if (!out.symbol_count) {
        // Loader-visible Dart AOT objects generated by the VM carry a hash table. Do not
        // guess dynsym size from adjacent addresses because that would weaken geometry.
        out.error = "dynamic symbol count is unavailable (no validated DT_HASH/DT_GNU_HASH)";
        out.error_offset = ym.off;
        return out;
    }
    if (out.symbol_count > ym.available / out.syment) {
        out.error = "dynamic symbol count exceeds mapped symbol table bytes";
        out.error_offset = ym.off;
        return out;
    }
    out.valid = true;
    return out;
}

struct ParsedDynSymbol {
    std::uint32_t index = 0;
    std::string name;
    std::uint64_t value = 0;
    std::uint64_t size = 0;
    std::uint8_t info = 0;
    std::uint16_t shndx = 0;
};

std::vector<ParsedDynSymbol> parse_dyn_symbols(std::span<const std::uint8_t> data,
                                               const ElfInfo& elf, const DartElfLayout& layout,
                                               const DynamicLayout& dyn,
                                               std::string& error,
                                               std::uint64_t& error_offset) {
    Reader r{data, elf.little_endian, elf.elf64};
    const auto sm = map_va(layout, dyn.strtab);
    const auto ym = map_va(layout, dyn.symtab);
    std::vector<ParsedDynSymbol> out;
    out.reserve(static_cast<std::size_t>(dyn.symbol_count));
    for (std::uint64_t i = 0; i < dyn.symbol_count; ++i) {
        const auto at = ym.off + i * dyn.syment;
        const auto name_idx = r.u32(at);
        std::uint64_t value = 0, size = 0;
        std::uint8_t info = 0;
        std::uint16_t shndx = 0;
        if (elf.elf64) {
            info = data[at + 4];
            shndx = r.u16(at + 6);
            value = r.u64(at + 8);
            size = r.u64(at + 16);
        } else {
            value = r.u32(at + 4);
            size = r.u32(at + 8);
            info = data[at + 12];
            shndx = r.u16(at + 14);
        }
        if (name_idx >= dyn.strsz) {
            error = "dynamic symbol name index exceeds DT_STRSZ";
            error_offset = at;
            return {};
        }
        const auto name_off = sm.off + name_idx;
        const auto max = dyn.strsz - name_idx;
        const auto begin = reinterpret_cast<const char*>(data.data() + name_off);
        const auto end = static_cast<const char*>(std::memchr(begin, 0, static_cast<std::size_t>(max)));
        if (!end) {
            error = "dynamic symbol name is not NUL terminated within DT_STRSZ";
            error_offset = name_off;
            return {};
        }
        out.push_back({static_cast<std::uint32_t>(i), std::string(begin, end), value, size, info, shndx});
    }
    return out;
}

std::uint32_t elf_sysv_hash(std::string_view name) {
    std::uint32_t h = 0;
    for (const unsigned char c : name) {
        h = (h << 4) + c;
        const auto g = h & 0xf0000000u;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

std::uint32_t elf_gnu_hash(std::string_view name) {
    std::uint32_t h = 5381;
    for (const unsigned char c : name) h = h * 33u + c;
    return h;
}

bool sysv_hash_resolves(const Reader& r, const DartElfLayout& layout, const DynamicLayout& dyn,
                        const std::vector<ParsedDynSymbol>& syms, const ParsedDynSymbol& target,
                        std::string& error, std::uint64_t& error_offset) {
    if (!dyn.hash) return false;
    const auto hm = map_va(layout, dyn.hash);
    if (!hm.ok || hm.available < 8) {
        error = "Dart target symbol SysV hash table is not file-backed";
        error_offset = hm.ok ? hm.off : 0;
        return false;
    }
    const auto nbucket = r.u32(hm.off);
    const auto nchain = r.u32(hm.off + 4);
    const auto buckets = hm.off + 8;
    const auto chains = buckets + std::uint64_t(nbucket) * 4;
    if (target.index >= nchain || target.index >= syms.size()) {
        error = "Dart target symbol index exceeds SysV hash chain table";
        error_offset = hm.off;
        return false;
    }
    auto idx = r.u32(buckets + std::uint64_t(elf_sysv_hash(target.name) % nbucket) * 4);
    for (std::uint64_t steps = 0; idx != 0 && steps < nchain; ++steps) {
        if (idx >= nchain || idx >= syms.size()) {
            error = "SysV hash chain index exceeds dynamic symbol table";
            error_offset = chains + std::uint64_t(std::min<std::uint32_t>(idx, nchain)) * 4;
            return false;
        }
        if (syms[idx].name == target.name) return idx == target.index;
        idx = r.u32(chains + std::uint64_t(idx) * 4);
    }
    return false;
}

bool gnu_hash_resolves(const Reader& r, const DartElfLayout& layout, const DynamicLayout& dyn,
                       const std::vector<ParsedDynSymbol>& syms, const ParsedDynSymbol& target,
                       std::string& error, std::uint64_t& error_offset) {
    if (!dyn.gnu_hash) return false;
    const auto hm = map_va(layout, dyn.gnu_hash);
    if (!hm.ok || hm.available < 16) {
        error = "Dart target symbol GNU hash table is not file-backed";
        error_offset = hm.ok ? hm.off : 0;
        return false;
    }
    const auto nbuckets = r.u32(hm.off);
    const auto symoffset = r.u32(hm.off + 4);
    const auto bloom_size = r.u32(hm.off + 8);
    const auto bloom_shift = r.u32(hm.off + 12);
    if (!nbuckets || !bloom_size) return false;
    const auto h = elf_gnu_hash(target.name);
    const auto word_bytes = r.elf64 ? 8u : 4u;
    const auto word_bits = word_bytes * 8u;
    const auto bloom_off = hm.off + 16;
    const auto bloom_index = (h / word_bits) % bloom_size;
    const auto bloom_word = r.elf64
        ? r.u64(bloom_off + std::uint64_t(bloom_index) * word_bytes)
        : std::uint64_t(r.u32(bloom_off + std::uint64_t(bloom_index) * word_bytes));
    const auto mask = (std::uint64_t(1) << (h % word_bits)) |
                      (std::uint64_t(1) << ((h >> bloom_shift) % word_bits));
    if ((bloom_word & mask) != mask) return false;
    const auto buckets_off = bloom_off + std::uint64_t(bloom_size) * word_bytes;
    const auto chains_off = buckets_off + std::uint64_t(nbuckets) * 4;
    auto idx = r.u32(buckets_off + std::uint64_t(h % nbuckets) * 4);
    if (idx == 0 || idx < symoffset) return false;
    for (std::uint64_t steps = 0; steps < 1000000; ++steps, ++idx) {
        if (idx >= syms.size()) {
            error = "GNU hash chain reaches beyond dynamic symbol table";
            error_offset = chains_off + std::uint64_t(idx - symoffset) * 4;
            return false;
        }
        const auto chain = r.u32(chains_off + std::uint64_t(idx - symoffset) * 4);
        if ((chain | 1u) == (h | 1u) && syms[idx].name == target.name) return idx == target.index;
        if (chain & 1u) return false;
    }
    error = "unreasonable GNU hash lookup chain length";
    error_offset = chains_off;
    return false;
}

bool target_hash_resolves(std::span<const std::uint8_t> data, const ElfInfo& elf,
                          const DartElfLayout& layout, const DynamicLayout& dyn, const std::vector<ParsedDynSymbol>& syms,
                          const ParsedDynSymbol& target, std::string& error,
                          std::uint64_t& error_offset) {
    Reader r{data, elf.little_endian, elf.elf64};
    bool checked = false;
    if (dyn.hash) {
        checked = true;
        if (!sysv_hash_resolves(r, layout, dyn, syms, target, error, error_offset)) return false;
    }
    if (dyn.gnu_hash) {
        checked = true;
        if (!gnu_hash_resolves(r, layout, dyn, syms, target, error, error_offset)) return false;
    }
    return checked;
}

bool target_symbol(std::string_view name) {
    static constexpr std::array<std::string_view, 8> names = {
        "_kDartSnapshotData", "_kDartSnapshotText", "_kDartSnapshotBuildId", "_kDartSnapshotBss",
        "kDartVmSnapshotData", "kDartVmSnapshotInstructions",
        "kDartIsolateSnapshotData", "kDartIsolateSnapshotInstructions"
    };
    return std::find(names.begin(), names.end(), name) != names.end();
}

const DartAotSymbol* symbol(const DartAotInfo& aot, std::string_view name) {
    const auto it = std::find_if(aot.symbols.begin(), aot.symbols.end(),
                                 [&](const DartAotSymbol& x) { return x.name == name; });
    return it == aot.symbols.end() ? nullptr : &*it;
}

bool validate_symbol_geometry(DartAotInfo& out, const DartElfLayout& layout,
                              const ParsedDynSymbol& s, DartAotSymbol& x) {
    x.name = s.name;
    x.value = s.value;
    x.size = s.size;
    x.binding = s.info >> 4;
    x.type = s.info & 0x0f;
    if (s.shndx == 0 || s.value == 0 || s.size == 0) {
        out.error = "Dart AOT symbol is undefined/zero-sized: " + s.name;
        return false;
    }
    std::uint32_t flags = 0;
    if (!contained_in_load(layout, s.value, s.size, false, &flags)) {
        out.error = "Dart AOT symbol is outside mapped PT_LOAD memory: " + s.name;
        return false;
    }
    x.segment_flags = flags;
    const auto fm = map_va(layout, s.value);
    if (fm.ok && s.size <= fm.available) {
        x.file_backed = true;
        x.file_offset = fm.off;
    }
    return true;
}

bool validate_aot_data_symbol(DartAotInfo& out, std::span<const std::uint8_t> data,
                              const DartAotSymbol& s, std::string_view role) {
    if (!s.file_backed || (s.segment_flags & PF_R) == 0 || (s.segment_flags & (PF_W | PF_X)) != 0) {
        out.error = std::string(role) + " must be file-backed in a read-only non-executable PT_LOAD";
        out.error_offset = s.file_offset;
        return false;
    }
    auto snap = parse_dart_snapshot(data, s.file_offset, s.size);
    if (!snap.valid) {
        out.error = std::string(role) + " does not contain a valid Dart snapshot header: " + snap.error;
        out.error_offset = snap.error_offset;
        out.snapshots.push_back(std::move(snap));
        return false;
    }
    if (snap.kind != 2) {
        out.error = std::string(role) + " snapshot kind is not FullAOT";
        out.error_offset = s.file_offset + 12;
        out.snapshots.push_back(std::move(snap));
        return false;
    }
    out.snapshots.push_back(std::move(snap));
    return true;
}

bool validate_aot_text_symbol(DartAotInfo& out, const DartAotSymbol& s,
                              std::string_view role) {
    if (!s.file_backed || (s.segment_flags & (PF_R | PF_X)) != (PF_R | PF_X) ||
        (s.segment_flags & PF_W) != 0) {
        out.error = std::string(role) + " must be file-backed in a readable executable non-writable PT_LOAD";
        out.error_offset = s.file_offset;
        return false;
    }
    return true;
}

std::string hex_bytes(std::span<const std::uint8_t> b) {
    constexpr char h[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (const auto x : b) {
        out.push_back(h[x >> 4]);
        out.push_back(h[x & 0xf]);
    }
    return out;
}

std::vector<DartStringHint> collect_ascii_hints_range(std::span<const std::uint8_t> data,
                                                         std::uint64_t begin,
                                                         std::uint64_t size,
                                                         std::size_t max_hints = 1024) {
    std::vector<DartStringHint> out;
    if (begin > data.size() || size > data.size() - begin) return out;
    constexpr std::size_t kMaxText = 512;
    std::set<std::string> seen;
    const auto end = begin + size;
    std::uint64_t p = begin;
    while (p < end && out.size() < max_hints) {
        while (p < end && (data[p] < 0x20 || data[p] > 0x7e)) ++p;
        const auto start = p;
        while (p < end && data[p] >= 0x20 && data[p] <= 0x7e && p - start < kMaxText) ++p;
        const auto n = p - start;
        if (n >= 4) {
            std::string text(reinterpret_cast<const char*>(data.data() + start), static_cast<std::size_t>(n));
            if (seen.insert(text).second) out.push_back({start, std::move(text)});
        }
        if (p == start) ++p;
        while (p < end && data[p] >= 0x20 && data[p] <= 0x7e) ++p;
    }
    return out;
}

void collect_ascii_hints(DartAotInfo& out, std::span<const std::uint8_t> data,
                         const DartAotSymbol& symbol) {
    if (!symbol.file_backed) return;
    out.string_hints = collect_ascii_hints_range(data, symbol.file_offset, symbol.size);
}

bool validate_optional_support_symbols(DartAotInfo& out, std::span<const std::uint8_t> data) {
    if (const auto* build = symbol(out, "_kDartSnapshotBuildId")) {
        if (!build->file_backed || build->size != 32 || (build->segment_flags & PF_R) == 0 ||
            (build->segment_flags & (PF_W | PF_X)) != 0 || build->file_offset > data.size() ||
            build->size > data.size() - build->file_offset) {
            out.error = "_kDartSnapshotBuildId must be exactly 32 file-backed bytes in a read-only non-executable PT_LOAD";
            out.error_offset = build->file_offset;
            return false;
        }
        out.build_id_hex = hex_bytes(data.subspan(build->file_offset, 32));
    }
    if (const auto* bss = symbol(out, "_kDartSnapshotBss")) {
        if ((bss->segment_flags & (PF_R | PF_W)) != (PF_R | PF_W) || (bss->segment_flags & PF_X) != 0) {
            out.error = "_kDartSnapshotBss must reside in a readable writable non-executable PT_LOAD";
            out.error_offset = bss->file_offset;
            return false;
        }
    }
    return true;
}

void check_architecture_feature(DartAotInfo& out) {
    if (out.architecture.empty()) return;
    for (const auto& snap : out.snapshots) {
        if (!snap.valid) continue;
        std::string observed;
        for (const auto& token : snap.feature_tokens) {
            std::string arch;
            if (token == "ia32") arch = "ia32";
            else if (token == "arm") arch = "arm";
            else if (token == "x64" || token.starts_with("x64-")) arch = "x64";
            else if (token == "arm64" || token.starts_with("arm64-")) arch = "arm64";
            else if (token == "riscv64" || token.starts_with("riscv64-")) arch = "riscv64";
            if (arch.empty()) continue;
            if (!observed.empty() && observed != arch) {
                out.architecture_feature_matches = false;
                out.error = "Dart snapshot features contain multiple architecture profiles";
                out.error_offset = snap.file_offset + kSnapshotHeaderSize + kSnapshotHashSize;
                return;
            }
            observed = std::move(arch);
        }
        if (observed.empty()) {
            out.anomalies.push_back("Dart snapshot features contain no recognized architecture profile");
        } else if (observed != out.architecture) {
            out.architecture_feature_matches = false;
            out.error = "Dart snapshot architecture feature does not match ELF e_machine";
            out.error_offset = snap.file_offset + kSnapshotHeaderSize + kSnapshotHashSize;
            return;
        }
    }
}


struct KernelError {
    std::string message;
    std::uint64_t offset = 0;
};

class KernelCursor {
public:
    KernelCursor(std::span<const std::uint8_t> data, std::uint64_t begin, std::uint64_t limit)
        : data_(data), pos_(begin), limit_(std::min<std::uint64_t>(limit, data.size())) {}

    std::uint64_t pos() const { return pos_; }
    std::uint64_t limit() const { return limit_; }
    std::uint64_t remaining() const { return pos_ <= limit_ ? limit_ - pos_ : 0; }

    bool byte(std::uint8_t& value, KernelError& error) {
        if (pos_ >= limit_) { error = {"truncated Dart Kernel byte", pos_}; return false; }
        value = data_[pos_++];
        return true;
    }

    bool be32(std::uint32_t& value, KernelError& error) {
        if (remaining() < 4) { error = {"truncated Dart Kernel UInt32", pos_}; return false; }
        value = (std::uint32_t(data_[pos_]) << 24) | (std::uint32_t(data_[pos_ + 1]) << 16) |
                (std::uint32_t(data_[pos_ + 2]) << 8) | std::uint32_t(data_[pos_ + 3]);
        pos_ += 4;
        return true;
    }

    bool u30(std::uint32_t& value, KernelError& error) {
        const auto at = pos_;
        std::uint8_t first = 0;
        if (!byte(first, error)) return false;
        if ((first & 0x80u) == 0) { value = first; return true; }
        if ((first & 0x40u) == 0) {
            std::uint8_t second = 0;
            if (!byte(second, error)) { error = {"truncated two-byte Dart Kernel UInt30", at}; return false; }
            value = (std::uint32_t(first & 0x3fu) << 8) | second;
            return true;
        }
        if (remaining() < 3) { error = {"truncated four-byte Dart Kernel UInt30", at}; return false; }
        value = (std::uint32_t(first & 0x3fu) << 24) | (std::uint32_t(data_[pos_]) << 16) |
                (std::uint32_t(data_[pos_ + 1]) << 8) | std::uint32_t(data_[pos_ + 2]);
        pos_ += 3;
        return true;
    }

    bool skip(std::uint64_t size, KernelError& error, std::string_view what) {
        if (size > remaining()) { error = {"truncated Dart Kernel " + std::string(what), pos_}; return false; }
        pos_ += size;
        return true;
    }

    std::span<const std::uint8_t> span(std::uint64_t begin, std::uint64_t size) const {
        if (begin > data_.size() || size > data_.size() - begin) return {};
        return data_.subspan(static_cast<std::size_t>(begin), static_cast<std::size_t>(size));
    }

private:
    std::span<const std::uint8_t> data_;
    std::uint64_t pos_ = 0;
    std::uint64_t limit_ = 0;
};

void append_kernel_u_escape(std::string& out, std::uint32_t cp) {
    constexpr char hex[] = "0123456789ABCDEF";
    out += "\\u";
    out.push_back(hex[(cp >> 12) & 0xf]);
    out.push_back(hex[(cp >> 8) & 0xf]);
    out.push_back(hex[(cp >> 4) & 0xf]);
    out.push_back(hex[cp & 0xf]);
}

bool decode_kernel_wtf8(std::span<const std::uint8_t> raw, std::string& out,
                        bool& surrogate_escaped, KernelError& error,
                        std::uint64_t file_offset) {
    out.clear();
    surrogate_escaped = false;
    out.reserve(raw.size());
    std::size_t i = 0;
    while (i < raw.size()) {
        const auto start = i;
        const auto c = raw[i++];
        std::uint32_t cp = 0;
        std::size_t need = 0;
        if (c < 0x80) { out.push_back(char(c)); continue; }
        if (c >= 0xc2 && c <= 0xdf) { cp = c & 0x1f; need = 1; }
        else if (c >= 0xe0 && c <= 0xef) { cp = c & 0x0f; need = 2; }
        else if (c >= 0xf0 && c <= 0xf4) { cp = c & 0x07; need = 3; }
        else { error = {"invalid Dart Kernel WTF-8 lead byte", file_offset + start}; return false; }
        if (need > raw.size() - i) { error = {"truncated Dart Kernel WTF-8 sequence", file_offset + start}; return false; }
        for (std::size_t n = 0; n < need; ++n) {
            const auto d = raw[i++];
            if ((d & 0xc0) != 0x80) { error = {"invalid Dart Kernel WTF-8 continuation byte", file_offset + i - 1}; return false; }
            if (n == 0) {
                if (c == 0xe0 && d < 0xa0) { error = {"overlong Dart Kernel WTF-8 sequence", file_offset + start}; return false; }
                if (c == 0xf0 && d < 0x90) { error = {"overlong Dart Kernel WTF-8 sequence", file_offset + start}; return false; }
                if (c == 0xf4 && d > 0x8f) { error = {"Dart Kernel WTF-8 code point exceeds Unicode range", file_offset + start}; return false; }
            }
            cp = (cp << 6) | (d & 0x3f);
        }
        if (cp > 0x10ffff) { error = {"Dart Kernel WTF-8 code point exceeds Unicode range", file_offset + start}; return false; }
        if (cp >= 0xd800 && cp <= 0xdfff) {
            append_kernel_u_escape(out, cp);
            surrogate_escaped = true;
        } else {
            out.append(reinterpret_cast<const char*>(raw.data() + start), i - start);
        }
    }
    return true;
}

bool read_kernel_direct_string(KernelCursor& cursor, std::string& out,
                               bool& surrogate_escaped, KernelError& error,
                               std::uint64_t* bytes_offset = nullptr) {
    std::uint32_t size = 0;
    if (!cursor.u30(size, error)) return false;
    if (size > 16u * 1024u * 1024u) { error = {"Dart Kernel direct string exceeds 16 MiB bound", cursor.pos()}; return false; }
    const auto at = cursor.pos();
    if (size > cursor.remaining()) { error = {"truncated Dart Kernel direct string", at}; return false; }
    if (bytes_offset) *bytes_offset = at;
    const auto raw = cursor.span(at, size);
    if (!decode_kernel_wtf8(raw, out, surrogate_escaped, error, at)) return false;
    return cursor.skip(size, error, "direct string bytes");
}

bool zero_padding(std::span<const std::uint8_t> data, std::uint64_t begin,
                  std::uint64_t end, std::uint64_t max_padding,
                  KernelError& error, std::string_view what) {
    if (begin > end || end > data.size() || end - begin > max_padding) {
        error = {"invalid Dart Kernel " + std::string(what) + " padding geometry", begin};
        return false;
    }
    for (auto at = begin; at < end; ++at) {
        if (data[at] != 0) { error = {"nonzero Dart Kernel " + std::string(what) + " padding", at}; return false; }
    }
    return true;
}

bool parse_kernel_string_table(std::span<const std::uint8_t> data,
                               DartKernelInfo& out, KernelError& error) {
    constexpr std::uint32_t kMaxStrings = 1000000;
    constexpr std::uint64_t kMaxStringBytes = 64ull * 1024 * 1024;
    KernelCursor cursor(data, out.string_table_offset, out.component_index_offset);
    std::uint32_t count = 0;
    if (!cursor.u30(count, error)) return false;
    if (count > kMaxStrings) { error = {"Dart Kernel string count exceeds parser bound", out.string_table_offset}; return false; }
    std::vector<std::uint32_t> ends;
    ends.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t end = 0;
        const auto at = cursor.pos();
        if (!cursor.u30(end, error)) return false;
        if (end < previous || end > kMaxStringBytes) { error = {"Dart Kernel string-table end offsets are unsorted/out of bounds", at}; return false; }
        previous = end;
        ends.push_back(end);
    }
    const auto data_begin = cursor.pos();
    const auto total = ends.empty() ? 0u : ends.back();
    if (total != cursor.remaining()) { error = {"Dart Kernel string-table byte span does not end at componentIndexOffset", data_begin}; return false; }
    out.strings.clear();
    out.strings.reserve(count);
    previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto end = ends[i];
        const auto size = end - previous;
        const auto at = data_begin + previous;
        DartKernelString x;
        x.index = i; x.file_offset = at; x.byte_size = size;
        if (!decode_kernel_wtf8(data.subspan(static_cast<std::size_t>(at), size), x.text,
                                x.wtf8_surrogate_escaped, error, at)) return false;
        out.strings.push_back(std::move(x));
        previous = end;
    }
    out.string_count = count;
    return true;
}

std::string kernel_constant_tag_name(std::uint8_t tag) {
    switch (tag) {
        case 0: return "NullConstant";
        case 1: return "BoolConstant";
        case 2: return "IntConstant";
        case 3: return "DoubleConstant";
        case 4: return "StringConstant";
        case 5: return "SymbolConstant";
        case 6: return "MapConstant";
        case 7: return "ListConstant";
        case 8: return "InstanceConstant";
        case 9: return "InstantiationConstant";
        case 10: return "StaticTearOffConstant";
        case 11: return "TypeLiteralConstant";
        case 12: return "UnevaluatedConstant";
        case 13: return "SetConstant";
        case 14: return "TypedefTearOffConstant";
        case 15: return "ConstructorTearOffConstant";
        case 16: return "RedirectingFactoryTearOffConstant";
        case 17: return "RecordConstant";
        default: return {};
    }
}

bool parse_kernel_constant_index(std::span<const std::uint8_t> data,
                                 DartKernelInfo& out, KernelError& error) {
    constexpr std::uint32_t kMaxConstants = 1000000;
    KernelCursor table(data, out.constant_table_offset, out.constant_table_index_offset);
    std::uint32_t count = 0;
    if (!table.u30(count, error)) return false;
    if (count > kMaxConstants) { error = {"Dart Kernel constant count exceeds parser bound", out.constant_table_offset}; return false; }
    const auto header_end = table.pos();
    const auto index_bytes = out.canonical_name_table_offset - out.constant_table_index_offset;
    if (index_bytes != (std::uint64_t(count) + 1) * 4) {
        error = {"Dart Kernel constant-table index size/count mismatch", out.constant_table_index_offset};
        return false;
    }
    KernelCursor index(data, out.constant_table_index_offset, out.canonical_name_table_offset);
    std::vector<std::uint32_t> relative; relative.reserve(count);
    std::uint32_t previous = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t rel = 0; const auto at = index.pos();
        if (!index.be32(rel, error)) return false;
        if (rel < header_end - out.constant_table_offset || rel >= out.constant_table_index_offset - out.constant_table_offset ||
            (i != 0 && rel <= previous)) {
            error = {"Dart Kernel constant relative offsets are out of range/unsorted", at};
            return false;
        }
        previous = rel; relative.push_back(rel);
    }
    std::uint32_t stored_count = 0; const auto count_at = index.pos();
    if (!index.be32(stored_count, error)) return false;
    if (stored_count != count) { error = {"Dart Kernel constant-table index count mismatch", count_at}; return false; }
    if (index.pos() != out.canonical_name_table_offset) { error = {"Dart Kernel constant index does not end at canonicalNameTableOffset", index.pos()}; return false; }
    if (count && relative.front() != header_end - out.constant_table_offset) {
        error = {"Dart Kernel first constant offset does not follow constant count header", out.constant_table_index_offset};
        return false;
    }
    out.constants.clear(); out.constants.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        DartKernelConstant x; x.index = i; x.file_offset = out.constant_table_offset + relative[i];
        x.end_offset = (i + 1 < count) ? out.constant_table_offset + relative[i + 1] : out.constant_table_index_offset;
        if (x.file_offset >= x.end_offset || x.end_offset > data.size()) { error = {"Dart Kernel constant range is empty/out of bounds", x.file_offset}; return false; }
        x.tag = data[x.file_offset]; x.tag_name = kernel_constant_tag_name(x.tag);
        if (x.tag_name.empty()) { error = {"unknown Dart Kernel constant tag", x.file_offset}; return false; }
        KernelCursor value_cursor(data, x.file_offset + 1, x.end_offset);
        if (x.tag == 0) {
            if (value_cursor.remaining() != 0) { error = {"Dart Kernel NullConstant has trailing payload", value_cursor.pos()}; return false; }
            x.simple_value_decoded = true; x.value = "null";
        } else if (x.tag == 1) {
            std::uint8_t value = 0;
            if (!value_cursor.byte(value, error)) return false;
            if (value > 1) { error = {"Dart Kernel BoolConstant value is not 0/1", x.file_offset + 1}; return false; }
            if (value_cursor.remaining() != 0) { error = {"Dart Kernel BoolConstant has trailing payload", value_cursor.pos()}; return false; }
            x.simple_value_decoded = true; x.value = value ? "true" : "false";
        } else if (x.tag == 4) {
            std::uint32_t ref = 0; const auto ref_at = value_cursor.pos();
            if (!value_cursor.u30(ref, error)) return false;
            if (ref >= out.strings.size()) { error = {"Dart Kernel StringConstant string reference is out of range", ref_at}; return false; }
            if (value_cursor.remaining() != 0) { error = {"Dart Kernel StringConstant has trailing payload", value_cursor.pos()}; return false; }
            x.simple_value_decoded = true; x.value = out.strings[ref].text;
        }
        out.constants.push_back(std::move(x));
    }
    out.constant_count = count;
    return true;
}

bool parse_kernel_canonical_table(std::span<const std::uint8_t> data,
                                  DartKernelInfo& out, KernelError& error) {
    constexpr std::uint32_t kMaxCanonicalNames = 1000000;
    constexpr std::size_t kMaxPath = 16384;
    KernelCursor cursor(data, out.canonical_name_table_offset, out.metadata_payloads_offset);
    std::uint32_t count = 0;
    if (!cursor.u30(count, error)) return false;
    if (count > kMaxCanonicalNames) { error = {"Dart Kernel canonical-name count exceeds parser bound", out.canonical_name_table_offset}; return false; }
    out.canonical_names.clear(); out.canonical_names.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        DartKernelCanonicalName x; x.index = i; x.file_offset = cursor.pos();
        if (!cursor.u30(x.parent_reference, error) || !cursor.u30(x.string_reference, error)) return false;
        if (x.parent_reference > i) { error = {"Dart Kernel canonical parent is a forward/out-of-range reference", x.file_offset}; return false; }
        if (x.string_reference >= out.strings.size()) { error = {"Dart Kernel canonical string reference is out of range", x.file_offset}; return false; }
        x.name = out.strings[x.string_reference].text;
        if (x.parent_reference == 0) x.path = x.name;
        else {
            const auto& parent = out.canonical_names[x.parent_reference - 1];
            if (parent.path.size() + 2 + x.name.size() <= kMaxPath) x.path = parent.path + "::" + x.name;
            else { x.path = parent.path.substr(0, std::min(parent.path.size(), kMaxPath - 5)) + "::..."; x.path_truncated = true; }
        }
        out.canonical_names.push_back(std::move(x));
    }
    if (!zero_padding(data, cursor.pos(), out.metadata_payloads_offset, 7, error, "canonical-name")) return false;
    out.canonical_name_count = count;
    return true;
}

bool parse_kernel_source_table(std::span<const std::uint8_t> data,
                               DartKernelInfo& out, KernelError& error) {
    constexpr std::uint32_t kMaxSources = 100000;
    constexpr std::uint64_t kMaxSourceBytes = 256ull * 1024 * 1024;
    constexpr std::uint64_t kMaxLineStarts = 2000000;
    KernelCursor cursor(data, out.source_table_offset, out.constant_table_offset);
    std::uint32_t count = 0;
    if (!cursor.be32(count, error)) return false;
    if (count > kMaxSources) { error = {"Dart Kernel source count exceeds parser bound", out.source_table_offset}; return false; }
    out.sources.clear(); out.sources.reserve(count);
    std::vector<std::uint64_t> starts; starts.reserve(count);
    std::set<std::string> seen_uris;
    std::uint64_t total_source_bytes = 0, total_line_starts = 0;
    for (std::uint32_t i = 0; i < count; ++i) {
        DartKernelSource src; src.index = i; src.file_offset = cursor.pos(); starts.push_back(src.file_offset);
        if (!read_kernel_direct_string(cursor, src.uri, src.uri_wtf8_surrogate_escaped, error)) return false;
        if (!seen_uris.insert(src.uri).second) { error = {"duplicate Dart Kernel source URI", src.file_offset}; return false; }
        if (!cursor.u30(src.source_code_size, error)) return false;
        src.source_code_offset = cursor.pos();
        total_source_bytes += src.source_code_size;
        if (total_source_bytes > kMaxSourceBytes) { error = {"Dart Kernel embedded source bytes exceed parser bound", src.source_code_offset}; return false; }
        if (!cursor.skip(src.source_code_size, error, "embedded source bytes")) return false;
        if (!cursor.u30(src.line_count, error)) return false;
        total_line_starts += src.line_count;
        if (total_line_starts > kMaxLineStarts) { error = {"Dart Kernel line-start count exceeds parser bound", cursor.pos()}; return false; }
        src.line_starts.reserve(src.line_count);
        std::uint32_t line = 0;
        for (std::uint32_t n = 0; n < src.line_count; ++n) {
            std::uint32_t delta = 0; const auto at = cursor.pos();
            if (!cursor.u30(delta, error)) return false;
            if (delta > std::numeric_limits<std::uint32_t>::max() - line) { error = {"Dart Kernel line-start delta overflows", at}; return false; }
            line += delta; src.line_starts.push_back(line);
        }
        if (!read_kernel_direct_string(cursor, src.import_uri, src.import_uri_wtf8_surrogate_escaped, error)) return false;
        if (!cursor.u30(src.coverage_reference_count, error)) return false;
        if (src.coverage_reference_count > out.canonical_names.size()) { error = {"Dart Kernel source coverage reference count is unreasonable", cursor.pos()}; return false; }
        for (std::uint32_t n = 0; n < src.coverage_reference_count; ++n) {
            std::uint32_t ref = 0; const auto at = cursor.pos();
            if (!cursor.u30(ref, error)) return false;
            if (ref == 0 || ref > out.canonical_names.size()) { error = {"Dart Kernel source coverage canonical reference is out of range", at}; return false; }
        }
        out.sources.push_back(std::move(src));
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t indexed = 0; const auto at = cursor.pos();
        if (!cursor.be32(indexed, error)) return false;
        if (indexed != starts[i]) { error = {"Dart Kernel source random-access index does not match record offset", at}; return false; }
    }
    if (cursor.pos() != out.constant_table_offset) { error = {"Dart Kernel source table does not end at constantTableOffset", cursor.pos()}; return false; }
    out.source_count = count;
    return true;
}

bool parse_kernel_procedure_prefix(std::span<const std::uint8_t> data,
                                   const DartKernelInfo& out,
                                   const DartKernelSerializedRange& range,
                                   DartKernelProcedure& proc,
                                   KernelError& error) {
    constexpr std::uint8_t kProcedureTag = 6;
    proc.index = range.index; proc.file_offset = range.file_offset; proc.end_offset = range.end_offset;
    KernelCursor cursor(data, range.file_offset, range.end_offset);
    std::uint8_t tag = 0;
    if (!cursor.byte(tag, error)) return false;
    if (tag != kProcedureTag) { error = {"Dart Kernel procedure serialized range does not start with Tag.Procedure", range.file_offset}; return false; }
    const auto canonical_at = cursor.pos();
    if (!cursor.u30(proc.canonical_reference, error) || proc.canonical_reference == 0 || proc.canonical_reference > out.canonical_names.size()) {
        error = {"Dart Kernel procedure canonical reference is out of range", canonical_at}; return false;
    }
    const auto& canonical = out.canonical_names[proc.canonical_reference - 1];
    proc.canonical_path = canonical.path; proc.name = canonical.name;
    const auto uri_at = cursor.pos();
    if (!cursor.u30(proc.file_uri_reference, error) || proc.file_uri_reference >= out.sources.size()) {
        error = {"Dart Kernel procedure file-URI reference is out of range", uri_at}; return false;
    }
    proc.file_uri = out.sources[proc.file_uri_reference].uri;
    auto read_source_offset = [&](std::int64_t& value) -> bool {
        std::uint32_t raw = 0;
        if (!cursor.u30(raw, error)) return false;
        value = std::int64_t(raw) - 1;
        return true;
    };
    if (!read_source_offset(proc.source_start_offset) || !read_source_offset(proc.source_name_offset) || !read_source_offset(proc.source_end_offset)) return false;
    if (!cursor.byte(proc.kind, error) || !cursor.byte(proc.stub_kind, error)) return false;
    if (!cursor.u30(proc.flags, error)) return false;
    proc.prefix_end_offset = cursor.pos();
    if (proc.prefix_end_offset >= range.end_offset) { error = {"Dart Kernel procedure fixed prefix consumes entire serialized range", proc.prefix_end_offset}; return false; }
    return true;
}

bool parse_kernel_library_prefixes(std::span<const std::uint8_t> data,
                                   DartKernelInfo& out, KernelError& error) {
    constexpr std::uint32_t kMaxLibraryIndexedNodes = 1000000;
    out.libraries.clear(); out.libraries.reserve(out.library_count);
    std::uint64_t aggregate_indexed = 0;
    auto be32_at = [&](std::uint64_t off, std::uint32_t& value) -> bool {
        if (off > data.size() || 4 > data.size() - off) { error = {"truncated Dart Kernel library index UInt32", off}; return false; }
        value = (std::uint32_t(data[off]) << 24) | (std::uint32_t(data[off + 1]) << 16) |
                (std::uint32_t(data[off + 2]) << 8) | std::uint32_t(data[off + 3]);
        return true;
    };
    for (std::uint32_t i = 0; i < out.library_count; ++i) {
        const auto start = out.library_offsets[i], end = out.library_offsets[i + 1];
        DartKernelLibrary lib; lib.index = i; lib.file_offset = start; lib.end_offset = end;
        if (start >= end || end > out.source_table_offset || end - start < 16) { error = {"invalid Dart Kernel library range", start}; return false; }
        if (!be32_at(end - 4, lib.procedure_count)) return false;
        aggregate_indexed += lib.procedure_count;
        if (aggregate_indexed > kMaxLibraryIndexedNodes) { error = {"Dart Kernel library procedure/class index count exceeds parser bound", end - 4}; return false; }
        const auto proc_words = std::uint64_t(lib.procedure_count) + 3;
        if (proc_words > (end - start) / 4) { error = {"Dart Kernel library procedure index exceeds library range", end - 4}; return false; }
        const auto class_count_at = end - proc_words * 4;
        if (!be32_at(class_count_at, lib.class_count)) return false;
        aggregate_indexed += lib.class_count;
        if (aggregate_indexed > kMaxLibraryIndexedNodes) { error = {"Dart Kernel library procedure/class index count exceeds parser bound", class_count_at}; return false; }
        const auto total_words = std::uint64_t(lib.procedure_count) + lib.class_count + 4;
        if (total_words > (end - start) / 4) { error = {"Dart Kernel library class/procedure index overlaps body", class_count_at}; return false; }
        lib.index_offset = end - total_words * 4;

        auto validate_offsets = [&](std::uint64_t at, std::uint32_t count, std::string_view what) -> bool {
            std::uint64_t previous = 0;
            for (std::uint32_t n = 0; n < count; ++n) {
                std::uint32_t value = 0; const auto field = at + std::uint64_t(n) * 4;
                if (!be32_at(field, value)) return false;
                if (value < start || value > lib.index_offset || (n != 0 && value <= previous)) {
                    error = {"Dart Kernel library " + std::string(what) + " offsets are out of range/unsorted", field}; return false;
                }
                previous = value;
            }
            return true;
        };
        const auto class_offsets_at = lib.index_offset;
        if (!validate_offsets(class_offsets_at, lib.class_count + 1, "class")) return false;
        std::vector<std::uint32_t> class_offsets; class_offsets.reserve(std::uint64_t(lib.class_count) + 1);
        for (std::uint32_t n = 0; n < lib.class_count + 1; ++n) {
            std::uint32_t value = 0; if (!be32_at(class_offsets_at + std::uint64_t(n) * 4, value)) return false; class_offsets.push_back(value);
        }
        const auto stored_class_count_at = class_offsets_at + std::uint64_t(lib.class_count + 1) * 4;
        std::uint32_t stored_class_count = 0;
        if (!be32_at(stored_class_count_at, stored_class_count) || stored_class_count != lib.class_count) {
            error = {"Dart Kernel library class count/index mismatch", stored_class_count_at}; return false;
        }
        const auto procedure_offsets_at = stored_class_count_at + 4;
        if (!validate_offsets(procedure_offsets_at, lib.procedure_count + 1, "procedure")) return false;
        std::vector<std::uint32_t> procedure_offsets; procedure_offsets.reserve(std::uint64_t(lib.procedure_count) + 1);
        for (std::uint32_t n = 0; n < lib.procedure_count + 1; ++n) {
            std::uint32_t value = 0; if (!be32_at(procedure_offsets_at + std::uint64_t(n) * 4, value)) return false; procedure_offsets.push_back(value);
        }
        lib.class_ranges.reserve(lib.class_count);
        for (std::uint32_t n = 0; n < lib.class_count; ++n) lib.class_ranges.push_back({n, class_offsets[n], class_offsets[n + 1]});
        lib.procedure_ranges.reserve(lib.procedure_count);
        for (std::uint32_t n = 0; n < lib.procedure_count; ++n) lib.procedure_ranges.push_back({n, procedure_offsets[n], procedure_offsets[n + 1]});
        lib.procedures.reserve(lib.procedure_count);
        for (const auto& range : lib.procedure_ranges) {
            DartKernelProcedure proc;
            if (!parse_kernel_procedure_prefix(data, out, range, proc, error)) return false;
            lib.procedures.push_back(std::move(proc));
        }
        std::uint32_t stored_procedure_count = 0;
        if (!be32_at(end - 4, stored_procedure_count) || stored_procedure_count != lib.procedure_count) {
            error = {"Dart Kernel library procedure count/index mismatch", end - 4}; return false;
        }

        KernelCursor cursor(data, start, lib.index_offset);
        if (!cursor.byte(lib.flags, error) || !cursor.u30(lib.language_major, error) || !cursor.u30(lib.language_minor, error)) return false;
        if (lib.language_major > 1000 || lib.language_minor > 1000) { error = {"implausible Dart Kernel library language version", start + 1}; return false; }
        if (!cursor.u30(lib.canonical_reference, error) || lib.canonical_reference == 0 || lib.canonical_reference > out.canonical_names.size()) {
            error = {"Dart Kernel library canonical reference is out of range", cursor.pos()}; return false;
        }
        const auto& canonical = out.canonical_names[lib.canonical_reference - 1];
        if (canonical.parent_reference != 0) { error = {"Dart Kernel library canonical reference is not a root child", cursor.pos()}; return false; }
        lib.import_uri = canonical.path;
        if (!cursor.u30(lib.name_reference, error) || lib.name_reference >= out.strings.size()) {
            error = {"Dart Kernel library name string reference is out of range", cursor.pos()}; return false;
        }
        lib.name = out.strings[lib.name_reference].text;
        if (!cursor.u30(lib.file_uri_reference, error) || lib.file_uri_reference >= out.sources.size()) {
            error = {"Dart Kernel library file-URI reference is out of range", cursor.pos()}; return false;
        }
        lib.file_uri = out.sources[lib.file_uri_reference].uri;
        if (!cursor.u30(lib.problem_count, error) || lib.problem_count > 10000) {
            error = {"Dart Kernel library problem list count exceeds parser bound", cursor.pos()}; return false;
        }
        for (std::uint32_t n = 0; n < lib.problem_count; ++n) {
            std::string ignored; bool surrogate = false;
            if (!read_kernel_direct_string(cursor, ignored, surrogate, error)) return false;
        }
        lib.prefix_end_offset = cursor.pos();
        if (lib.prefix_end_offset > lib.index_offset) { error = {"Dart Kernel library prefix overlaps tail index", lib.prefix_end_offset}; return false; }
        out.libraries.push_back(std::move(lib));
    }
    return true;
}

bool parse_kernel_deep_metadata(std::span<const std::uint8_t> data,
                                DartKernelInfo& out, KernelError& error) {
    if (!parse_kernel_string_table(data, out, error)) return false;
    if (!parse_kernel_constant_index(data, out, error)) return false;
    if (!parse_kernel_canonical_table(data, out, error)) return false;
    if (!parse_kernel_source_table(data, out, error)) return false;
    if (!parse_kernel_library_prefixes(data, out, error)) return false;
    return true;
}

}  // namespace

DartSnapshotInfo parse_dart_snapshot(std::span<const std::uint8_t> data,
                                     std::uint64_t file_offset,
                                     std::uint64_t available_size) {
    DartSnapshotInfo out;
    out.file_offset = file_offset;
    if (file_offset > data.size()) return out;
    if (available_size == 0) available_size = data.size() - file_offset;
    available_size = std::min<std::uint64_t>(available_size, data.size() - file_offset);
    out.available_size = available_size;
    if (available_size < 4) return out;
    const auto u32le = [&](std::uint64_t off) {
        return std::uint32_t(data[off]) | (std::uint32_t(data[off + 1]) << 8) |
               (std::uint32_t(data[off + 2]) << 16) | (std::uint32_t(data[off + 3]) << 24);
    };
    if (u32le(file_offset) != kSnapshotMagic) return out;
    out.candidate = true;
    if (available_size < kSnapshotHeaderSize) {
        out.error = "truncated Dart snapshot header";
        out.error_offset = file_offset;
        return out;
    }
    const auto i64le = [&](std::uint64_t off) -> std::int64_t {
        std::uint64_t v = 0;
        for (unsigned i = 0; i < 8; ++i) v |= std::uint64_t(data[off + i]) << (i * 8);
        return static_cast<std::int64_t>(v);
    };
    out.stored_length = i64le(file_offset + 4);
    out.kind = i64le(file_offset + 12);
    out.kind_name = snapshot_kind_name(out.kind);
    if (out.stored_length < static_cast<std::int64_t>(kSnapshotHeaderSize + kSnapshotHashSize + 1 - 4)) {
        out.error = "Dart snapshot stored length is too small";
        out.error_offset = file_offset + 4;
        return out;
    }
    const auto stored = static_cast<std::uint64_t>(out.stored_length);
    if (stored > std::numeric_limits<std::uint64_t>::max() - 4) {
        out.error = "Dart snapshot stored length overflows";
        out.error_offset = file_offset + 4;
        return out;
    }
    out.length = stored + 4;
    if (out.length > available_size) {
        out.error = "Dart snapshot length exceeds containing bytes";
        out.error_offset = file_offset + 4;
        return out;
    }
    if (out.kind < 1 || out.kind > 5) {
        out.error = "unsupported/invalid Dart snapshot kind";
        out.error_offset = file_offset + 12;
        return out;
    }
    const auto hash_off = file_offset + kSnapshotHeaderSize;
    if (!lower_hex32(data.subspan(hash_off, kSnapshotHashSize))) {
        out.error = "Dart snapshot version hash is not a 32-byte lowercase MD5 hex string";
        out.error_offset = hash_off;
        return out;
    }
    out.snapshot_hash.assign(reinterpret_cast<const char*>(data.data() + hash_off), kSnapshotHashSize);
    const auto features_off = hash_off + kSnapshotHashSize;
    const auto snapshot_end = file_offset + out.length;
    const auto max_end = std::min<std::uint64_t>(snapshot_end, features_off + kMaxFeatures + 1);
    std::uint64_t end = features_off;
    while (end < max_end && data[end] != 0) {
        if (!printable_feature_char(data[end])) {
            out.error = "Dart snapshot features contain non-printable bytes";
            out.error_offset = end;
            return out;
        }
        ++end;
    }
    if (end == max_end || data[end] != 0) {
        out.error = snapshot_end - features_off > kMaxFeatures
            ? "Dart snapshot features exceed bounded parser limit"
            : "Dart snapshot features are not NUL terminated within snapshot length";
        out.error_offset = end;
        return out;
    }
    out.features.assign(reinterpret_cast<const char*>(data.data() + features_off), end - features_off);
    if (out.features.empty()) {
        out.error = "Dart snapshot features string is empty";
        out.error_offset = features_off;
        return out;
    }
    out.feature_tokens = split_features(out.features);
    if (out.feature_tokens.empty()) {
        out.error = "Dart snapshot features contain no tokens";
        out.error_offset = features_off;
        return out;
    }
    out.valid = true;
    return out;
}

DartKernelInfo parse_dart_kernel(std::span<const std::uint8_t> data) {
    DartKernelInfo out;
    const auto be32 = [&](std::uint64_t off) -> std::uint32_t {
        if (off > data.size() || 4 > data.size() - off) return 0;
        return (std::uint32_t(data[off]) << 24) | (std::uint32_t(data[off + 1]) << 16) |
               (std::uint32_t(data[off + 2]) << 8) | std::uint32_t(data[off + 3]);
    };
    if (data.size() < 4 || be32(0) != kKernelMagic) return out;
    out.candidate = true;
    // Kernel ComponentFile fixed-width index words are big-endian. Current 3.13
    // format has 9 fixed fields before (library_count + 1) offsets and 2 after.
    constexpr std::uint64_t kFixedBeforeLibraries = 9;
    constexpr std::uint64_t kFixedAfterLibraries = 2;
    constexpr std::uint64_t kMinimumFixedWords = kFixedBeforeLibraries + 1 + kFixedAfterLibraries;
    if (data.size() < 8 + kMinimumFixedWords * 4) {
        out.error = "truncated Dart Kernel component";
        return out;
    }
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        out.error = "Dart Kernel component exceeds 32-bit self-index format";
        return out;
    }
    out.format_version = be32(4);
    if (out.format_version == 0 || out.format_version > 10000) {
        out.error = "implausible Dart Kernel binary format version";
        out.error_offset = 4;
        return out;
    }
    out.deep_metadata_supported = out.format_version == 138 || out.format_version == 139;
    if (out.deep_metadata_supported) {
        if (data.size() < 18) {
            out.error = "truncated Dart Kernel SDK hash";
            out.error_offset = 8;
            return out;
        }
        out.sdk_hash.assign(reinterpret_cast<const char*>(data.data() + 8), 10);
        const bool hash_ok = std::all_of(out.sdk_hash.begin(), out.sdk_hash.end(), [](unsigned char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
        if (!hash_ok) {
            out.error = "Dart Kernel SDK hash is not a 10-byte lowercase Git hex string";
            out.error_offset = 8;
            return out;
        }
    }
    out.library_count = be32(data.size() - 8);
    out.component_file_size = be32(data.size() - 4);
    if (out.component_file_size != data.size()) {
        out.error = "Dart Kernel componentFileSize does not match physical input size";
        out.error_offset = data.size() - 4;
        return out;
    }
    if (out.library_count > 100000) {
        out.error = "unreasonable Dart Kernel library count";
        out.error_offset = data.size() - 8;
        return out;
    }
    const auto fixed_words = kFixedBeforeLibraries + (std::uint64_t(out.library_count) + 1) + kFixedAfterLibraries;
    if (fixed_words > std::numeric_limits<std::uint32_t>::max() || fixed_words * 4 > data.size()) {
        out.error = "Dart Kernel component index size/library count mismatch";
        out.error_offset = data.size() - 8;
        return out;
    }
    out.component_index_words = static_cast<std::uint32_t>(fixed_words);
    const auto fixed_start = data.size() - fixed_words * 4;
    if (fixed_start < 8) {
        out.error = "Dart Kernel component index overlaps header";
        out.error_offset = fixed_start;
        return out;
    }

    out.source_table_offset = be32(fixed_start + 0 * 4);
    out.constant_table_offset = be32(fixed_start + 1 * 4);
    out.constant_table_index_offset = be32(fixed_start + 2 * 4);
    out.canonical_name_table_offset = be32(fixed_start + 3 * 4);
    out.metadata_payloads_offset = be32(fixed_start + 4 * 4);
    out.metadata_mappings_offset = be32(fixed_start + 5 * 4);
    out.string_table_offset = be32(fixed_start + 6 * 4);
    out.component_index_offset = be32(fixed_start + 7 * 4);
    out.main_method_reference = be32(fixed_start + 8 * 4);

    if (out.component_index_offset < 8 || out.component_index_offset > fixed_start) {
        out.error = "invalid Dart Kernel componentIndexOffset";
        out.error_offset = fixed_start + 7 * 4;
        return out;
    }
    const auto padding = fixed_start - out.component_index_offset;
    if (padding > 7 || data.size() % 8 != 0) {
        out.error = "invalid Dart Kernel component-index alignment padding";
        out.error_offset = out.component_index_offset;
        return out;
    }
    for (auto off = out.component_index_offset; off < fixed_start; ++off) {
        if (data[off] != 0) {
            out.error = "nonzero Dart Kernel component-index alignment padding";
            out.error_offset = off;
            return out;
        }
    }

    const std::array<std::pair<std::uint64_t, const char*>, 7> tables = {{
        {out.source_table_offset, "sourceTableOffset"},
        {out.constant_table_offset, "constantTableOffset"},
        {out.constant_table_index_offset, "constantTableIndexOffset"},
        {out.canonical_name_table_offset, "canonicalNameTableOffset"},
        {out.metadata_payloads_offset, "metadataPayloadsOffset"},
        {out.metadata_mappings_offset, "metadataMappingsOffset"},
        {out.string_table_offset, "stringTableOffset"}
    }};
    std::uint64_t previous_table = 0;
    for (std::size_t i = 0; i < tables.size(); ++i) {
        const auto [value, name] = tables[i];
        if (value < 8 || value > out.component_index_offset) {
            out.error = std::string("Dart Kernel ") + name + " is outside component data";
            out.error_offset = fixed_start + std::uint64_t(i) * 4;
            return out;
        }
        if (i != 0 && value < previous_table) {
            out.error = "Dart Kernel table offsets are not in writer order";
            out.error_offset = fixed_start + std::uint64_t(i) * 4;
            return out;
        }
        previous_table = value;
    }

    out.library_offsets.reserve(std::uint64_t(out.library_count) + 1);
    const auto libraries_start = fixed_start + kFixedBeforeLibraries * 4;
    std::uint64_t previous_library = 0;
    for (std::uint32_t i = 0; i < out.library_count + 1; ++i) {
        const auto at = libraries_start + std::uint64_t(i) * 4;
        const auto value = std::uint64_t(be32(at));
        if (value < 8 || value > out.source_table_offset || (i != 0 && value <= previous_library)) {
            out.error = "Dart Kernel library offsets are out of bounds or unsorted";
            out.error_offset = at;
            return out;
        }
        previous_library = value;
        out.library_offsets.push_back(value);
    }
    if (out.library_offsets.empty() || out.library_offsets.back() != out.source_table_offset) {
        out.error = "Dart Kernel final library boundary does not equal sourceTableOffset";
        out.error_offset = libraries_start + std::uint64_t(out.library_count) * 4;
        return out;
    }
    if (be32(data.size() - 8) != out.library_count || be32(data.size() - 4) != data.size()) {
        out.error = "Dart Kernel trailing library-count/file-size fields changed during index parse";
        out.error_offset = data.size() - 8;
        return out;
    }

    out.string_hints = collect_ascii_hints_range(data, 8, out.component_index_offset - 8);
    if (out.deep_metadata_supported) {
        KernelError deep_error;
        if (!parse_kernel_deep_metadata(data, out, deep_error)) {
            out.deep_metadata_error = deep_error.message;
            out.deep_metadata_error_offset = deep_error.offset;
            out.error = "Dart Kernel deep metadata validation failed: " + deep_error.message;
            out.error_offset = deep_error.offset;
            return out;
        }
        out.deep_metadata_complete = true;
    }
    out.valid = true;
    return out;
}

DartInfo detect_dart(std::span<const std::uint8_t> data, const ElfInfo& elf) {
    DartInfo out;
    out.raw_snapshot = parse_dart_snapshot(data);
    out.kernel = parse_dart_kernel(data);
    if (out.kernel.candidate) {
        out.candidate = true;
        if (out.kernel.valid) out.valid = true;
        else { out.error = out.kernel.error; out.error_offset = out.kernel.error_offset; }
    }
    if (out.raw_snapshot.candidate) {
        out.candidate = true;
        if (out.raw_snapshot.valid) out.valid = true;
        else {
            out.error = out.raw_snapshot.error;
            out.error_offset = out.raw_snapshot.error_offset;
        }
    }
    if (!elf.valid) return out;

    const auto layout = parse_program_layout(data, elf);
    if (!layout.valid) return out;
    auto dyn = parse_dynamic(data, elf, layout);
    if (!dyn.present) return out;
    if (!dyn.valid) {
        // Do not turn every unrelated ELF dynamic-table issue into a Dart candidate.
        return out;
    }
    std::string sym_error;
    std::uint64_t sym_error_offset = 0;
    const auto syms = parse_dyn_symbols(data, elf, layout, dyn, sym_error, sym_error_offset);
    if (!sym_error.empty()) return out;
    bool names_present = false;
    for (const auto& s : syms) if (target_symbol(s.name)) { names_present = true; break; }
    if (!names_present) return out;

    auto& aot = out.aot;
    aot.candidate = true;
    if (elf.type != 3) {
        aot.error = "Dart AOT snapshot symbols are present but ELF type is not ET_DYN";
        out.candidate = true;
        out.error = aot.error;
        return out;
    }
    out.candidate = true;
    aot.section_table_independent = true;
    aot.symbol_parse_complete = true;
    aot.dynamic_symbol_count = static_cast<std::uint32_t>(std::min<std::uint64_t>(dyn.symbol_count, std::numeric_limits<std::uint32_t>::max()));
    aot.architecture = elf_arch(elf.machine);
    std::set<std::string> target_names;
    for (const auto& s : syms) {
        if (!target_symbol(s.name)) continue;
        if (!target_names.insert(s.name).second) {
            aot.error = "duplicate Dart AOT target dynamic symbol: " + s.name;
            out.error = aot.error;
            return out;
        }
        const auto binding = std::uint8_t(s.info >> 4), type = std::uint8_t(s.info & 0x0f);
        if ((binding != 1 && binding != 2) || type != 1) {
            aot.error = "Dart AOT target symbol is not GLOBAL/WEAK OBJECT: " + s.name;
            out.error = aot.error;
            return out;
        }
        std::string hash_error;
        std::uint64_t hash_error_offset = 0;
        if (!target_hash_resolves(data, elf, layout, dyn, syms, s, hash_error, hash_error_offset)) {
            aot.error = hash_error.empty() ? "Dart AOT target dynamic symbol is not reachable through ELF hash lookup: " + s.name : hash_error;
            aot.error_offset = hash_error_offset;
            out.error = aot.error;
            out.error_offset = aot.error_offset;
            return out;
        }
        DartAotSymbol x;
        if (!validate_symbol_geometry(aot, layout, s, x)) {
            out.error = aot.error;
            out.error_offset = aot.error_offset;
            return out;
        }
        aot.symbols.push_back(std::move(x));
    }

    const auto* standalone_data = symbol(aot, "_kDartSnapshotData");
    const auto* standalone_text = symbol(aot, "_kDartSnapshotText");
    const auto* vm_data = symbol(aot, "kDartVmSnapshotData");
    const auto* vm_text = symbol(aot, "kDartVmSnapshotInstructions");
    const auto* isolate_data = symbol(aot, "kDartIsolateSnapshotData");
    const auto* isolate_text = symbol(aot, "kDartIsolateSnapshotInstructions");
    aot.standalone = standalone_data || standalone_text;
    aot.flutter_symbols = vm_data || vm_text || isolate_data || isolate_text;

    if (aot.standalone) {
        aot.variant = "standalone Dart AOT ELF";
        if (!standalone_data || !standalone_text) {
            aot.error = "standalone Dart AOT dynamic symbol pair is incomplete";
        } else if (!validate_aot_data_symbol(aot, data, *standalone_data, "_kDartSnapshotData")) {
            // error set by helper
        } else if (!validate_aot_text_symbol(aot, *standalone_text, "_kDartSnapshotText")) {
            // error set by helper
        } else {
            check_architecture_feature(aot);
            if (aot.error.empty() && validate_optional_support_symbols(aot, data)) {
                collect_ascii_hints(aot, data, *standalone_data);
                aot.valid = true;
            }
        }
    }
    if (aot.flutter_symbols && !aot.valid) {
        aot.variant = "Flutter-style Dart AOT ELF";
        // Current Flutter engine knows all four names, but packaging can source VM and app
        // snapshots independently. Require complete pairs for every role that is present,
        // and at least one complete data+instructions pair; do not require all four blindly.
        bool any_pair = false;
        if ((vm_data != nullptr) != (vm_text != nullptr)) {
            aot.error = "Flutter VM snapshot data/instructions symbol pair is incomplete";
        } else if ((isolate_data != nullptr) != (isolate_text != nullptr)) {
            aot.error = "Flutter isolate snapshot data/instructions symbol pair is incomplete";
        } else {
            if (vm_data && vm_text) {
                any_pair = true;
                if (!validate_aot_data_symbol(aot, data, *vm_data, "kDartVmSnapshotData") ||
                    !validate_aot_text_symbol(aot, *vm_text, "kDartVmSnapshotInstructions")) {
                    any_pair = false;
                }
            }
            if (aot.error.empty() && isolate_data && isolate_text) {
                any_pair = true;
                if (!validate_aot_data_symbol(aot, data, *isolate_data, "kDartIsolateSnapshotData") ||
                    !validate_aot_text_symbol(aot, *isolate_text, "kDartIsolateSnapshotInstructions")) {
                    any_pair = false;
                }
            }
            if (aot.error.empty() && any_pair) {
                check_architecture_feature(aot);
                if (aot.error.empty() && validate_optional_support_symbols(aot, data)) {
                    if (isolate_data) collect_ascii_hints(aot, data, *isolate_data);
                    else if (vm_data) collect_ascii_hints(aot, data, *vm_data);
                    aot.valid = true;
                }
            }
            if (aot.error.empty() && !any_pair) aot.error = "no complete Flutter snapshot data/instructions pair";
        }
    }

    if (!aot.standalone && !aot.flutter_symbols && !aot.symbols.empty() && aot.error.empty()) {
        aot.error = "Dart support symbols are present without a snapshot data/instructions pair";
    }

    if (aot.valid) out.valid = true;
    else if (!aot.error.empty()) {
        out.error = aot.error;
        out.error_offset = aot.error_offset;
    }
    return out;
}

}  // namespace prts
