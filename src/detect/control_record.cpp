#include "prts/control_record.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace prts {
namespace {

constexpr std::uint32_t PT_LOAD_VALUE = 1;
constexpr std::uint32_t PT_GNU_RELRO_VALUE = 0x6474e552u;
constexpr std::uint32_t PF_X_VALUE = 1;
constexpr std::uint32_t PF_W_VALUE = 2;
constexpr std::uint32_t R_X86_64_64_VALUE = 1;
constexpr std::uint32_t R_X86_64_RELATIVE_VALUE = 8;
constexpr std::size_t MAX_FUNCTION_BYTES = 0x10000;
constexpr std::size_t MAX_FUNCTION_INSTRUCTIONS = 8192;
constexpr std::size_t MAX_BOUNDED_FUNCTIONS = 200000;
constexpr std::size_t MAX_INDIRECT_CALLS_PER_FUNCTION = 256;
constexpr std::uint32_t MAX_RECORD_STRIDE = 0x100;
constexpr std::uint32_t MAX_RECORD_COUNT = 256;
constexpr std::uint64_t MAX_TABLE_BYTES = 1u << 20;
constexpr std::size_t MAX_CANDIDATE_EVALUATIONS = 8192;

struct FunctionRange {
    std::uint64_t begin_va = 0;
    std::uint64_t end_va = 0;
    std::uint64_t file_offset = 0;
};

struct Decoded {
    std::uint64_t va = 0;
    std::uint64_t file_offset = 0;
    ZydisDecodedInstruction zi{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{};
};

ZydisRegister large(ZydisRegister r) {
    if (r == ZYDIS_REGISTER_NONE) return r;
    return ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, r);
}

std::optional<std::uint64_t> add_signed(std::uint64_t base, std::int64_t delta) {
    // x86-64 address/register arithmetic is modulo 2^64. This is needed for
    // compiler-generated negative-bias iterators such as base=-N plus an
    // absolute displacement into a table.
    return base + static_cast<std::uint64_t>(delta);
}

std::optional<std::uint64_t> va_to_file(const ElfInfo& elf, std::uint64_t va, std::uint64_t size = 1) {
    for (const auto& s : elf.segments) {
        if (s.type != PT_LOAD_VALUE || va < s.address) continue;
        const auto delta = va - s.address;
        if (delta >= s.file_size || size > s.file_size - delta) continue;
        return s.offset + delta;
    }
    return {};
}

const ElfSegment* load_for_range(const ElfInfo& elf, std::uint64_t va, std::uint64_t size) {
    for (const auto& s : elf.segments) {
        if (s.type != PT_LOAD_VALUE || va < s.address) continue;
        const auto delta = va - s.address;
        if (delta <= s.memory_size && size <= s.memory_size - delta) return &s;
    }
    return nullptr;
}

bool executable_va(const ElfInfo& elf, std::uint64_t va) {
    for (const auto& s : elf.segments) {
        if (s.type != PT_LOAD_VALUE || !(s.flags & PF_X_VALUE) || va < s.address) continue;
        if (va - s.address < s.memory_size) return true;
    }
    return false;
}

bool nonexec_file_backed(const ElfInfo& elf, std::uint64_t va, std::uint64_t size) {
    const auto* s = load_for_range(elf, va, size);
    if (!s || (s->flags & PF_X_VALUE)) return false;
    const auto delta = va - s->address;
    return delta < s->file_size && size <= s->file_size - delta;
}

std::vector<FunctionRange> functions(const ElfInfo& elf) {
    std::vector<FunctionRange> out;
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen;
    for (const auto& f : elf.unwind.fdes) {
        if (!f.function_file_backed || !f.function_size || f.function_end_va <= f.function_start_va) continue;
        if (f.function_size > MAX_FUNCTION_BYTES) continue;
        if (seen.emplace(f.function_start_va, f.function_end_va).second)
            out.push_back({f.function_start_va, f.function_end_va, f.function_file_offset});
    }
    return out;
}

std::vector<Decoded> decode_function(std::span<const std::uint8_t> data, const FunctionRange& f) {
    std::vector<Decoded> out;
    if (f.end_va <= f.begin_va || f.file_offset >= data.size()) return out;
    const auto span = std::min<std::uint64_t>(f.end_va - f.begin_va, data.size() - f.file_offset);
    if (!span || span > MAX_FUNCTION_BYTES) return out;
    ZydisDecoder dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) return out;
    std::uint64_t delta = 0;
    while (delta < span && out.size() < MAX_FUNCTION_INSTRUCTIONS) {
        Decoded x;
        x.va = f.begin_va + delta;
        x.file_offset = f.file_offset + delta;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, data.data() + x.file_offset,
                static_cast<std::size_t>(span - delta), &x.zi, x.ops.data())) || !x.zi.length) break;
        out.push_back(x);
        delta += x.zi.length;
    }
    return out;
}

std::optional<std::uint64_t> relative_target(const Decoded& x) {
    if (x.zi.meta.category != ZYDIS_CATEGORY_COND_BR && x.zi.meta.category != ZYDIS_CATEGORY_UNCOND_BR) return {};
    for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i) {
        const auto& o = x.ops[i];
        if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) continue;
        const auto next = x.va + x.zi.length;
        return add_signed(next, o.imm.value.s);
    }
    return {};
}

class PointerResolver {
public:
    PointerResolver(std::span<const std::uint8_t> data, const ElfInfo& elf) : data_(data), elf_(elf) {
        for (const auto& r : elf.dynamic.relocations) relocations_.emplace(r.target_va, &r);
    }

    std::optional<std::uint64_t> pointer_at(std::uint64_t slot_va) const {
        const auto range = relocations_.equal_range(slot_va);
        for (auto it = range.first; it != range.second; ++it) {
            const auto& r = *it->second;
            if (r.type == R_X86_64_RELATIVE_VALUE) {
                if (r.has_addend) {
                    if (r.addend < 0) return {};
                    return static_cast<std::uint64_t>(r.addend);
                }
                return raw64(slot_va);
            }
            if (r.type == R_X86_64_64_VALUE && r.symbol_index < elf_.dynamic.symbols.size()) {
                const auto base = elf_.dynamic.symbols[r.symbol_index].value;
                if (!base && elf_.dynamic.symbols[r.symbol_index].imported) continue;
                return add_signed(base, r.has_addend ? r.addend : 0);
            }
        }
        return raw64(slot_va);
    }

    bool executable_pointer_at(std::uint64_t slot_va) const {
        const auto p = pointer_at(slot_va);
        return p && executable_va(elf_, *p);
    }

    bool printable_string_pointer_at(std::uint64_t slot_va) const {
        const auto p = pointer_at(slot_va);
        if (!p) return false;
        const auto off = va_to_file(elf_, *p);
        if (!off || *off >= data_.size()) return false;
        std::size_t len = 0;
        for (; len < 96 && *off + len < data_.size(); ++len) {
            const auto c = data_[*off + len];
            if (!c) break;
            if (c < 0x20 || c > 0x7e) return false;
        }
        return len >= 2 && len < 96 && *off + len < data_.size() && data_[*off + len] == 0;
    }

private:
    std::optional<std::uint64_t> raw64(std::uint64_t va) const {
        const auto off = va_to_file(elf_, va, 8);
        if (!off || *off + 8 > data_.size()) return {};
        std::uint64_t v = 0;
        for (std::uint32_t i = 0; i < 8; ++i)
            v |= static_cast<std::uint64_t>(data_[*off + i]) << (i * 8);
        return v;
    }

    std::span<const std::uint8_t> data_;
    const ElfInfo& elf_;
    std::multimap<std::uint64_t, const ElfRelocation*> relocations_;
};

using Registers = std::map<ZydisRegister, std::uint64_t>;

std::optional<std::uint64_t> reg_value(const Registers& regs, ZydisRegister r) {
    const auto it = regs.find(large(r));
    if (it == regs.end()) return {};
    return it->second;
}

std::optional<std::uint64_t> memory_address(const Decoded& x, const ZydisDecodedOperand& o, const Registers& regs) {
    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY) return {};
    std::uint64_t value = 0;
    if (large(o.mem.base) == ZYDIS_REGISTER_RIP) {
        value = x.va + x.zi.length;
    } else if (o.mem.base != ZYDIS_REGISTER_NONE) {
        const auto base = reg_value(regs, o.mem.base);
        if (!base) return {};
        value = *base;
    }
    if (o.mem.index != ZYDIS_REGISTER_NONE) {
        const auto index = reg_value(regs, o.mem.index);
        if (!index) return {};
        const auto scale = static_cast<std::uint64_t>(o.mem.scale ? o.mem.scale : 1);
        if (*index && scale > UINT64_MAX / *index) return {};
        const auto add = *index * scale;
        if (value > UINT64_MAX - add) return {};
        value += add;
    }
    if (o.mem.disp.has_displacement) return add_signed(value, o.mem.disp.value);
    return value;
}

std::optional<std::uint64_t> mov_immediate(const ZydisDecodedOperand& dst, const ZydisDecodedOperand& src) {
    if (src.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || src.imm.is_relative) return {};
    if (dst.size == 64 && src.size == 32)
        return static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(src.imm.value.u)));
    if (dst.size == 32) return static_cast<std::uint32_t>(src.imm.value.u);
    return src.imm.value.u;
}

void apply_register_write(const Decoded& x, Registers& regs) {
    if (!x.zi.operand_count_visible || x.ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !(x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE)) return;
    const auto dst = large(x.ops[0].reg.value);
    std::optional<std::uint64_t> next;
    if (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2) {
        if (x.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) next = reg_value(regs, x.ops[1].reg.value);
        else next = mov_immediate(x.ops[0], x.ops[1]);
    } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_LEA && x.zi.operand_count_visible >= 2) {
        next = memory_address(x, x.ops[1], regs);
    } else if ((x.zi.mnemonic == ZYDIS_MNEMONIC_ADD || x.zi.mnemonic == ZYDIS_MNEMONIC_SUB) &&
               x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        const auto cur = reg_value(regs, dst);
        if (cur) {
            auto delta = x.ops[1].imm.value.s;
            if (x.zi.mnemonic == ZYDIS_MNEMONIC_SUB) delta = -delta;
            next = add_signed(*cur, delta);
        }
    } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_XOR && x.zi.operand_count_visible >= 2 &&
               x.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && large(x.ops[1].reg.value) == dst) {
        next = 0;
    }
    if (next) regs[dst] = *next;
    else regs.erase(dst);
}

void clear_call_clobbers(Registers& regs) {
    for (const auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI,
                         ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10,
                         ZYDIS_REGISTER_R11}) regs.erase(r);
}

struct IndirectCallRef {
    std::uint64_t instruction_va = 0;
    std::uint64_t slot_va = 0;
    std::set<ZydisRegister> address_registers;
};

struct ScalarRef {
    std::uint64_t slot_va = 0;
    std::uint32_t width = 0;
    bool control = false;
};

struct StrideUpdate {
    ZydisRegister reg = ZYDIS_REGISTER_NONE;
    std::uint32_t stride = 0;
    std::int64_t delta = 0;
    bool before_exact = false;
    std::uint64_t before_value = 0;
    bool zero_flag_branch = false;
};

struct CompareLimit {
    ZydisRegister reg = ZYDIS_REGISTER_NONE;
    std::uint64_t limit = 0;
};

struct ConsumerEvidence {
    FunctionRange function;
    std::vector<IndirectCallRef> calls;
    std::vector<ScalarRef> scalars;
    std::vector<StrideUpdate> strides;
    std::vector<CompareLimit> compare_limits;
    std::set<std::uint64_t> table_base_hints;
    bool has_backward_branch = false;
    bool limited = false;
};

ConsumerEvidence inspect_consumer(std::span<const std::uint8_t> data, const ElfInfo& elf,
                                  const FunctionRange& f, const PointerResolver& pointers) {
    ConsumerEvidence out;
    out.function = f;
    const auto ins = decode_function(data, f);
    Registers regs;
    std::map<ZydisRegister, ScalarRef> scalar_origins;
    std::optional<std::size_t> previous_stride;
    for (const auto& x : ins) {
        if ((x.zi.meta.category == ZYDIS_CATEGORY_COND_BR || x.zi.meta.category == ZYDIS_CATEGORY_UNCOND_BR)) {
            const auto t = relative_target(x);
            if (t && *t >= f.begin_va && *t < x.va) out.has_backward_branch = true;
        }
        if ((x.zi.mnemonic == ZYDIS_MNEMONIC_JZ || x.zi.mnemonic == ZYDIS_MNEMONIC_JNZ) && previous_stride)
            out.strides[*previous_stride].zero_flag_branch = true;
        previous_stride.reset();

        const bool control = x.zi.mnemonic == ZYDIS_MNEMONIC_CMP || x.zi.mnemonic == ZYDIS_MNEMONIC_TEST;
        if (control) {
            for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i) {
                if (x.ops[i].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
                const auto it = scalar_origins.find(large(x.ops[i].reg.value));
                if (it != scalar_origins.end()) {
                    auto q = it->second;
                    q.control = true;
                    out.scalars.push_back(q);
                }
            }
        }

        if (x.zi.mnemonic == ZYDIS_MNEMONIC_CMP && x.zi.operand_count_visible >= 2) {
            for (int side = 0; side < 2; ++side) {
                const auto& a = x.ops[side];
                const auto& b = x.ops[1 - side];
                if (a.type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
                std::optional<std::uint64_t> limit;
                if (b.type == ZYDIS_OPERAND_TYPE_REGISTER) limit = reg_value(regs, b.reg.value);
                else if (b.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) limit = mov_immediate(a, b);
                if (limit) out.compare_limits.push_back({large(a.reg.value), *limit});
            }
        }

        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL && x.zi.operand_count_visible &&
            x.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            const auto slot = memory_address(x, x.ops[0], regs);
            if (slot && pointers.executable_pointer_at(*slot)) {
                IndirectCallRef c;
                c.instruction_va = x.va;
                c.slot_va = *slot;
                for (const auto r : {x.ops[0].mem.base, x.ops[0].mem.index}) {
                    const auto q = large(r);
                    if (q != ZYDIS_REGISTER_NONE && q != ZYDIS_REGISTER_RIP) {
                        c.address_registers.insert(q);
                        const auto v = reg_value(regs, q);
                        if (v && nonexec_file_backed(elf, *v, 8)) out.table_base_hints.insert(*v);
                    }
                }
                if (out.calls.size() < MAX_INDIRECT_CALLS_PER_FUNCTION) out.calls.push_back(std::move(c));
                else out.limited = true;
            }
        }

        std::optional<ScalarRef> loaded_scalar;
        for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i) {
            const auto& o = x.ops[i];
            if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || !(o.actions & ZYDIS_OPERAND_ACTION_READ) ||
                !o.size || o.size > 32) continue;
            if (x.zi.meta.category == ZYDIS_CATEGORY_CALL && i == 0) continue;
            const auto addr = memory_address(x, o, regs);
            if (!addr) continue;
            ScalarRef q{*addr, static_cast<std::uint32_t>(o.size / 8), control};
            out.scalars.push_back(q);
            if (x.zi.operand_count_visible >= 2 && x.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV || x.zi.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
                 x.zi.mnemonic == ZYDIS_MNEMONIC_MOVSX || x.zi.mnemonic == ZYDIS_MNEMONIC_MOVSXD)) loaded_scalar = q;
        }

        if ((x.zi.mnemonic == ZYDIS_MNEMONIC_ADD || x.zi.mnemonic == ZYDIS_MNEMONIC_SUB) &&
            x.zi.operand_count_visible >= 2 && x.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            x.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            auto delta = x.ops[1].imm.value.s;
            if (x.zi.mnemonic == ZYDIS_MNEMONIC_SUB) delta = -delta;
            const auto mag = delta < 0 ? -delta : delta;
            if (mag >= 16 && mag <= MAX_RECORD_STRIDE && (mag % 8) == 0) {
                StrideUpdate u;
                u.reg = large(x.ops[0].reg.value);
                u.stride = static_cast<std::uint32_t>(mag);
                u.delta = delta;
                if (const auto before = reg_value(regs, u.reg)) {
                    u.before_exact = true;
                    u.before_value = *before;
                }
                out.strides.push_back(u);
                previous_stride = out.strides.size() - 1;
            }
        }

        const bool writes_reg = x.zi.operand_count_visible && x.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                                (x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE);
        const auto written_reg = writes_reg ? large(x.ops[0].reg.value) : ZYDIS_REGISTER_NONE;
        apply_register_write(x, regs);
        if (writes_reg) {
            if (loaded_scalar) scalar_origins[written_reg] = *loaded_scalar;
            else scalar_origins.erase(written_reg);
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL) {
            clear_call_clobbers(regs);
            for (const auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI,
                                 ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10,
                                 ZYDIS_REGISTER_R11}) scalar_origins.erase(r);
        }
    }
    return out;
}

bool record_has_fields(const PointerResolver& pointers, std::uint64_t base,
                       const std::set<std::uint32_t>& fields) {
    for (const auto off : fields)
        if (!pointers.executable_pointer_at(base + off)) return false;
    return true;
}

std::set<std::uint32_t> common_executable_fields(const PointerResolver& pointers,
                                                 const ElfInfo& elf, std::uint64_t base,
                                                 std::uint32_t stride) {
    std::set<std::uint32_t> fields;
    for (std::uint32_t off = 0; off + 8 <= stride; off += 8)
        if (pointers.executable_pointer_at(base + off)) fields.insert(off);
    if (fields.empty()) return {};
    for (std::uint32_t n = 1; n < 4 && !fields.empty(); ++n) {
        const auto record = base + static_cast<std::uint64_t>(n) * stride;
        if (!nonexec_file_backed(elf, record, stride)) return {};
        for (auto it = fields.begin(); it != fields.end();) {
            if (!pointers.executable_pointer_at(record + *it)) it = fields.erase(it);
            else ++it;
        }
    }
    return fields;
}

struct TableCandidate {
    std::uint64_t base = 0;
    std::uint32_t stride = 0;
    std::uint32_t count = 0;
    std::set<std::uint32_t> executable_fields;
    std::set<std::uint32_t> string_fields;
    std::map<std::uint32_t, std::pair<std::uint32_t, bool>> scalar_fields;
    std::uint32_t dispatch_count = 0;
    std::string profile;
    bool mutable_storage = false;
    std::string mutability_basis;
    std::uint64_t score = 0;
};

std::optional<std::pair<bool, std::string>> mutability(const ElfInfo& elf, std::uint64_t base, std::uint64_t size) {
    const auto* load = load_for_range(elf, base, size);
    if (!load) return {};
    const auto end = base + size;
    for (const auto& s : elf.segments) {
        if (s.type != PT_GNU_RELRO_VALUE || base < s.address) continue;
        if (end <= s.address + s.memory_size) return std::make_pair(false, std::string("PT_GNU_RELRO"));
    }
    if (load->flags & PF_W_VALUE) return std::make_pair(true, std::string("WRITABLE_PT_LOAD"));
    return std::make_pair(false, std::string("READ_ONLY_PT_LOAD"));
}

std::optional<TableCandidate> evaluate_candidate(const ConsumerEvidence& consumer,
                                                 const PointerResolver& pointers, const ElfInfo& elf,
                                                 std::uint64_t seed_base, std::uint32_t stride,
                                                 const std::string& profile) {
    if (!stride || stride > MAX_RECORD_STRIDE || (stride % 8) != 0 || !nonexec_file_backed(elf, seed_base, stride * 4ull)) return {};
    auto fields = common_executable_fields(pointers, elf, seed_base, stride);
    if (fields.empty()) return {};

    auto base = seed_base;
    std::uint32_t back = 0;
    while (back < MAX_RECORD_COUNT && base >= stride) {
        const auto prior = base - stride;
        if (!nonexec_file_backed(elf, prior, stride) || !record_has_fields(pointers, prior, fields)) break;
        base = prior;
        ++back;
    }

    std::uint32_t count = 0;
    while (count < MAX_RECORD_COUNT) {
        const auto record = base + static_cast<std::uint64_t>(count) * stride;
        if (!nonexec_file_backed(elf, record, stride) || !record_has_fields(pointers, record, fields)) break;
        ++count;
    }
    if (count < 4) return {};
    const auto table_size = static_cast<std::uint64_t>(count) * stride;
    if (!table_size || table_size > MAX_TABLE_BYTES) return {};

    for (const auto& c : consumer.calls) {
        if (c.slot_va < base || c.slot_va >= base + table_size) return {};
        const auto off = static_cast<std::uint32_t>((c.slot_va - base) % stride);
        if (!fields.count(off)) return {};
    }

    TableCandidate out;
    out.base = base;
    out.stride = stride;
    out.count = count;
    out.executable_fields = std::move(fields);
    out.dispatch_count = static_cast<std::uint32_t>(consumer.calls.size());
    out.profile = profile;

    for (std::uint32_t off = 0; off + 8 <= stride; off += 8) {
        if (out.executable_fields.count(off)) continue;
        bool all_strings = true;
        for (std::uint32_t n = 0; n < count; ++n) {
            if (!pointers.printable_string_pointer_at(base + static_cast<std::uint64_t>(n) * stride + off)) {
                all_strings = false;
                break;
            }
        }
        if (all_strings) out.string_fields.insert(off);
    }

    for (const auto& s : consumer.scalars) {
        if (s.slot_va < base || s.slot_va >= base + table_size) continue;
        const auto off = static_cast<std::uint32_t>((s.slot_va - base) % stride);
        bool overlaps_pointer = false;
        for (const auto p : out.executable_fields)
            if (off >= p && off < p + 8) overlaps_pointer = true;
        for (const auto p : out.string_fields)
            if (off >= p && off < p + 8) overlaps_pointer = true;
        if (overlaps_pointer) continue;
        auto& x = out.scalar_fields[off];
        x.first = std::max(x.first, s.width);
        x.second = x.second || s.control;
    }

    const auto m = mutability(elf, base, table_size);
    if (!m) return {};
    out.mutable_storage = m->first;
    out.mutability_basis = m->second;

    const bool exact_hint = consumer.table_base_hints.count(base) != 0;
    const auto dispatch_phase = out.executable_fields.empty() ? MAX_RECORD_STRIDE : *out.executable_fields.begin();
    out.score = static_cast<std::uint64_t>(out.dispatch_count) * 10000u + static_cast<std::uint64_t>(count) * 100u +
                static_cast<std::uint64_t>(out.string_fields.size()) * 500u +
                static_cast<std::uint64_t>(out.executable_fields.size()) * 100u +
                static_cast<std::uint64_t>(out.scalar_fields.size()) * 20u + (exact_hint ? 1000u : 0u) +
                (MAX_RECORD_STRIDE - std::min(dispatch_phase, MAX_RECORD_STRIDE));
    return out;
}

std::vector<std::uint32_t> loop_strides(const ConsumerEvidence& c) {
    std::set<std::uint32_t> out;
    if (!c.has_backward_branch) return {};
    std::set<ZydisRegister> call_regs;
    for (const auto& call : c.calls) call_regs.insert(call.address_registers.begin(), call.address_registers.end());
    for (const auto& s : c.strides)
        if (call_regs.count(s.reg)) out.insert(s.stride);
    return {out.begin(), out.end()};
}

std::set<std::uint32_t> loop_count_hints(const ConsumerEvidence& c, std::uint32_t stride) {
    std::set<std::uint32_t> out;
    for (const auto& s : c.strides) {
        if (s.stride != stride || !s.before_exact || !s.delta) continue;
        for (const auto& cmp : c.compare_limits) {
            if (cmp.reg != s.reg) continue;
            const auto distance = s.delta > 0 ? (cmp.limit - s.before_value) : (s.before_value - cmp.limit);
            if (distance % stride) continue;
            const auto n = distance / stride;
            if (n >= 4 && n <= MAX_RECORD_COUNT) out.insert(static_cast<std::uint32_t>(n));
        }
        if (s.zero_flag_branch) {
            const auto distance = s.delta > 0 ? (std::uint64_t{0} - s.before_value) : s.before_value;
            if (!(distance % stride)) {
                const auto n = distance / stride;
                if (n >= 4 && n <= MAX_RECORD_COUNT) out.insert(static_cast<std::uint32_t>(n));
            }
        }
    }
    return out;
}

bool profile_count_exact(const ConsumerEvidence& c, const TableCandidate& q) {
    if (q.profile == "LOOP_STRIDE_INDIRECT_DISPATCH") {
        const auto counts = loop_count_hints(c, q.stride);
        return !counts.empty() && counts.count(q.count);
    }
    std::map<std::uint32_t, std::uint32_t> per_field;
    for (const auto& call : c.calls) {
        if (call.slot_va < q.base || call.slot_va >= q.base + static_cast<std::uint64_t>(q.stride) * q.count) return false;
        const auto off = static_cast<std::uint32_t>((call.slot_va - q.base) % q.stride);
        if (!q.executable_fields.count(off)) return false;
        ++per_field[off];
    }
    std::uint32_t best = 0;
    for (const auto& [_, n] : per_field) best = std::max(best, n);
    return best == q.count && best >= 4;
}

std::vector<std::uint32_t> unrolled_strides(const ConsumerEvidence& c) {
    std::vector<std::uint32_t> out;
    if (c.calls.size() < 4) return out;
    for (std::uint32_t stride = 16; stride <= MAX_RECORD_STRIDE; stride += 8) {
        std::map<std::uint64_t, std::uint32_t> residue;
        for (const auto& call : c.calls) ++residue[call.slot_va % stride];
        std::uint32_t best = 0;
        for (const auto& [_, n] : residue) best = std::max(best, n);
        if (best >= 4) out.push_back(stride);
    }
    return out;
}

std::optional<TableCandidate> best_table(const ConsumerEvidence& consumer,
                                         const PointerResolver& pointers, const ElfInfo& elf,
                                         std::size_t& evaluations) {
    std::optional<TableCandidate> best;
    const auto try_profile = [&](const std::vector<std::uint32_t>& strides, const std::string& profile,
                                 std::optional<TableCandidate>& dst) {
        for (const auto stride : strides) {
            for (const auto& call : consumer.calls) {
                for (std::uint32_t field = 0; field + 8 <= stride; field += 8) {
                    if (evaluations++ >= MAX_CANDIDATE_EVALUATIONS) return false;
                    if (call.slot_va < field) continue;
                    const auto seed = call.slot_va - field;
                    auto q = evaluate_candidate(consumer, pointers, elf, seed, stride, profile);
                    if (!q || !profile_count_exact(consumer, *q)) continue;
                    if (!dst || q->score > dst->score ||
                        (q->score == dst->score && std::tie(q->stride, q->base) < std::tie(dst->stride, dst->base))) dst = std::move(q);
                }
            }
        }
        return true;
    };

    const auto loops = loop_strides(consumer);
    if (!loops.empty()) {
        if (!try_profile(loops, "LOOP_STRIDE_INDIRECT_DISPATCH", best)) return best;
        if (best) return best;
    }
    const auto unrolled = unrolled_strides(consumer);
    if (!unrolled.empty()) try_profile(unrolled, "UNROLLED_PERIODIC_INDIRECT_DISPATCH", best);
    return best;
}

} // namespace

ControlRecordInfo detect_control_records(std::span<const std::uint8_t> data, const ElfInfo& elf) {
    ControlRecordInfo out;
    if (!elf.valid) return out;
    if (!elf.elf64 || !elf.little_endian || elf.machine != 62) {
        out.state = "UNSUPPORTED";
        out.error = "initial control-record detector supports ELF64 little-endian x86-64 only";
        return out;
    }
    if (elf.unwind.state != "RESOLVED" || elf.unwind.fdes.empty()) {
        out.state = "UNSUPPORTED";
        out.error = "validated .eh_frame function boundaries are required";
        return out;
    }

    const PointerResolver pointers(data, elf);
    const auto fs = functions(elf);
    if (fs.size() > MAX_BOUNDED_FUNCTIONS) out.analysis_limited = true;
    std::size_t evaluations = 0;
    std::set<std::tuple<std::uint64_t, std::uint32_t, std::uint32_t, std::uint64_t>> seen;
    for (std::size_t fi = 0; fi < fs.size() && fi < MAX_BOUNDED_FUNCTIONS; ++fi) {
        const auto& f = fs[fi];
        ++out.bounded_function_count;
        const auto c = inspect_consumer(data, elf, f, pointers);
        if (c.limited) out.analysis_limited = true;
        if (c.calls.empty()) continue;
        ++out.candidate_consumer_count;
        const auto t = best_table(c, pointers, elf, evaluations);
        if (!t) {
            ++out.rejected_consumer_count;
            if (evaluations >= MAX_CANDIDATE_EVALUATIONS) {
                out.analysis_limited = true;
                break;
            }
            continue;
        }
        const auto key = std::make_tuple(t->base, t->stride, t->count, f.begin_va);
        if (!seen.insert(key).second) continue;
        const auto file = va_to_file(elf, t->base, t->stride * static_cast<std::uint64_t>(t->count));
        if (!file) continue;

        ControlRecordTable x;
        x.index = static_cast<std::uint32_t>(out.tables.size());
        x.evidence_state = "EXACT_STRUCTURAL";
        x.priority_reason = "repeated executable-pointer records with an exact bounded indirect-dispatch consumer; writable storage is capability only";
        x.table_va = t->base;
        x.table_file_offset = *file;
        x.record_stride = t->stride;
        x.record_count = t->count;
        x.table_size = static_cast<std::uint64_t>(t->stride) * t->count;
        x.stride_evidence_state = t->profile == "LOOP_STRIDE_INDIRECT_DISPATCH" ?
            "EXACT_RECORD_POINTER_DELTA" : "EXACT_PERIODIC_DISPATCH_DELTA";
        x.count_evidence_state = t->profile == "LOOP_STRIDE_INDIRECT_DISPATCH" ?
            "EXACT_LOOP_BOUND" : "EXACT_UNROLLED_DISPATCH_CARDINALITY";
        x.consumer_va = f.begin_va;
        x.consumer_file_offset = f.file_offset;
        x.consumer_profile = t->profile;
        x.indirect_dispatch_count = t->dispatch_count;
        x.mutable_storage = t->mutable_storage;
        x.mutability_basis = t->mutability_basis;
        for (const auto off : t->executable_fields)
            x.fields.push_back({off, 8, "executable_pointer", "EXACT_REPEATED_EXECUTABLE_POINTER"});
        for (const auto off : t->string_fields)
            x.fields.push_back({off, 8, "printable_string_pointer", "EXACT_REPEATED_PRINTABLE_STRING_POINTER"});
        for (const auto& [off, q] : t->scalar_fields)
            x.fields.push_back({off, q.first, q.second ? "control_scalar" : "consumer_scalar",
                                q.second ? "EXACT_CONSUMER_CONTROL_ACCESS" : "EXACT_CONSUMER_SCALAR_ACCESS"});
        std::sort(x.fields.begin(), x.fields.end(), [](const auto& a, const auto& b) {
            if (a.offset != b.offset) return a.offset < b.offset;
            return a.role < b.role;
        });
        std::ostringstream detail;
        detail << "record boundary/stride/count are derived from repeated exact pointer geometry plus consumer dispatch; profile="
               << t->profile << "; mutability=" << t->mutability_basis;
        x.detail = detail.str();
        out.tables.push_back(std::move(x));
        if (evaluations >= MAX_CANDIDATE_EVALUATIONS) {
            out.analysis_limited = true;
            break;
        }
    }

    out.confirmed_table_count = out.tables.size();
    if (!out.tables.empty()) out.state = out.analysis_limited ? "PARTIAL" : "RESOLVED";
    else if (out.analysis_limited) out.state = "PARTIAL";
    return out;
}

} // namespace prts
