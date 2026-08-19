#include "prts/continuation.hpp"
#include "Zydis.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
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

std::optional<std::uint64_t> va_to_file(const ElfInfo& elf, std::uint64_t va, std::uint64_t size = 1) {
    for (const auto& s : elf.segments) {
        if (s.type != 1 || va < s.address) continue;
        const auto delta = va - s.address;
        if (delta >= s.file_size || size > s.file_size - delta) continue;
        return s.offset + delta;
    }
    return {};
}

bool executable_va(const ElfInfo& elf, std::uint64_t va) {
    for (const auto& s : elf.segments) {
        if (s.type != 1 || !(s.flags & 1) || va < s.address) continue;
        if (va - s.address < s.memory_size) return true;
    }
    return false;
}

std::optional<FunctionRange> function_for(const ElfInfo& elf, std::uint64_t va) {
    for (const auto& f : elf.unwind.fdes) {
        if (!f.function_file_backed || !f.function_size) continue;
        if (va == f.function_start_va) return FunctionRange{f.function_start_va, f.function_end_va, f.function_file_offset};
    }
    return {};
}

std::vector<FunctionRange> functions(const ElfInfo& elf) {
    std::vector<FunctionRange> out;
    std::set<std::pair<std::uint64_t, std::uint64_t>> seen;
    for (const auto& f : elf.unwind.fdes) {
        if (!f.function_file_backed || !f.function_size || f.function_end_va <= f.function_start_va) continue;
        if (seen.emplace(f.function_start_va, f.function_end_va).second)
            out.push_back({f.function_start_va, f.function_end_va, f.function_file_offset});
    }
    return out;
}

std::vector<Decoded> decode_function(std::span<const std::uint8_t> data, const FunctionRange& f) {
    std::vector<Decoded> out;
    if (f.end_va <= f.begin_va || f.file_offset >= data.size()) return out;
    const auto span = std::min<std::uint64_t>(f.end_va - f.begin_va, data.size() - f.file_offset);
    if (!span || span > 0x10000) return out;
    ZydisDecoder dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) return out;
    std::uint64_t delta = 0;
    while (delta < span && out.size() < 8192) {
        Decoded x;
        x.va = f.begin_va + delta;
        x.file_offset = f.file_offset + delta;
        const auto avail = static_cast<std::size_t>(span - delta);
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, data.data() + x.file_offset, avail, &x.zi, x.ops.data())) || !x.zi.length) break;
        out.push_back(x);
        delta += x.zi.length;
    }
    return out;
}

std::optional<std::uint64_t> relative_target(const Decoded& x) {
    if (x.zi.meta.category != ZYDIS_CATEGORY_CALL && x.zi.meta.category != ZYDIS_CATEGORY_UNCOND_BR && x.zi.meta.category != ZYDIS_CATEGORY_COND_BR) return {};
    for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i) {
        const auto& o = x.ops[i];
        if (o.type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !o.imm.is_relative) continue;
        const auto t = static_cast<std::int64_t>(x.va + x.zi.length) + o.imm.value.s;
        if (t < 0) return {};
        return static_cast<std::uint64_t>(t);
    }
    return {};
}

std::optional<std::uint64_t> pointer_value(const Decoded& x, const ZydisDecodedOperand& o) {
    if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && !o.imm.is_relative) {
        auto v = o.imm.value.u;
        if (o.size == 32 && x.zi.operand_width == 64)
            v = static_cast<std::uint64_t>(static_cast<std::int64_t>(static_cast<std::int32_t>(v)));
        return v;
    }
    return {};
}

struct RegisterValue {
    enum class Kind { Unknown, Constant, Allocation } kind = Kind::Unknown;
    std::uint64_t value = 0;
    std::uint64_t allocation_id = 0;
};

using Registers = std::map<ZydisRegister, RegisterValue>;

RegisterValue reg_value(const Registers& regs, ZydisRegister r) {
    const auto it = regs.find(large(r));
    return it == regs.end() ? RegisterValue{} : it->second;
}

std::optional<std::uint64_t> constant_operand(const Decoded& x, const ZydisDecodedOperand& o, const Registers& regs) {
    if (auto v = pointer_value(x, o)) return v;
    if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) {
        const auto v = reg_value(regs, o.reg.value);
        if (v.kind == RegisterValue::Kind::Constant) return v.value;
    }
    if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.index == ZYDIS_REGISTER_NONE && large(o.mem.base) == ZYDIS_REGISTER_RIP) {
        const auto disp = o.mem.disp.has_displacement ? o.mem.disp.value : 0;
        const auto t = static_cast<std::int64_t>(x.va + x.zi.length) + disp;
        if (t >= 0) return static_cast<std::uint64_t>(t);
    }
    return {};
}

void apply_register_write(const Decoded& x, Registers& regs) {
    if (!x.zi.operand_count_visible || x.ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !(x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE)) return;
    const auto dst = large(x.ops[0].reg.value);
    RegisterValue next;
    if (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2) {
        if (x.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) next = reg_value(regs, x.ops[1].reg.value);
        else if (auto v = pointer_value(x, x.ops[1])) next = {RegisterValue::Kind::Constant, *v, 0};
    } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_LEA && x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
        const auto& m = x.ops[1].mem;
        if (m.index == ZYDIS_REGISTER_NONE && large(m.base) == ZYDIS_REGISTER_RIP) {
            const auto disp = m.disp.has_displacement ? m.disp.value : 0;
            const auto t = static_cast<std::int64_t>(x.va + x.zi.length) + disp;
            if (t >= 0) next = {RegisterValue::Kind::Constant, static_cast<std::uint64_t>(t), 0};
        } else if (m.index == ZYDIS_REGISTER_NONE && m.base != ZYDIS_REGISTER_NONE) {
            next = reg_value(regs, m.base);
            if (next.kind == RegisterValue::Kind::Constant) {
                const auto disp = m.disp.has_displacement ? m.disp.value : 0;
                next.value = static_cast<std::uint64_t>(static_cast<std::int64_t>(next.value) + disp);
            } else if (m.disp.has_displacement && m.disp.value != 0) {
                next = {};
            }
        }
    } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_XOR && x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER && large(x.ops[1].reg.value) == dst) {
        next = {RegisterValue::Kind::Constant, 0, 0};
    }
    if (next.kind == RegisterValue::Kind::Unknown) regs.erase(dst);
    else regs[dst] = next;
}

void clear_call_clobbers(Registers& regs) {
    for (const auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11}) regs.erase(r);
}

std::optional<std::uint64_t> plt_got_slot(std::span<const std::uint8_t> data, const ElfInfo& elf, std::uint64_t target) {
    auto fo = va_to_file(elf, target);
    if (!fo || *fo >= data.size()) return {};
    ZydisDecoder dec;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) return {};
    std::uint64_t va = target, off = *fo;
    for (int n = 0; n < 5 && off < data.size(); ++n) {
        ZydisDecodedInstruction zi{};
        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> ops{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, data.data() + off, std::min<std::size_t>(32, data.size() - off), &zi, ops.data())) || !zi.length) break;
        if (zi.meta.category == ZYDIS_CATEGORY_UNCOND_BR && zi.operand_count_visible && ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[0].mem.index == ZYDIS_REGISTER_NONE && large(ops[0].mem.base) == ZYDIS_REGISTER_RIP) {
            const auto disp = ops[0].mem.disp.has_displacement ? ops[0].mem.disp.value : 0;
            const auto slot = static_cast<std::int64_t>(va + zi.length) + disp;
            if (slot >= 0) return static_cast<std::uint64_t>(slot);
        }
        va += zi.length;
        off += zi.length;
    }
    return {};
}

std::string imported_call_name(std::span<const std::uint8_t> data, const ElfInfo& elf, std::uint64_t target) {
    const auto slot = plt_got_slot(data, elf, target);
    if (!slot) return {};
    for (const auto& r : elf.dynamic.relocations) {
        if (r.target_va != *slot || r.symbol_index >= elf.dynamic.symbols.size()) continue;
        return elf.dynamic.symbols[r.symbol_index].name;
    }
    return {};
}

bool allocator_name(const std::string& n) {
    return n.rfind("_Znwm", 0) == 0 || n.rfind("_Znam", 0) == 0;
}

bool deallocator_name(const std::string& n) {
    return n.rfind("_ZdlPv", 0) == 0 || n.rfind("_ZdaPv", 0) == 0;
}

struct Candidate {
    std::uint64_t allocation_id = 0;
    std::uint64_t creator_va = 0;
    std::uint64_t creator_file_offset = 0;
    std::uint64_t allocation_site_va = 0;
    std::uint64_t allocation_site_file_offset = 0;
    bool frame_size_exact = false;
    std::uint64_t frame_size = 0;
    std::uint64_t resume_va = 0;
    std::uint64_t destroy_va = 0;
    std::string allocator;
};

std::vector<Candidate> creator_candidates(std::span<const std::uint8_t> data, const ElfInfo& elf, const FunctionRange& f) {
    std::vector<Candidate> out;
    const auto ins = decode_function(data, f);
    Registers regs;
    std::map<std::uint64_t, Candidate> pending;
    std::uint64_t next_alloc = 1;
    for (const auto& x : ins) {
        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL) {
            const auto call_target = relative_target(x);
            const auto alloc = call_target ? imported_call_name(data, elf, *call_target) : std::string{};
            const auto sz = reg_value(regs, ZYDIS_REGISTER_RDI);
            clear_call_clobbers(regs);
            if (call_target && allocator_name(alloc)) {
                Candidate c;
                c.allocation_id = next_alloc++;
                c.creator_va = f.begin_va;
                c.creator_file_offset = f.file_offset;
                c.allocation_site_va = x.va;
                c.allocation_site_file_offset = x.file_offset;
                c.allocator = alloc;
                if (sz.kind == RegisterValue::Kind::Constant && sz.value >= 16 && sz.value <= (1u << 20)) {
                    c.frame_size_exact = true;
                    c.frame_size = sz.value;
                }
                pending[c.allocation_id] = c;
                regs[ZYDIS_REGISTER_RAX] = {RegisterValue::Kind::Allocation, 0, c.allocation_id};
            }
            continue;
        }

        if (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2 && x.ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
            const auto& dst = x.ops[0].mem;
            if (dst.index == ZYDIS_REGISTER_NONE && dst.base != ZYDIS_REGISTER_NONE) {
                const auto base = reg_value(regs, dst.base);
                const auto disp = dst.disp.has_displacement ? dst.disp.value : 0;
                if (base.kind == RegisterValue::Kind::Allocation && (disp == 0 || disp == 8)) {
                    auto it = pending.find(base.allocation_id);
                    if (it != pending.end()) {
                        const auto target = constant_operand(x, x.ops[1], regs);
                        if (target && executable_va(elf, *target) && function_for(elf, *target)) {
                            if (disp == 0) it->second.resume_va = *target;
                            else it->second.destroy_va = *target;
                            if (it->second.resume_va && it->second.destroy_va) {
                                out.push_back(it->second);
                                pending.erase(it);
                            }
                        }
                    }
                }
            }
        }
        apply_register_write(x, regs);
    }
    return out;
}

using FrameAliases = std::map<ZydisRegister, std::int64_t>;

FrameAliases stable_frame_aliases(const std::vector<Decoded>& ins) {
    FrameAliases stable{{ZYDIS_REGISTER_RDI, 0}};
    const auto limit = std::min<std::size_t>(ins.size(), 24);
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& x = ins[i];
        if (x.zi.mnemonic != ZYDIS_MNEMONIC_MOV || x.zi.operand_count_visible < 2 ||
            x.ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || x.ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER) continue;
        const auto src = large(x.ops[1].reg.value), dst = large(x.ops[0].reg.value);
        if (src != ZYDIS_REGISTER_RDI) continue;
        if (dst == ZYDIS_REGISTER_RBX || dst == ZYDIS_REGISTER_RBP ||
            dst == ZYDIS_REGISTER_R12 || dst == ZYDIS_REGISTER_R13 || dst == ZYDIS_REGISTER_R14 || dst == ZYDIS_REGISTER_R15)
            stable[dst] = 0;
    }
    return stable;
}

void restore_stable_aliases(FrameAliases& aliases, const FrameAliases& stable) {
    for (const auto& [r, off] : stable) if (r != ZYDIS_REGISTER_RDI) aliases[r] = off;
}

void clear_frame_call_clobbers(FrameAliases& aliases) {
    for (const auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11}) aliases.erase(r);
}

std::optional<std::int64_t> frame_memory_offset(const ZydisDecodedOperand& o, const FrameAliases& aliases) {
    if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.index != ZYDIS_REGISTER_NONE || o.mem.base == ZYDIS_REGISTER_NONE) return {};
    const auto it = aliases.find(large(o.mem.base));
    if (it == aliases.end()) return {};
    const auto disp = it->second + (o.mem.disp.has_displacement ? o.mem.disp.value : 0);
    if (disp < 0 || disp > 0x1000) return {};
    return disp;
}

void apply_frame_alias_write(const Decoded& x, FrameAliases& aliases) {
    if (!x.zi.operand_count_visible || x.ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !(x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE)) return;
    const auto dst = large(x.ops[0].reg.value);
    std::optional<std::int64_t> next;
    if (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        const auto it = aliases.find(large(x.ops[1].reg.value));
        if (it != aliases.end()) next = it->second;
    } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_LEA && x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY && x.ops[1].mem.index == ZYDIS_REGISTER_NONE && x.ops[1].mem.base != ZYDIS_REGISTER_NONE) {
        const auto it = aliases.find(large(x.ops[1].mem.base));
        if (it != aliases.end()) next = it->second + (x.ops[1].mem.disp.has_displacement ? x.ops[1].mem.disp.value : 0);
    } else if ((x.zi.mnemonic == ZYDIS_MNEMONIC_ADD || x.zi.mnemonic == ZYDIS_MNEMONIC_SUB) && x.zi.operand_count_visible >= 2 && x.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
        const auto it = aliases.find(dst);
        if (it != aliases.end()) next = it->second + (x.zi.mnemonic == ZYDIS_MNEMONIC_ADD ? x.ops[1].imm.value.s : -x.ops[1].imm.value.s);
    }
    if (next && *next >= 0 && *next <= 0x1000) aliases[dst] = *next;
    else aliases.erase(dst);
}

struct ResumeEvidence {
    bool valid = false;
    bool clears_resume = false;
    bool has_state_dispatch = false;
    std::uint32_t state_offset = 0;
    std::uint32_t state_width = 0;
    std::vector<ContinuationSuspendSite> suspend_sites;
};

ResumeEvidence verify_resume(std::span<const std::uint8_t> data, const ElfInfo& elf, std::uint64_t target) {
    ResumeEvidence e;
    const auto fr = function_for(elf, target);
    if (!fr) return e;
    const auto ins = decode_function(data, *fr);
    struct RW { std::uint32_t width = 0, reads = 0, writes = 0; };
    std::map<std::uint32_t, RW> rw;
    std::set<std::uint32_t> branch_driver_offsets;
    const auto stable = stable_frame_aliases(ins);
    FrameAliases aliases = stable;
    std::map<ZydisRegister, std::uint32_t> state_origin;
    auto origin_for_operand = [&](const ZydisDecodedOperand& o) -> std::optional<std::uint32_t> {
        if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const auto it = state_origin.find(large(o.reg.value));
            if (it != state_origin.end()) return it->second;
        }
        if (const auto disp = frame_memory_offset(o, aliases); disp && *disp >= 16 && o.size && o.size <= 32)
            return static_cast<std::uint32_t>(*disp);
        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            for (const auto r : {o.mem.base, o.mem.index}) {
                if (r == ZYDIS_REGISTER_NONE) continue;
                const auto it = state_origin.find(large(r));
                if (it != state_origin.end()) return it->second;
            }
        }
        return {};
    };
    for (const auto& x : ins) {
        if (x.zi.mnemonic == ZYDIS_MNEMONIC_CMP || x.zi.mnemonic == ZYDIS_MNEMONIC_TEST) {
            for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i)
                if (const auto o = origin_for_operand(x.ops[i])) branch_driver_offsets.insert(*o);
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_UNCOND_BR && x.zi.operand_count_visible && x.ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i)
                if (const auto o = origin_for_operand(x.ops[i])) branch_driver_offsets.insert(*o);
        }
        for (std::uint8_t i = 0; i < x.zi.operand_count_visible; ++i) {
            const auto& o = x.ops[i];
            const auto disp = frame_memory_offset(o, aliases);
            if (!disp) continue;
            if (*disp == 0 && o.size == 64 && (o.actions & ZYDIS_OPERAND_ACTION_WRITE) && x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2) {
                const auto z = pointer_value(x, x.ops[1]);
                if (z && *z == 0) e.clears_resume = true;
            }
            if (*disp < 16 || o.size == 0 || o.size > 32) continue;
            auto& q = rw[static_cast<std::uint32_t>(*disp)];
            q.width = std::max<std::uint32_t>(q.width, o.size / 8);
            if (o.actions & ZYDIS_OPERAND_ACTION_READ) ++q.reads;
            if (o.actions & ZYDIS_OPERAND_ACTION_WRITE) ++q.writes;
        }

        if (x.zi.operand_count_visible && x.ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && (x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE)) {
            const auto dst = large(x.ops[0].reg.value);
            std::optional<std::uint32_t> next;
            if ((x.zi.mnemonic == ZYDIS_MNEMONIC_MOV || x.zi.mnemonic == ZYDIS_MNEMONIC_MOVZX ||
                 x.zi.mnemonic == ZYDIS_MNEMONIC_MOVSX || x.zi.mnemonic == ZYDIS_MNEMONIC_MOVSXD) && x.zi.operand_count_visible >= 2) {
                next = origin_for_operand(x.ops[1]);
            } else if (x.zi.mnemonic == ZYDIS_MNEMONIC_LEA && x.zi.operand_count_visible >= 2) {
                next = origin_for_operand(x.ops[1]);
            } else if ((x.zi.mnemonic == ZYDIS_MNEMONIC_ADD || x.zi.mnemonic == ZYDIS_MNEMONIC_SUB ||
                        x.zi.mnemonic == ZYDIS_MNEMONIC_AND || x.zi.mnemonic == ZYDIS_MNEMONIC_OR ||
                        x.zi.mnemonic == ZYDIS_MNEMONIC_XOR || x.zi.mnemonic == ZYDIS_MNEMONIC_SHL ||
                        x.zi.mnemonic == ZYDIS_MNEMONIC_SHR) && x.zi.operand_count_visible >= 2) {
                const auto it = state_origin.find(dst);
                if (it != state_origin.end()) next = it->second;
                if (!next) next = origin_for_operand(x.ops[1]);
            }
            if (next) state_origin[dst] = *next;
            else state_origin.erase(dst);
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL) {
            clear_frame_call_clobbers(aliases);
            for (const auto r : {ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11}) state_origin.erase(r);
        }
        apply_frame_alias_write(x, aliases);
        restore_stable_aliases(aliases, stable);
    }
    std::uint32_t best_score = 0;
    for (const auto& [off, q] : rw) {
        if (!branch_driver_offsets.count(off) || !q.reads || !q.writes || (q.width != 1 && q.width != 2 && q.width != 4)) continue;
        const auto score = q.reads + q.writes;
        if (score > best_score) {
            best_score = score;
            e.state_offset = off;
            e.state_width = q.width;
        }
    }
    e.has_state_dispatch = e.state_offset != 0;
    if (!e.state_offset || !e.clears_resume || !e.has_state_dispatch) return e;
    aliases = stable;
    for (const auto& x : ins) {
        if (x.zi.mnemonic == ZYDIS_MNEMONIC_MOV && x.zi.operand_count_visible >= 2) {
            const auto disp = frame_memory_offset(x.ops[0], aliases);
            if (disp && static_cast<std::uint32_t>(*disp) == e.state_offset && (x.ops[0].actions & ZYDIS_OPERAND_ACTION_WRITE)) {
                ContinuationSuspendSite s;
                s.instruction_va = x.va;
                s.instruction_file_offset = x.file_offset;
                s.state_frame_offset = e.state_offset;
                s.state_width = e.state_width;
                s.evidence_state = "EXACT_FRAME_STATE_WRITE";
                if (const auto v = pointer_value(x, x.ops[1])) {
                    s.state_value_exact = true;
                    s.state_value = *v;
                }
                if (e.suspend_sites.size() < 64) e.suspend_sites.push_back(std::move(s));
            }
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL) clear_frame_call_clobbers(aliases);
        apply_frame_alias_write(x, aliases);
        restore_stable_aliases(aliases, stable);
    }
    e.valid = true;
    return e;
}

struct DestroyEvidence {
    bool valid = false;
    std::string profile;
};

DestroyEvidence verify_destroy(std::span<const std::uint8_t> data, const ElfInfo& elf, std::uint64_t destroy, std::uint64_t resume, std::uint32_t state_offset) {
    DestroyEvidence e;
    const auto fr = function_for(elf, destroy);
    if (!fr) return e;
    const auto ins = decode_function(data, *fr);
    bool state_destroy_bit = false, transfers_resume = false;
    std::size_t direct_frame_dealloc = 0;
    const auto stable = stable_frame_aliases(ins);
    FrameAliases aliases = stable;
    for (const auto& x : ins) {
        if (x.zi.mnemonic == ZYDIS_MNEMONIC_OR && x.zi.operand_count_visible >= 2) {
            const auto disp = frame_memory_offset(x.ops[0], aliases);
            if (disp && static_cast<std::uint32_t>(*disp) == state_offset && x.ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && (x.ops[1].imm.value.u & 1u)) state_destroy_bit = true;
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
            if (const auto t = relative_target(x); t && *t == resume) transfers_resume = true;
        }
        if (x.zi.meta.category == ZYDIS_CATEGORY_CALL) {
            if (const auto t = relative_target(x); t && deallocator_name(imported_call_name(data, elf, *t))) {
                const auto rdi = aliases.find(ZYDIS_REGISTER_RDI);
                if (rdi != aliases.end() && rdi->second == 0) ++direct_frame_dealloc;
            }
            clear_frame_call_clobbers(aliases);
        }
        apply_frame_alias_write(x, aliases);
        restore_stable_aliases(aliases, stable);
    }
    if (state_destroy_bit && transfers_resume) {
        e.valid = true;
        e.profile = "gcc_state_destroy_x86_64";
        return e;
    }
    if (direct_frame_dealloc == 1) {
        e.valid = true;
        e.profile = "clang_direct_free_x86_64";
    }
    return e;
}

} // namespace

ContinuationInfo detect_cpp20_continuations(std::span<const std::uint8_t> data, const ElfInfo& elf) {
    ContinuationInfo out;
    if (!elf.valid) return out;
    if (!elf.elf64 || !elf.little_endian || elf.machine != 62) {
        out.state = "UNSUPPORTED";
        out.error = "initial continuation detector supports ELF64 little-endian x86-64 only";
        return out;
    }
    if (elf.unwind.state != "RESOLVED" || elf.unwind.fdes.empty()) {
        out.state = "UNSUPPORTED";
        out.error = "validated .eh_frame function boundaries are required";
        return out;
    }
    const auto fs = functions(elf);
    if (fs.size() > 200000) {
        out.state = "PARTIAL";
        out.analysis_limited = true;
        out.error = "function-boundary budget exceeded";
        return out;
    }
    std::set<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>> seen;
    for (const auto& f : fs) {
        for (const auto& c : creator_candidates(data, elf, f)) {
            ++out.candidate_creator_count;
            const auto key = std::make_tuple(c.creator_va, c.resume_va, c.destroy_va);
            if (!seen.insert(key).second) continue;
            const auto resume = verify_resume(data, elf, c.resume_va);
            if (!resume.valid) {
                ++out.rejected_shape_count;
                continue;
            }
            const auto destroy = verify_destroy(data, elf, c.destroy_va, c.resume_va, resume.state_offset);
            if (!destroy.valid) {
                ++out.rejected_shape_count;
                continue;
            }
            const auto ro = va_to_file(elf, c.resume_va);
            const auto doff = va_to_file(elf, c.destroy_va);
            if (!ro || !doff) {
                ++out.rejected_shape_count;
                continue;
            }
            ContinuationEntry x;
            x.index = static_cast<std::uint32_t>(out.entries.size());
            { std::ostringstream q; q << "coroutine@0x" << std::hex << c.creator_va; x.coroutine_identity = q.str(); }
            x.compiler_profile = destroy.profile;
            x.evidence_state = "EXACT_STRUCTURAL";
            x.priority_reason = "ordinary C++20 coroutine presence is informational; writable heap control fields are capability, not evidence of tampering";
            x.creator_va = c.creator_va;
            x.creator_file_offset = c.creator_file_offset;
            x.frame_allocation_site_va = c.allocation_site_va;
            x.frame_allocation_site_file_offset = c.allocation_site_file_offset;
            x.frame_size_exact = c.frame_size_exact;
            x.frame_size = c.frame_size;
            x.frame_storage = "HEAP_OPERATOR_NEW";
            x.frame_control_pointers_writable = true;
            x.resume_target_va = c.resume_va;
            x.resume_target_file_offset = *ro;
            x.destroy_target_va = c.destroy_va;
            x.destroy_target_file_offset = *doff;
            x.state_frame_offset = resume.state_offset;
            x.state_width = resume.state_width;
            x.final_clears_resume_pointer = resume.clears_resume;
            x.destroy_consumes_common_frame = true;
            x.control_fields.push_back({"resume_pointer", 0, 8, c.resume_va, *ro, true, "EXACT_CODE_POINTER_STORE"});
            x.control_fields.push_back({"destroy_pointer", 8, 8, c.destroy_va, *doff, true, "EXACT_CODE_POINTER_STORE"});
            x.control_fields.push_back({"state_discriminator", resume.state_offset, resume.state_width, 0, 0, false, "EXACT_FRAME_READ_WRITE"});
            x.suspend_sites = resume.suspend_sites;
            std::ostringstream detail;
            detail << "allocator=" << c.allocator << "; common frame stores exact resume/destroy code pointers at +0/+8; "
                   << "resume reads/writes state @+0x" << std::hex << resume.state_offset << std::dec
                   << " and clears frame+0 at finalization; destroy profile=" << destroy.profile;
            x.detail = detail.str();
            out.entries.push_back(std::move(x));
        }
    }
    out.confirmed_count = out.entries.size();
    if (!out.entries.empty()) out.state = "RESOLVED";
    else if (out.candidate_creator_count) out.state = "NOT_PRESENT";
    return out;
}

} // namespace prts
