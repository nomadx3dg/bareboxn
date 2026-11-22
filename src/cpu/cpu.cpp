// CPU core: reset, step loop, exception entry/return, memory access, ALU helpers.
#include "cpu/cpu.h"

#include <cstring>

#include "core/bits.h"

namespace bbn {

namespace {
constexpr uint8_t EC_ILLEGAL_STATE = 0x0E;
constexpr uint8_t EC_INST_ABORT = 0x21;   // same-EL encoding; converted to 0x20 from EL0
constexpr uint8_t EC_PC_ALIGN = 0x22;
constexpr uint8_t EC_DATA_ABORT = 0x25;   // same-EL encoding; converted to 0x24 from EL0
}  // namespace

Cpu::Cpu(Bus& bus, const CpuConfig& cfg) : bus_(bus), cfg_(cfg) {}

void Cpu::reset(uint64_t entry_pc) {
  uint64_t x[31];
  std::memcpy(x, s_.x, sizeof(x));
  s_ = CpuState{};
  std::memcpy(s_.x, x, sizeof(x));
  s_.pc = entry_pc;
  mon_ = {};
  pend_ = {};
  stop_ = StopReason::None;
  stop_msg_.clear();
}

uint64_t Cpu::sp() const { return (s_.el == 0 || !s_.sp_sel) ? s_.sp_el0 : s_.sp_el1; }

void Cpu::wr_sp(unsigned n, uint64_t v) {
  if (n != 31) {
    s_.x[n] = v;
  } else if (s_.el == 0 || !s_.sp_sel) {
    s_.sp_el0 = v;
  } else {
    s_.sp_el1 = v;
  }
}

void Cpu::request_stop(StopReason r, const std::string& msg) {
  stop_ = r;
  stop_msg_ = msg;
}

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

void Cpu::raise(uint8_t ec, uint32_t iss) {
  pend_.valid = true;
  pend_.ec = ec;
  pend_.iss = iss;
}

void Cpu::raise_data_abort(uint64_t va, bool is_write, uint8_t dfsc, bool external) {
  raise(EC_DATA_ABORT, (dfsc & 0x3Fu) | (is_write ? 1u << 6 : 0u) | (external ? 1u << 9 : 0u));
  pend_.far = va;
  pend_.far_valid = true;
}

void Cpu::raise_inst_abort(uint64_t va, uint8_t ifsc, bool external) {
  raise(EC_INST_ABORT, (ifsc & 0x3Fu) | (external ? 1u << 9 : 0u));
  pend_.far = va;
  pend_.far_valid = true;
}

uint64_t Cpu::pack_spsr() const {
  uint64_t v = (uint64_t{s_.n} << 31) | (uint64_t{s_.z} << 30) | (uint64_t{s_.c} << 29) |
               (uint64_t{s_.v} << 28);
  v |= uint64_t{s_.daif} << 6;
  v |= uint64_t{s_.el} << 2;
  if (s_.el == 1 && s_.sp_sel) v |= 1;
  return v;
}

void Cpu::enter_el1(ExcKind kind, uint64_t elr, uint32_t esr) {
  const unsigned from_el = s_.el;
  const bool from_sph = s_.sp_sel;
  s_.spsr_el1 = pack_spsr();
  s_.elr_el1 = elr;
  if (kind == ExcKind::Sync) s_.esr_el1 = esr;
  s_.el = 1;
  s_.sp_sel = true;
  s_.daif = 0xF;
  uint64_t offset = from_el == 0 ? 0x400 : (from_sph ? 0x200 : 0x000);
  offset += static_cast<uint64_t>(kind) * 0x80;
  s_.pc = (s_.vbar_el1 & ~uint64_t{0x7FF}) + offset;
  mon_.valid = false;
}

void Cpu::take_exception(const Pending& p, uint64_t insn_pc) {
  uint8_t ec = p.ec;
  if (s_.el == 0) {
    if (ec == EC_DATA_ABORT) ec = 0x24;
    if (ec == EC_INST_ABORT) ec = 0x20;
  }
  const uint32_t esr = (uint32_t{ec} << 26) | (1u << 25) | (p.iss & 0x1FFFFFFu);
  if (p.far_valid) s_.far_el1 = p.far;
  enter_el1(ExcKind::Sync, p.return_next ? insn_pc + 4 : insn_pc, esr);
}

void Cpu::take_async(ExcKind kind) { enter_el1(kind, s_.pc, 0); }

void Cpu::set_pstate_from_spsr_bits(uint64_t spsr) {
  s_.n = bit(static_cast<uint32_t>(spsr), 31);
  s_.z = bit(static_cast<uint32_t>(spsr), 30);
  s_.c = bit(static_cast<uint32_t>(spsr), 29);
  s_.v = bit(static_cast<uint32_t>(spsr), 28);
  s_.daif = static_cast<uint8_t>((spsr >> 6) & 0xF);
  const unsigned m = static_cast<unsigned>(spsr & 0xF);
  s_.el = static_cast<uint8_t>((m >> 2) & 3);
  s_.sp_sel = s_.el == 1 && (m & 1);
}

void Cpu::do_eret() {
  const uint64_t spsr = s_.spsr_el1;
  const unsigned m = static_cast<unsigned>(spsr & 0x1F);
  // Legal AArch64 targets here: EL0t (0), EL1t (4), EL1h (5). Anything else (AArch32,
  // EL2/EL3, reserved) is an illegal exception return. Deviation: real hardware sets
  // PSTATE.IL and faults on the *next* instruction; we fault on the ERET itself.
  if (!(m == 0 || m == 4 || m == 5)) {
    raise(EC_ILLEGAL_STATE, 0);
    return;
  }
  set_pstate_from_spsr_bits(spsr);
  next_pc_ = s_.elr_el1;
  mon_.valid = false;
}

// ---------------------------------------------------------------------------
// Step / run
// ---------------------------------------------------------------------------

StopReason Cpu::step() {
  if (fiq_ && !(s_.daif & 1)) {
    take_async(ExcKind::Fiq);
    return StopReason::None;
  }
  if (irq_ && !(s_.daif & 2)) {
    take_async(ExcKind::Irq);
    return StopReason::None;
  }

  cur_pc_ = s_.pc;
  pend_ = Pending{};
  if (cur_pc_ & 3) {
    raise(EC_PC_ALIGN, 0);
    pend_.far = cur_pc_;
    pend_.far_valid = true;
  } else {
    uint32_t insn = 0;
    if (!bus_.fetch32(cur_pc_, insn)) {
      raise_inst_abort(cur_pc_, 0x10, true);
    } else {
      if (trace_) trace_(cur_pc_, insn);
      next_pc_ = cur_pc_ + 4;
      exec(insn);
    }
  }
  ++icount_;
  if (pend_.valid) {
    take_exception(pend_, cur_pc_);
  } else {
    s_.pc = next_pc_;
  }
  if (stop_ != StopReason::None) {
    StopReason r = stop_;
    stop_ = StopReason::None;
    return r;
  }
  return StopReason::None;
}

StopReason Cpu::run(uint64_t max_insns) {
  for (uint64_t i = 0; i < max_insns; ++i) {
    StopReason r = step();
    if (r != StopReason::None) return r;
  }
  return StopReason::InsnLimit;
}

void Cpu::exec(uint32_t insn) {
  switch (bits(insn, 28, 25)) {
    case 0x8: case 0x9: exec_dp_imm(insn); break;
    case 0xA: case 0xB: exec_branch_sys(insn); break;
    case 0x4: case 0x6: case 0xC: case 0xE: exec_ldst(insn); break;
    case 0x5: case 0xD: exec_dp_reg(insn); break;
    default: undef(); break;  // reserved/UDF (0-3), SVE, scalar FP and Advanced SIMD (7, F)
  }
}

// ---------------------------------------------------------------------------
// Memory access (identity-mapped until the MMU lands)
// ---------------------------------------------------------------------------

bool Cpu::mem_read(uint64_t va, unsigned size, uint64_t& v, bool require_aligned) {
  if (require_aligned && (va & (size - 1))) {
    raise_data_abort(va, false, 0x21, false);
    return false;
  }
  if (bus_.read(va, size, v) != BusResult::Ok) {
    raise_data_abort(va, false, 0x10, true);
    return false;
  }
  return true;
}

bool Cpu::mem_write(uint64_t va, unsigned size, uint64_t v, bool require_aligned) {
  if (require_aligned && (va & (size - 1))) {
    raise_data_abort(va, true, 0x21, false);
    return false;
  }
  if (bus_.write(va, size, v) != BusResult::Ok) {
    raise_data_abort(va, true, 0x10, true);
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// ALU helpers
// ---------------------------------------------------------------------------

uint64_t Cpu::add_with_carry(uint64_t x, uint64_t y, unsigned carry_in, bool sf, bool set_flags) {
  if (sf) {
    const uint64_t s = x + y;
    const bool c1 = s < x;
    const uint64_t r = s + carry_in;
    const bool c2 = r < s;
    if (set_flags) {
      s_.n = r >> 63;
      s_.z = r == 0;
      s_.c = c1 || c2;
      s_.v = (((~(x ^ y)) & (x ^ r)) >> 63) & 1;
    }
    return r;
  }
  const uint32_t a = static_cast<uint32_t>(x), b = static_cast<uint32_t>(y);
  const uint32_t s = a + b;
  const bool c1 = s < a;
  const uint32_t r = s + carry_in;
  const bool c2 = r < s;
  if (set_flags) {
    s_.n = r >> 31;
    s_.z = r == 0;
    s_.c = c1 || c2;
    s_.v = (((~(a ^ b)) & (a ^ r)) >> 31) & 1;
  }
  return r;
}

void Cpu::set_nz(uint64_t r, bool sf) {
  if (sf) {
    s_.n = r >> 63;
    s_.z = r == 0;
  } else {
    s_.n = (r >> 31) & 1;
    s_.z = static_cast<uint32_t>(r) == 0;
  }
}

bool Cpu::cond_holds(unsigned cond) const {
  bool r = false;
  switch (cond >> 1) {
    case 0: r = s_.z; break;                         // EQ/NE
    case 1: r = s_.c; break;                         // CS/CC
    case 2: r = s_.n; break;                         // MI/PL
    case 3: r = s_.v; break;                         // VS/VC
    case 4: r = s_.c && !s_.z; break;                // HI/LS
    case 5: r = s_.n == s_.v; break;                 // GE/LT
    case 6: r = (s_.n == s_.v) && !s_.z; break;      // GT/LE
    default: return true;                            // AL and NV both behave as "always"
  }
  return (cond & 1) ? !r : r;
}

uint64_t Cpu::shift_val(uint64_t v, unsigned type, unsigned amt, unsigned dsize) {
  if (dsize == 32) {
    const uint32_t x = static_cast<uint32_t>(v);
    switch (type) {
      case 0: return static_cast<uint32_t>(x << amt);
      case 1: return x >> amt;
      case 2: return static_cast<uint32_t>(static_cast<int32_t>(x) >> amt);
      default: return amt ? static_cast<uint32_t>((x >> amt) | (x << (32 - amt))) : x;
    }
  }
  switch (type) {
    case 0: return v << amt;
    case 1: return v >> amt;
    case 2: return static_cast<uint64_t>(static_cast<int64_t>(v) >> amt);
    default: return amt ? ((v >> amt) | (v << (64 - amt))) : v;
  }
}

uint64_t Cpu::extend_val(uint64_t v, unsigned option, unsigned shift) {
  const bool is_signed = option & 4;
  uint64_t x = 0;
  switch (option & 3) {
    case 0: x = is_signed ? static_cast<uint64_t>(sext(v, 8)) : (v & 0xFF); break;
    case 1: x = is_signed ? static_cast<uint64_t>(sext(v, 16)) : (v & 0xFFFF); break;
    case 2: x = is_signed ? static_cast<uint64_t>(sext(v, 32)) : (v & 0xFFFFFFFFull); break;
    default: x = v; break;
  }
  return x << shift;
}

}  // namespace bbn
