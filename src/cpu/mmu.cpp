// Stage-1 address translation for the EL1&0 regime: table walk, permission checks,
// software TLB and the AT instructions. Not implemented: stage 2, hardware AF/dirty
// updates (ID_AA64MMFR1_EL1.HAFDBS = 0), PAN, 52-bit addresses, LVA, MTE.
#include <algorithm>

#include "core/bits.h"
#include "cpu/cpu.h"

namespace bbn {
namespace {

constexpr uint64_t SCTLR_WXN = 1ull << 19;
enum Perm : uint8_t { R0 = 1, W0 = 2, X0 = 4, R1 = 8, W1 = 16, X1 = 32 };

// TCR_EL1.IPS -> output address width, capped at the advertised PARange (40 bits).
unsigned pa_bits_from_ips(unsigned ips) {
  static const unsigned kBits[8] = {32, 36, 40, 42, 44, 48, 48, 48};
  return std::min(kBits[ips & 7], 40u);
}

}  // namespace

void Cpu::flush_tlb() {
  for (TlbEntry& e : tlb_) e.vpn = ~uint64_t{0};
  fc_valid_ = false;
}

uint16_t Cpu::current_asid() const {
  const uint64_t ttbr = ((s_.tcr_el1 >> 22) & 1) ? s_.ttbr1_el1 : s_.ttbr0_el1;  // TCR.A1
  const uint16_t asid = static_cast<uint16_t>(ttbr >> 48);
  return ((s_.tcr_el1 >> 36) & 1) ? asid : static_cast<uint16_t>(asid & 0xFF);     // TCR.AS
}

// With TBI enabled for the region a branch target falls in, the tag byte is not part of the
// PC: it is replaced by the sign-extension of bit 55 (so ELR/FAR for fetch faults are tag-free).
uint64_t Cpu::branch_addr(uint64_t target) const {
  if (!mmu_enabled()) return target;
  const bool upper = (target >> 55) & 1;
  if (!((s_.tcr_el1 >> (upper ? 38 : 37)) & 1)) return target;
  return (target & 0x00FFFFFFFFFFFFFFull) | (upper ? 0xFF00000000000000ull : 0);
}

Cpu::Trans Cpu::translate_core(uint64_t va, Access acc, bool el0) {
  Trans t;
  if (!mmu_enabled()) {  // MMU off: identity mapping (see docs for the memory-type deviation)
    t.ok = true;
    t.pa = va;
    return t;
  }
  const bool upper = (va >> 55) & 1;  // selects TTBR1
  const bool tbi = (s_.tcr_el1 >> (upper ? 38 : 37)) & 1;
  uint64_t cv = va;
  if (tbi) cv = (va & 0x00FFFFFFFFFFFFFFull) | (upper ? 0xFF00000000000000ull : 0);
  const uint64_t vpn = cv >> 12;

  TlbEntry& e = tlb_[(vpn ^ (vpn >> 9)) & (kTlbSize - 1)];
  if (e.vpn == vpn && (e.global || e.asid == current_asid())) {
    const unsigned need = el0 ? (acc == Access::Read ? R0 : acc == Access::Write ? W0 : X0)
                              : (acc == Access::Read ? R1 : acc == Access::Write ? W1 : X1);
    if (!(e.perm & need)) {
      t.fsc = static_cast<uint8_t>(0x0C | e.level);  // permission fault
      return t;
    }
    t.ok = true;
    t.pa = e.pa_page | (cv & 0xFFF);
    t.device = e.device;
    t.attr = e.attr;
    t.sh = e.sh;
    return t;
  }
  return walk(cv, upper, acc, el0, e);
}

Cpu::Trans Cpu::walk(uint64_t cv, bool upper, Access acc, bool el0, TlbEntry& slot) {
  Trans t;
  const uint64_t tcr = s_.tcr_el1;
  unsigned txsz = static_cast<unsigned>(upper ? (tcr >> 16) & 0x3F : tcr & 0x3F);
  txsz = std::clamp(txsz, 16u, 39u);
  const bool epd = (tcr >> (upper ? 23 : 7)) & 1;
  const unsigned tg = static_cast<unsigned>(upper ? (tcr >> 30) & 3 : (tcr >> 14) & 3);
  unsigned g;  // log2(granule); reserved TGx encodings fall back to 4K
  if (upper) g = tg == 1 ? 14 : tg == 3 ? 16 : 12;
  else       g = tg == 2 ? 14 : tg == 1 ? 16 : 12;
  const unsigned ia = 64 - txsz;

  // The bits above the input-address size must all equal the region-select bit.
  const uint64_t hi = ~mask_n(ia);
  if (epd || (upper ? (cv & hi) != hi : (cv & hi) != 0)) {
    t.fsc = 0x04;  // translation fault, level 0
    return t;
  }

  const unsigned stride = g - 3;
  const unsigned nlev = (ia - g + stride - 1) / stride;
  const unsigned start = 4 - nlev;
  const unsigned topbits = ia - g - (nlev - 1) * stride;
  const unsigned pa_bits = pa_bits_from_ips(static_cast<unsigned>((tcr >> 32) & 7));

  uint64_t table = (upper ? s_.ttbr1_el1 : s_.ttbr0_el1) & mask_n(48) & ~uint64_t{1};
  table &= ~((uint64_t{8} << topbits) - 1);
  if (table >> pa_bits) {
    t.fsc = static_cast<uint8_t>(start);  // address size fault
    return t;
  }

  unsigned aptable = 0;
  bool uxn_table = false, pxn_table = false;
  for (unsigned level = start; level <= 3; ++level) {
    const unsigned shift = g + (3 - level) * stride;
    const unsigned ibits = level == start ? topbits : stride;
    const uint64_t index = (cv >> shift) & mask_n(ibits);
    uint64_t desc = 0;
    if (bus_.read(table + index * 8, 8, desc) != BusResult::Ok) {
      t.fsc = static_cast<uint8_t>(0x14 | level);  // external abort on table walk
      t.ext = true;
      return t;
    }
    if (!(desc & 1)) {
      t.fsc = static_cast<uint8_t>(0x04 | level);  // translation fault
      return t;
    }
    const bool bit1 = desc & 2;
    if (level < 3 && bit1) {  // table descriptor
      const uint64_t next = desc & mask_n(48) & ~mask_n(g);
      if (next >> pa_bits) {
        t.fsc = static_cast<uint8_t>(level);  // address size fault
        return t;
      }
      aptable |= static_cast<unsigned>((desc >> 61) & 3);
      uxn_table |= (desc >> 60) & 1;
      pxn_table |= (desc >> 59) & 1;
      table = next;
      continue;
    }
    if (level == 3 ? !bit1 : false) {  // level-3 encoding 0b01 is reserved
      t.fsc = 0x07;
      return t;
    }
    if (level < 3) {  // block descriptor: only some levels allow it, depending on granule
      const bool allowed = g == 12 ? (level == 1 || level == 2) : level == 2;
      if (!allowed) {
        t.fsc = static_cast<uint8_t>(0x04 | level);
        return t;
      }
    }
    const uint64_t oa = (desc & mask_n(48) & ~mask_n(shift)) | (cv & mask_n(shift));
    if (oa >> pa_bits) {
      t.fsc = static_cast<uint8_t>(level);  // address size fault
      return t;
    }
    if (!((desc >> 10) & 1)) {
      t.fsc = static_cast<uint8_t>(0x08 | level);  // access flag fault (no HW AF update)
      return t;
    }

    const bool ap2 = ((desc >> 7) & 1) || (aptable & 2);
    const bool ap1 = ((desc >> 6) & 1) && !(aptable & 1);
    const bool uxn = ((desc >> 54) & 1) || uxn_table;
    const bool pxn = ((desc >> 53) & 1) || pxn_table;
    const bool wxn = s_.sctlr_el1 & SCTLR_WXN;
    uint8_t perm = 0;
    const bool w0 = ap1 && !ap2, w1 = !ap2;
    if (ap1) perm |= R0;
    if (w0) perm |= W0;
    // Instruction fetch permission is independent of read permission: EL0 may execute a page it
    // cannot read (arm64 Linux "execute-only" mappings rely on this), so only UXN/WXN matter.
    if (!uxn && !(wxn && w0)) perm |= X0;
    perm |= R1;
    if (w1) perm |= W1;
    // EL1 may not execute a page that EL0 can write (implicit PXN), nor any writable page if WXN.
    if (!pxn && !w0 && !(wxn && w1)) perm |= X1;

    const unsigned attr_idx = static_cast<unsigned>((desc >> 2) & 7);
    const uint8_t attr = static_cast<uint8_t>((s_.mair_el1 >> (attr_idx * 8)) & 0xFF);
    const bool device = (attr & 0xF0) == 0;

    slot.vpn = cv >> 12;
    slot.pa_page = oa & ~uint64_t{0xFFF};
    slot.asid = current_asid();
    slot.global = !((desc >> 11) & 1);
    slot.perm = perm;
    slot.level = static_cast<uint8_t>(level);
    slot.device = device;
    slot.attr = attr;
    slot.sh = device ? 2 : static_cast<uint8_t>((desc >> 8) & 3);

    const unsigned need = el0 ? (acc == Access::Read ? R0 : acc == Access::Write ? W0 : X0)
                              : (acc == Access::Read ? R1 : acc == Access::Write ? W1 : X1);
    if (!(perm & need)) {
      t.fsc = static_cast<uint8_t>(0x0C | level);  // permission fault
      return t;
    }
    t.ok = true;
    t.pa = oa;
    t.device = device;
    t.attr = attr;
    t.sh = slot.sh;
    return t;
  }
  t.fsc = 0x07;  // unreachable: level 3 always terminates the loop
  return t;
}

bool Cpu::resolve(uint64_t va, unsigned size, Access acc, bool force_align, MemLoc& loc) {
  const bool write = acc == Access::Write;
  const bool unaligned = (va & (size - 1)) != 0;
  if (unaligned && (force_align || (s_.sctlr_el1 & (1u << 1)))) {  // exclusives, or SCTLR_EL1.A
    raise_data_abort(va, write, 0x21, false);
    return false;
  }
  const bool el0 = s_.el == 0 || unpriv_;
  Trans t = translate_core(va, acc, el0);
  if (!t.ok) {
    raise_data_abort(va, write, t.fsc, t.ext);
    return false;
  }
  loc.pa0 = t.pa;
  loc.split = false;
  bool device = t.device;
  if (mmu_enabled() && (va & 0xFFF) + size > 0x1000) {
    // The access straddles two 4K pages that may map to unrelated physical pages. Both must
    // translate before anything is read or written; a fault reports the lowest address of
    // the faulting page.
    const unsigned n1 = 0x1000 - static_cast<unsigned>(va & 0xFFF);
    const uint64_t va2 = va + n1;
    Trans t2 = translate_core(va2, acc, el0);
    if (!t2.ok) {
      raise_data_abort(va2, write, t2.fsc, t2.ext);
      return false;
    }
    loc.pa1 = t2.pa;
    loc.n1 = n1;
    loc.split = true;
    device = device || t2.device;
  }
  // Unaligned access to Device memory faults, but only after every page it touches translated.
  if (unaligned && device) {
    raise_data_abort(va, write, 0x21, false);
    return false;
  }
  return true;
}

bool Cpu::fetch_pa(uint64_t va, uint64_t& pa) {
  if (!mmu_enabled()) {
    pa = va;
    return true;
  }
  const uint64_t page = va >> 12;
  if (fc_valid_ && fc_page_ == page && fc_el_ == s_.el) {
    pa = fc_pa_ | (va & 0xFFF);
    return true;
  }
  Trans t = translate_core(va, Access::Exec, s_.el == 0);
  if (!t.ok) {
    raise_inst_abort(va, t.fsc, t.ext);
    return false;
  }
  fc_valid_ = true;
  fc_page_ = page;
  fc_el_ = s_.el;
  fc_pa_ = t.pa & ~uint64_t{0xFFF};
  pa = t.pa;
  return true;
}

// AT S1E1R/S1E1W/S1E0R/S1E0W: translate without faulting and report the result in PAR_EL1.
void Cpu::exec_at(unsigned op1, unsigned crm, unsigned op2, uint64_t va) {
  if (op1 != 0 || crm != 8 || op2 > 3) return undef();
  const bool el0 = op2 >= 2, write = op2 & 1;
  const Trans t = translate_core(va, write ? Access::Write : Access::Read, el0);
  if (t.ok) {
    s_.par_el1 = (uint64_t{t.attr} << 56) | (t.pa & mask_n(48) & ~uint64_t{0xFFF}) | (1ull << 11) |
                 (1ull << 9) /* NS: this machine has a single (Non-secure) world */ |
                 (uint64_t{t.sh} << 7);
  } else {
    s_.par_el1 = 1 | (uint64_t{t.fsc} << 1);
  }
}

}  // namespace bbn
