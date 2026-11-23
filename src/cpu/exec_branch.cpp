// Branches, exception-generating instructions, hints/barriers and system instructions.
#include "core/bits.h"
#include "cpu/cpu.h"

namespace bbn {

void Cpu::exec_branch_sys(uint32_t i) {
  const unsigned hi = bits(i, 31, 25);

  // B / BL (unconditional immediate): x00101
  if (bits(i, 30, 26) == 0x05) {
    const uint64_t target = cur_pc_ + static_cast<uint64_t>(sext(bits(i, 25, 0), 26) * 4);
    if (bit(i, 31)) wr(30, cur_pc_ + 4);
    next_pc_ = target;
    return;
  }
  // CBZ / CBNZ: x011010x
  if (bits(i, 30, 25) == 0x1A) {
    const bool sf = bit(i, 31);
    uint64_t v = rd(bits(i, 4, 0));
    if (!sf) v &= 0xFFFFFFFFull;
    if ((v == 0) != bit(i, 24)) next_pc_ = cur_pc_ + static_cast<uint64_t>(sext(bits(i, 23, 5), 19) * 4);
    return;
  }
  // TBZ / TBNZ: x011011x
  if (bits(i, 30, 25) == 0x1B) {
    const unsigned pos = (bit(i, 31) << 5) | bits(i, 23, 19);
    const bool set = (rd(bits(i, 4, 0)) >> pos) & 1;
    if (set == bit(i, 24)) next_pc_ = cur_pc_ + static_cast<uint64_t>(sext(bits(i, 18, 5), 14) * 4);
    return;
  }
  // B.cond: 01010100 ... 0 cond   (bit 4 set would be BC.cond, FEAT_HBC: not implemented)
  if (bits(i, 31, 24) == 0x54) {
    if (bit(i, 4)) return undef();
    if (cond_holds(bits(i, 3, 0))) next_pc_ = cur_pc_ + static_cast<uint64_t>(sext(bits(i, 23, 5), 19) * 4);
    return;
  }
  // Exception generation: 11010100
  if (bits(i, 31, 24) == 0xD4) return exec_exception_gen(i);
  // System: 1101010100
  if (bits(i, 31, 22) == 0x354) return exec_system(i);
  // Unconditional branch (register): 1101011
  if (hi == 0x6B) {
    const unsigned opc = bits(i, 24, 21), rn = bits(i, 9, 5);
    if (bits(i, 20, 16) != 0x1F || bits(i, 15, 10) != 0 || bits(i, 4, 0) != 0) return undef();
    switch (opc) {
      case 0: next_pc_ = branch_addr(rd(rn)); return;                     // BR
      case 1: { const uint64_t t = branch_addr(rd(rn)); wr(30, cur_pc_ + 4); next_pc_ = t; return; }  // BLR
      case 2: next_pc_ = branch_addr(rd(rn)); return;                     // RET
      case 4:                                                             // ERET
        if (rn != 31 || s_.el == 0) return undef();
        return do_eret();
      default: return undef();  // DRPS, PAC-authenticated forms
    }
  }
  undef();
}

void Cpu::exec_exception_gen(uint32_t i) {
  const unsigned opc = bits(i, 23, 21), ll = bits(i, 1, 0), op2 = bits(i, 4, 2);
  const uint16_t imm16 = static_cast<uint16_t>(bits(i, 20, 5));
  if (op2 != 0) return undef();
  if (opc == 0 && ll >= 1 && ll <= 3) {  // SVC / HVC / SMC
    if (ll == 1) {
      raise(0x15, imm16);
      pend_.return_next = true;
      return;
    }
    if (hvc_ && hvc_(*this, ll == 3, imm16)) return;  // handled: continue at next instruction
    return undef();  // no EL2/EL3 to trap to
  }
  if (opc == 1 && ll == 0) {  // BRK
    raise(0x3C, imm16);
    return;
  }
  if (opc == 2 && ll == 0 && cfg_.hlt_is_stop) {  // HLT (harness stop)
    halt_imm_ = imm16;
    request_stop(StopReason::Halt);
    return;
  }
  undef();  // DCPS*, HLT when not a stop, reserved
}

void Cpu::exec_msr_imm(uint32_t i) {
  const unsigned op1 = bits(i, 18, 16), crm = bits(i, 11, 8), op2 = bits(i, 7, 5);
  if (bits(i, 4, 0) != 31) return undef();
  if (s_.el == 0) return undef();
  if (op1 == 0 && op2 == 5) {  // SPSel
    s_.sp_sel = crm & 1;
  } else if (op1 == 3 && op2 == 6) {  // DAIFSet
    s_.daif |= crm;
  } else if (op1 == 3 && op2 == 7) {  // DAIFClear
    s_.daif &= static_cast<uint8_t>(~crm);
  } else {
    undef();  // PAN/UAO/DIT/SSBS/TCO etc.: not implemented
  }
}

void Cpu::exec_system(uint32_t i) {
  const bool l = bit(i, 21);
  const unsigned op0 = bits(i, 20, 19), op1 = bits(i, 18, 16), crn = bits(i, 15, 12);
  const unsigned crm = bits(i, 11, 8), op2 = bits(i, 7, 5), rt = bits(i, 4, 0);

  if (op0 == 0) {
    if (l) return undef();
    if (op1 != 3 && !(crn == 4)) return undef();
    if (crn == 4) return exec_msr_imm(i);
    if (rt != 31) return undef();
    if (crn == 2) {  // HINT. WFE/SEV/SEVL/YIELD and unallocated hints are NOPs (WFE may legally
                     // return immediately). WFI hands control back to the scheduler unless an
                     // interrupt is already pending (pending interrupts wake WFI even when masked).
      if (((crm << 3) | op2) == 3 && !irq_ && !fiq_) request_stop(StopReason::Wfi);
      return;
    }
    if (crn == 3) {        // barriers
      switch (op2) {
        case 2: mon_.valid = false; return;  // CLREX
        case 4: case 5: case 6: return;      // DSB / DMB / ISB: single-threaded interpreter, no-op
        default: return undef();             // SB etc.
      }
    }
    return undef();
  }
  if (op0 == 1) {  // SYS / SYSL: cache and TLB maintenance
    if (l) return undef();
    if (s_.el == 0 && !(op1 == 3 && crn == 7)) return undef();
    if (crn == 8) {  // TLBI (EL1 forms): VMALLE1, VAE1, ASIDE1, VAAE1, VALE1, VAALE1; IS/non-IS
      if (op1 == 0 && (crm == 3 || crm == 7) && (op2 <= 3 || op2 == 5 || op2 == 7)) {
        flush_tlb();  // over-invalidating is always architecturally permitted
        return;
      }
      return undef();
    }
    if (crn == 7) {
      if (op1 == 3 && crm == 4 && op2 == 1) return undef();  // DC ZVA (DCZID_EL0.DZP = 1)
      if (crm == 8) return exec_at(op1, crm, op2, rd(rt));   // AT S1E1R/S1E1W/S1E0R/S1E0W
      if (crm == 9) return undef();                          // AT S1E1RP/WP (FEAT_PAN2)
      return;                                                // IC/DC: memory is always coherent
    }
    return undef();
  }
  // MRS / MSR (register)
  const uint32_t key = (i >> 5) & 0xFFFF;
  if (l) {
    uint64_t v = 0;
    if (!read_sysreg(key, v)) return undef();
    wr(rt, v);
  } else {
    if (!write_sysreg(key, rd(rt))) return undef();
  }
}

}  // namespace bbn
