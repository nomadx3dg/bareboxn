// System register access (MRS/MSR). Unimplemented registers are UNDEFINED, which is the
// architecturally correct behaviour for a missing feature and makes gaps loud, not silent.
#include "core/bits.h"
#include "cpu/cpu.h"

namespace bbn {
namespace {

constexpr uint32_t K(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
  return sysreg_key(op0, op1, crn, crm, op2);
}

struct StoreReg {
  uint32_t key;
  uint64_t CpuState::*field;
};

// Plain read/write EL1 (or EL0) registers with no side effects in this model.
constexpr StoreReg kStore[] = {
    {K(3, 0, 1, 0, 2), &CpuState::cpacr_el1},
    {K(3, 0, 2, 0, 0), &CpuState::ttbr0_el1},
    {K(3, 0, 2, 0, 1), &CpuState::ttbr1_el1},
    {K(3, 0, 2, 0, 2), &CpuState::tcr_el1},
    {K(3, 0, 4, 0, 0), &CpuState::spsr_el1},
    {K(3, 0, 4, 0, 1), &CpuState::elr_el1},
    {K(3, 0, 5, 1, 0), &CpuState::afsr0_el1},
    {K(3, 0, 5, 1, 1), &CpuState::afsr1_el1},
    {K(3, 0, 5, 2, 0), &CpuState::esr_el1},
    {K(3, 0, 6, 0, 0), &CpuState::far_el1},
    {K(3, 0, 7, 4, 0), &CpuState::par_el1},
    {K(3, 0, 10, 2, 0), &CpuState::mair_el1},
    {K(3, 0, 12, 0, 0), &CpuState::vbar_el1},
    {K(3, 0, 13, 0, 1), &CpuState::contextidr_el1},
    {K(3, 0, 13, 0, 4), &CpuState::tpidr_el1},
    {K(3, 0, 14, 1, 0), &CpuState::cntkctl_el1},
    {K(3, 2, 0, 0, 0), &CpuState::csselr_el1},
    {K(3, 3, 13, 0, 2), &CpuState::tpidr_el0},
    {K(3, 3, 13, 0, 3), &CpuState::tpidrro_el0},
};

constexpr uint32_t MIDR_EL1 = K(3, 0, 0, 0, 0);
constexpr uint32_t MPIDR_EL1 = K(3, 0, 0, 0, 5);
constexpr uint32_t REVIDR_EL1 = K(3, 0, 0, 0, 6);
constexpr uint32_t ID_AA64PFR0_EL1 = K(3, 0, 0, 4, 0);
constexpr uint32_t ID_AA64DFR0_EL1 = K(3, 0, 0, 5, 0);
constexpr uint32_t ID_AA64MMFR0_EL1 = K(3, 0, 0, 7, 0);
constexpr uint32_t CCSIDR_EL1 = K(3, 1, 0, 0, 0);
constexpr uint32_t CLIDR_EL1 = K(3, 1, 0, 0, 1);
constexpr uint32_t AIDR_EL1 = K(3, 1, 0, 0, 7);
constexpr uint32_t CTR_EL0 = K(3, 3, 0, 0, 1);
constexpr uint32_t DCZID_EL0 = K(3, 3, 0, 0, 7);
constexpr uint32_t SCTLR_EL1 = K(3, 0, 1, 0, 0);
constexpr uint32_t SP_EL0 = K(3, 0, 4, 1, 0);
constexpr uint32_t SPSEL = K(3, 0, 4, 2, 0);
constexpr uint32_t CURRENTEL = K(3, 0, 4, 2, 2);
constexpr uint32_t NZCV = K(3, 3, 4, 2, 0);
constexpr uint32_t DAIF = K(3, 3, 4, 2, 1);
constexpr uint32_t AMAIR_EL1 = K(3, 0, 10, 3, 0);
constexpr uint32_t CNTFRQ_EL0 = K(3, 3, 14, 0, 0);
constexpr uint32_t CNTPCT_EL0 = K(3, 3, 14, 0, 1);
constexpr uint32_t CNTVCT_EL0 = K(3, 3, 14, 0, 2);

// ID register values advertised to the guest. Everything not listed reads as zero (RAZ),
// i.e. "feature not implemented" (no CRC32, atomics, AES/SHA, RNG, PAuth, SVE, MTE, ...).
constexpr uint64_t kMidr = 0x000FBB00;  // implementer 0 (software), architecture "see ID regs", part 0xBB0
// ID_AA64PFR0_EL1: EL0=AArch64 only, EL1=AArch64 only, EL2/EL3 absent, FP and AdvSIMD
// *not implemented* (0xF), GIC system-register interface absent.
constexpr uint64_t kPfr0 = (0x1ull << 0) | (0x1ull << 4) | (0xFull << 16) | (0xFull << 20);
// ID_AA64DFR0_EL1: ARMv8.0 debug architecture (6), 2 breakpoints, 2 watchpoints, no PMU.
constexpr uint64_t kDfr0 = 0x6 | (1ull << 12) | (1ull << 20);
// ID_AA64MMFR0_EL1: PARange = 40 bits, 16-bit ASIDs, 4K and 64K granules (field 0 = supported)
// and 16K granule (field 1 = supported). Big-endian and mixed-endian are not implemented.
constexpr uint64_t kMmfr0 = 0x2 | (0x2 << 4) | (0x1ull << 20);
// CTR_EL0: 64-byte cache lines, PIPT instruction caches, CWG/ERG 64 bytes.
constexpr uint64_t kCtr = 0x84448004;
constexpr uint64_t kDczid = 0x10;  // DZP=1: DC ZVA prohibited

constexpr uint64_t SCTLR_E0E = 1ull << 24, SCTLR_EE = 1ull << 25, SCTLR_UMA = 1ull << 9;

}  // namespace

void Cpu::write_sctlr(uint64_t v) {
  const uint64_t be = v & (SCTLR_EE | SCTLR_E0E);
  // Big-endian data accesses are not implemented: do not retain the bits, report to the host.
  s_.sctlr_el1 = v & ~(SCTLR_EE | SCTLR_E0E);
  flush_tlb();  // M, WXN and friends change how every cached translation must be interpreted
  if (be)
    request_stop(StopReason::Unsupported,
                 "guest requested big-endian data accesses (SCTLR_EL1.EE/E0E): not implemented");
}

bool Cpu::read_sysreg(uint32_t key, uint64_t& out) {
  const unsigned op0 = key >> 14, op1 = (key >> 11) & 7, crn = (key >> 7) & 15, crm = (key >> 3) & 15;

  // Debug architecture registers (MDSCR_EL1, OSLAR_EL1, DBGBVR<n>_EL1, ...): RAZ/WI at EL1.
  if (op0 == 2) {
    if (s_.el == 0 || op1 != 0) return false;
    out = 0;
    return true;
  }
  if (op0 != 3) return false;

  // --- registers accessible from EL0 (subject to enable bits) ---
  switch (key) {
    case NZCV:
      out = (uint64_t{s_.n} << 31) | (uint64_t{s_.z} << 30) | (uint64_t{s_.c} << 29) | (uint64_t{s_.v} << 28);
      return true;
    case K(3, 3, 13, 0, 2): out = s_.tpidr_el0; return true;
    case K(3, 3, 13, 0, 3): out = s_.tpidrro_el0; return true;
    case CTR_EL0: out = kCtr; return true;
    case DCZID_EL0: out = kDczid; return true;
    case DAIF:
      if (s_.el == 0 && !(s_.sctlr_el1 & SCTLR_UMA)) return false;
      out = uint64_t{s_.daif} << 6;
      return true;
    case CNTFRQ_EL0:
      if (s_.el == 0 && !(s_.cntkctl_el1 & 3)) return false;
      out = cfg_.cntfrq;
      return true;
    case CNTPCT_EL0:
      if (s_.el == 0 && !(s_.cntkctl_el1 & 1)) return false;
      out = counter();
      return true;
    case CNTVCT_EL0:
      if (s_.el == 0 && !(s_.cntkctl_el1 & 2)) return false;
      out = counter();
      return true;
    default: break;
  }
  if (s_.el == 0) return false;  // everything below is EL1-only

  for (const StoreReg& r : kStore) {
    if (r.key == key) {
      out = s_.*(r.field);
      return true;
    }
  }
  switch (key) {
    case SCTLR_EL1: out = s_.sctlr_el1; return true;
    case SP_EL0: out = s_.sp_el0; return true;
    case SPSEL: out = s_.sp_sel ? 1 : 0; return true;
    case CURRENTEL: out = uint64_t{s_.el} << 2; return true;
    case AMAIR_EL1: out = 0; return true;
    case MIDR_EL1: out = kMidr; return true;
    case MPIDR_EL1: out = mpidr(); return true;
    case REVIDR_EL1: case CCSIDR_EL1: case CLIDR_EL1: case AIDR_EL1: out = 0; return true;
    case ID_AA64PFR0_EL1: out = kPfr0; return true;
    case ID_AA64DFR0_EL1: out = kDfr0; return true;
    case ID_AA64MMFR0_EL1: out = kMmfr0; return true;
    default: break;
  }
  // Remaining feature-ID space (op1=0, CRn=0, CRm=1..7) is RAZ for unimplemented registers.
  if (op1 == 0 && crn == 0 && crm >= 1 && crm <= 7) {
    out = 0;
    return true;
  }
  return false;
}

bool Cpu::write_sysreg(uint32_t key, uint64_t value) {
  const unsigned op0 = key >> 14, op1 = (key >> 11) & 7;
  if (op0 == 2) return s_.el == 1 && op1 == 0;  // debug registers: RAZ/WI
  if (op0 != 3) return false;

  switch (key) {
    case NZCV:
      s_.n = (value >> 31) & 1; s_.z = (value >> 30) & 1; s_.c = (value >> 29) & 1; s_.v = (value >> 28) & 1;
      return true;
    case K(3, 3, 13, 0, 2): s_.tpidr_el0 = value; return true;
    case DAIF:
      if (s_.el == 0 && !(s_.sctlr_el1 & SCTLR_UMA)) return false;
      s_.daif = static_cast<uint8_t>((value >> 6) & 0xF);
      return true;
    default: break;
  }
  if (s_.el == 0) return false;

  for (const StoreReg& r : kStore) {
    if (r.key == key) {
      s_.*(r.field) = value;
      // Table base / ASID changes retarget instruction fetch; TCR/MAIR reinterpret all cached
      // translations. (TLB entries are ASID-tagged, so TTBR writes need not flush them.)
      if (key == K(3, 0, 2, 0, 0) || key == K(3, 0, 2, 0, 1)) fc_valid_ = false;
      else if (key == K(3, 0, 2, 0, 2) || key == K(3, 0, 10, 2, 0)) flush_tlb();
      return true;
    }
  }
  switch (key) {
    case SCTLR_EL1: write_sctlr(value); return true;
    case SP_EL0: s_.sp_el0 = value; return true;
    case SPSEL: s_.sp_sel = value & 1; return true;
    case AMAIR_EL1: return true;  // WI
    case CNTFRQ_EL0: cfg_.cntfrq = value & 0xFFFFFFFFull; return true;
    default: return false;  // read-only (ID, CurrentEL, counters) or unimplemented
  }
}

}  // namespace bbn
