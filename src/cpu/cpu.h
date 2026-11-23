// AArch64 (ARMv8-A, AArch64-only) reference interpreter.
//
// Scope of this implementation (see docs/CPU_STATUS.md for the full matrix):
//   * EL0 and EL1 only; no EL2/EL3, no AArch32.
//   * Integer base instruction set, exclusives, barriers, system registers.
//   * Stage-1 MMU (4K/16K/64K granules, TTBR0/TTBR1, ASIDs, TBI, hierarchical
//     permissions, access-flag faults) with a software TLB; no stage 2, no
//     hardware AF/dirty updates, no PAN.
//   * No FP/Advanced SIMD (encodings are UNDEFINED, ID_AA64PFR0_EL1 says so).
//
// The interpreter is the reference semantics for a future JIT: every
// instruction is decoded and executed through explicit architectural state.
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "memory/bus.h"

namespace bbn {

enum class StopReason : uint8_t {
  None,         // (internal) keep running
  InsnLimit,    // run() reached its instruction budget
  Halt,         // HLT executed (harness stop; see CpuConfig::hlt_is_stop)
  Wfi,          // WFI with no interrupt pending: the scheduler should wait for an event
  PowerOff,     // guest requested power off (PSCI SYSTEM_OFF)
  Reset,        // guest requested a system reset (PSCI SYSTEM_RESET)
  Unsupported,  // guest used a feature this CPU model does not implement; see stop_message()
};

struct CpuConfig {
  uint32_t cpu_id = 0;              // reported in MPIDR_EL1.Aff0
  uint64_t cntfrq = 62'500'000;     // CNTFRQ_EL0 (same as QEMU's virt machine)
  bool hlt_is_stop = true;          // HLT stops run(); otherwise HLT is UNDEFINED
};

struct CpuState {
  uint64_t x[31] = {};
  uint64_t sp_el0 = 0;
  uint64_t sp_el1 = 0;
  uint64_t pc = 0;
  bool n = false, z = false, c = false, v = false;  // PSTATE.NZCV
  uint8_t el = 1;                                   // current exception level (0 or 1)
  bool sp_sel = true;                               // PSTATE.SP (true: SP_ELx); always false at EL0
  uint8_t daif = 0xF;                               // bit3=D bit2=A bit1=I bit0=F

  // EL1 system registers that are plain read/write storage.
  uint64_t sctlr_el1 = 0x30D00800;  // reset value: RES1 bits only, MMU/caches off
  uint64_t cpacr_el1 = 0, ttbr0_el1 = 0, ttbr1_el1 = 0, tcr_el1 = 0, mair_el1 = 0;
  uint64_t esr_el1 = 0, far_el1 = 0, elr_el1 = 0, spsr_el1 = 0, vbar_el1 = 0;
  uint64_t afsr0_el1 = 0, afsr1_el1 = 0, par_el1 = 0, csselr_el1 = 0;
  uint64_t contextidr_el1 = 0, tpidr_el1 = 0, cntkctl_el1 = 0;
  uint64_t tpidr_el0 = 0, tpidrro_el0 = 0;
};

class Cpu {
 public:
  // Called for HVC/SMC. Return true if handled (execution continues after the
  // instruction); false makes the instruction UNDEFINED (no EL2/EL3 present).
  using HypercallHandler = std::function<bool(Cpu&, bool is_smc, uint16_t imm)>;
  using TraceHook = std::function<void(uint64_t pc, uint32_t insn)>;

  explicit Cpu(Bus& bus, const CpuConfig& cfg = CpuConfig{});

  // Architectural reset: EL1h, DAIF masked, PC = entry_pc. Registers are preserved
  // except system registers, which return to reset values.
  void reset(uint64_t entry_pc);

  StopReason step();                   // execute one instruction (or take one interrupt)
  StopReason run(uint64_t max_insns);  // run until a stop reason or the budget is exhausted

  CpuState& state() { return s_; }
  const CpuState& state() const { return s_; }
  uint64_t sp() const;               // current stack pointer (SP_EL0 or SP_EL1)
  uint64_t instructions_retired() const { return icount_; }
  const std::string& stop_message() const { return stop_msg_; }
  uint32_t halt_imm() const { return halt_imm_; }
  uint64_t mpidr() const { return 0x80000000ull | cfg_.cpu_id; }  // value read by MRS MPIDR_EL1

  void set_irq(bool level) { irq_ = level; }
  void set_fiq(bool level) { fiq_ = level; }
  void set_hypercall_handler(HypercallHandler h) { hvc_ = std::move(h); }
  void set_trace_hook(TraceHook h) { trace_ = std::move(h); }
  // Source for CNTVCT_EL0/CNTPCT_EL0. Default: the retired-instruction count, which
  // keeps execution fully deterministic.
  void set_counter_source(std::function<uint64_t()> f) { counter_src_ = std::move(f); }
  uint64_t counter() const { return counter_src_ ? counter_src_() : icount_; }

  // Host-side control: stop run() at the end of the current instruction.
  void request_stop(StopReason r, const std::string& msg = {});
  // Drop every cached translation (as TLBI VMALLE1 does).
  void flush_tlb();

 private:
  // --- pending synchronous exception raised by the instruction being executed ---
  struct Pending {
    bool valid = false;
    uint8_t ec = 0;
    uint32_t iss = 0;
    uint64_t far = 0;
    bool far_valid = false;
    bool return_next = false;  // preferred return address is the next instruction (SVC/HVC/SMC)
  };
  enum class ExcKind : uint8_t { Sync = 0, Irq = 1, Fiq = 2 };

  // --- register access (31 = ZR for rd/wr, SP for rd_sp/wr_sp) ---
  uint64_t rd(unsigned n) const { return n == 31 ? 0 : s_.x[n]; }
  void wr(unsigned n, uint64_t v) { if (n != 31) s_.x[n] = v; }
  uint64_t rd_sp(unsigned n) const { return n == 31 ? sp() : s_.x[n]; }
  void wr_sp(unsigned n, uint64_t v);
  void wr_w(unsigned n, uint64_t v32) { wr(n, v32 & 0xFFFFFFFFull); }

  // --- exceptions ---
  void raise(uint8_t ec, uint32_t iss = 0);
  void undef() { raise(0x00); }
  void raise_data_abort(uint64_t va, bool is_write, uint8_t dfsc, bool external);
  void raise_inst_abort(uint64_t va, uint8_t ifsc, bool external);
  void take_exception(const Pending& p, uint64_t insn_pc);
  void take_async(ExcKind kind);
  void enter_el1(ExcKind kind, uint64_t elr, uint32_t esr);
  uint64_t pack_spsr() const;
  void do_eret();

  // --- address translation (mmu.cpp) ---
  enum class Access : uint8_t { Read, Write, Exec };
  struct Trans {
    bool ok = false;
    uint64_t pa = 0;
    uint8_t fsc = 0;      // DFSC/IFSC when !ok
    bool ext = false;     // external abort (EA) on a table walk
    bool device = false;  // Device memory type (unaligned accesses fault)
    uint8_t attr = 0;     // MAIR attribute byte
    uint8_t sh = 0;
  };
  struct TlbEntry {
    uint64_t vpn = ~uint64_t{0};  // canonical VA >> 12; all-ones = invalid
    uint64_t pa_page = 0;
    uint16_t asid = 0;
    bool global = false;
    uint8_t perm = 0;             // bit0 r0, 1 w0, 2 x0, 3 r1, 4 w1, 5 x1
    uint8_t level = 0;
    bool device = false;
    uint8_t attr = 0;
    uint8_t sh = 0;
  };
  static constexpr size_t kTlbSize = 512;
  struct MemLoc {
    uint64_t pa0 = 0, pa1 = 0;
    unsigned n1 = 0;  // bytes in the first page when the access straddles two pages
    bool split = false;
  };
  bool mmu_enabled() const { return s_.sctlr_el1 & 1; }
  uint64_t branch_addr(uint64_t target) const;  // AArch64.BranchAddr: drop the TBI tag from a PC
  uint16_t current_asid() const;
  Trans translate_core(uint64_t va, Access acc, bool el0);
  Trans walk(uint64_t cv, bool upper, Access acc, bool el0, TlbEntry& slot);
  bool resolve(uint64_t va, unsigned size, Access acc, bool force_align, MemLoc& loc);
  bool fetch_pa(uint64_t va, uint64_t& pa);
  void exec_at(unsigned op1, unsigned crm, unsigned op2, uint64_t va);

  // --- memory access through the MMU ---
  bool mem_read(uint64_t va, unsigned size, uint64_t& v, bool require_aligned = false);
  bool mem_write(uint64_t va, unsigned size, uint64_t v, bool require_aligned = false);

  // --- ALU helpers ---
  uint64_t add_with_carry(uint64_t x, uint64_t y, unsigned carry_in, bool sf, bool set_flags);
  void set_nz(uint64_t result, bool sf);
  bool cond_holds(unsigned cond) const;
  static uint64_t shift_val(uint64_t v, unsigned type, unsigned amt, unsigned dsize);
  static uint64_t extend_val(uint64_t v, unsigned option, unsigned shift);

  // --- decode / execute (one translation unit per instruction class) ---
  void exec(uint32_t insn);
  void exec_dp_imm(uint32_t insn);
  void exec_dp_reg(uint32_t insn);
  void exec_branch_sys(uint32_t insn);
  void exec_ldst(uint32_t insn);
  void exec_ldst_reg(uint32_t insn);
  void exec_ldst_pair(uint32_t insn);
  void exec_ldst_literal(uint32_t insn);
  void exec_ldst_exclusive(uint32_t insn);
  void exec_system(uint32_t insn);
  void exec_exception_gen(uint32_t insn);
  void exec_msr_imm(uint32_t insn);

  // --- system registers (sysregs.cpp). Return false => UNDEFINED. ---
  bool read_sysreg(uint32_t key, uint64_t& out);
  bool write_sysreg(uint32_t key, uint64_t value);
  void write_sctlr(uint64_t v);
  void set_pstate_from_spsr_bits(uint64_t spsr);

  Bus& bus_;
  CpuConfig cfg_;
  CpuState s_;
  uint64_t icount_ = 0;
  uint64_t next_pc_ = 0;
  uint64_t cur_pc_ = 0;
  bool irq_ = false, fiq_ = false;
  Pending pend_;
  StopReason stop_ = StopReason::None;
  std::string stop_msg_;
  uint32_t halt_imm_ = 0;

  struct Monitor {
    bool valid = false;
    uint64_t addr = 0;
    unsigned size = 0;
  } mon_;

  std::array<TlbEntry, kTlbSize> tlb_;
  bool unpriv_ = false;  // LDTR/STTR: access checked with EL0 permissions
  // One-entry instruction-fetch translation cache (invalidated with the TLB and on TTBR writes).
  bool fc_valid_ = false;
  uint64_t fc_page_ = 0, fc_pa_ = 0;
  uint8_t fc_el_ = 0;

  HypercallHandler hvc_;
  TraceHook trace_;
  std::function<uint64_t()> counter_src_;

};

// Pack a system register encoding (op0, op1, CRn, CRm, op2) into the 16-bit key
// that appears in bits [20:5] of MRS/MSR instructions.
constexpr uint32_t sysreg_key(uint32_t op0, uint32_t op1, uint32_t crn, uint32_t crm, uint32_t op2) {
  return (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
}

}  // namespace bbn
