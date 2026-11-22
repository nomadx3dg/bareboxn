# AArch64 CPU status

Legend: **Done** = implemented and covered by tests. **UNDEF** = deliberately raises an
Undefined Instruction exception (feature not implemented or not advertised).

## Instruction classes

| Class | Status |
| :-- | :-- |
| Add/sub immediate, shifted and extended register, with/without flags | Done |
| Add/sub with carry (ADC/SBC/ADCS/SBCS) | Done |
| Logical immediate (all bitmask encodings) and shifted register | Done |
| Move wide (MOVN/MOVZ/MOVK), ADR/ADRP | Done |
| Bitfield (SBFM/BFM/UBFM and all aliases), EXTR/ROR | Done |
| Conditional select/compare (CSEL/CSINC/CSINV/CSNEG, CCMP/CCMN) | Done |
| Multiply, multiply-add/sub, SMULL/UMULL families, SMULH/UMULH | Done |
| UDIV/SDIV (architectural divide-by-zero and INT_MIN/-1 results) | Done |
| Variable shifts, RBIT, REV/REV16/REV32, CLZ, CLS | Done |
| B/BL, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR/BLR/RET, ERET | Done |
| SVC, BRK; HVC/SMC via hypercall hook (UNDEF without a handler) | Done |
| HLT | Harness stop by default (`CpuConfig::hlt_is_stop`), UNDEF otherwise |
| LDR/STR (imm, unscaled, pre/post-index, register offset), byte/half/word/signed | Done |
| LDP/STP/LDNP/STNP/LDPSW, LDR literal, LDRSW literal, PRFM (nop) | Done |
| LDXR/STXR/LDAXR/STLXR (all sizes), LDXP/STXP, LDAR/STLR, CLREX | Done (local monitor) |
| NOP/YIELD/WFE/SEV hints; WFI (returns `StopReason::Wfi`) | Done |
| DMB/DSB/ISB, IC/DC (except ZVA)/TLBI | Done as no-ops (single-threaded, coherent) |
| MRS/MSR, MSR (immediate) for SPSel/DAIFSet/DAIFClear | Done for the registers below |
| Scalar FP, Advanced SIMD, SVE | UNDEF |
| LSE atomics (CAS/SWP/LDADD...), CRC32, AES/SHA, PAuth, BTI, MTE | UNDEF |
| LDTR/STTR | Treated as ordinary accesses (no unprivileged-access model yet) |
| DC ZVA, AT | UNDEF |

## Exception model

EL0 and EL1 only. Synchronous exceptions, IRQ and FIQ are taken to EL1 with the correct
vector offsets (current-EL SP0/SPx, lower-EL AArch64), ESR/FAR/ELR/SPSR updates, DAIF
masking and SP banking. Fault classes produced: Undefined (EC 0x00), SVC (0x15), BRK
(0x3C), instruction abort (0x20/0x21, external abort), PC alignment (0x22), data abort
(0x24/0x25, external abort or alignment fault), illegal exception return (0x0E).

## System registers

Read/write: SCTLR_EL1 (see MMU note), CPACR, TTBR0/1, TCR, MAIR, AMAIR (WI), ESR, FAR,
ELR, SPSR, VBAR, AFSR0/1, PAR, CONTEXTIDR, TPIDR_EL0/EL1, TPIDRRO_EL0, CNTKCTL, CSSELR,
SP_EL0, SPSel, DAIF, NZCV, CNTFRQ. Read-only: MIDR, MPIDR, REVIDR, CurrentEL, CTR_EL0,
DCZID_EL0, CLIDR/CCSIDR/AIDR (0), ID_AA64PFR0/DFR0/MMFR0 (advertise only what exists; the
rest of the feature-ID space reads as zero), CNTVCT_EL0/CNTPCT_EL0 (instruction-count
based unless a counter source is installed). Debug registers (op0=2) are RAZ/WI.
Anything else is UNDEFINED. EL0 access follows `SCTLR_EL1.UMA` and `CNTKCTL_EL1`.

Not implemented (UNDEF on access): generic timer control/compare registers
(CNTV_*/CNTP_*), PMU, GIC system-register interface.

## MMU

Not implemented. Writing `SCTLR_EL1.M=1` (or EE/E0E) is not retained and stops execution
with `StopReason::Unsupported` and an explanatory message.

## Known deviations from the architecture

- Illegal exception return (`ERET` with an invalid SPSR mode) faults on the `ERET` itself
  instead of setting PSTATE.IL and faulting on the next instruction.
- `PSTATE.NZCV` is left unchanged on exception entry (saved in SPSR). The ARM ARM
  pseudocode was not re-checked in this session; software cannot normally observe this.
- No SP alignment check (`SCTLR_EL1.SA`), no unaligned-access fault for MMU-off data
  accesses (see ARCHITECTURE.md).
- Exclusive monitor: single local monitor, exact address+size match; stores by other
  agents (DMA) do not clear it.

## Verification

| Check | Result (this revision) |
| :-- | :-- |
| `ctest` (5 suites: bus, pl011, cpu_vectors, cpu_system, machine) | all pass |
| Generated vectors: 128 basic + 33 system | all pass |
| Basic vectors cross-checked on Unicorn (`gen_vectors.py --verify-unicorn`) | 126 vectors, 0 disagreements |
| Differential fuzz (`tools/difftest/difftest.py`), 60k cases seed 7 | 0 state mismatches; only CRC32 (unimplemented) differs |
| ASan + UBSan build: tests and 24k fuzz cases | clean |
| Mutation check (4 deliberate bugs) | all detected by the test suite |
| Interpreter throughput, Release, 1 core Xeon 2.3 GHz, tight ALU/load/store loop | ~94 MIPS (no MMU; baseline only) |
