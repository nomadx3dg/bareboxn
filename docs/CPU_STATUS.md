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
| DMB/DSB/ISB, IC/DC (except ZVA) | Done as no-ops (single-threaded, coherent memory) |
| MRS/MSR, MSR (immediate) for SPSel/DAIFSet/DAIFClear | Done for the registers below |
| Scalar FP, Advanced SIMD, SVE | UNDEF |
| LSE atomics (CAS/SWP/LDADD...), CRC32, AES/SHA, PAuth, BTI, MTE | UNDEF |
| LDTR/STTR | Done (checked with EL0 permissions when executed at EL1) |
| AT S1E1R/S1E1W/S1E0R/S1E0W | Done (result in `PAR_EL1`; never faults) |
| TLBI VMALLE1/VAE1/ASIDE1/VAAE1/VALE1/VAALE1 (+IS) | Done (always flushes the whole soft TLB, which is permitted) |
| DC ZVA, AT S1E1RP/WP, range/outer-shareable TLBI | UNDEF |
| HVC/SMC | PSCI 1.0 subset on `bbn-virt` (see below); UNDEF for other function IDs |

## Exception model

EL0 and EL1 only. Synchronous exceptions, IRQ and FIQ are taken to EL1 with the correct
vector offsets (current-EL SP0/SPx, lower-EL AArch64), ESR/FAR/ELR/SPSR updates, DAIF
masking and SP banking. Fault classes produced: Undefined (EC 0x00), SVC (0x15), BRK
(0x3C), instruction abort (0x20/0x21, external abort), PC alignment (0x22), data abort
(0x24/0x25, external abort or alignment fault), illegal exception return (0x0E).

## System registers

Read/write: SCTLR_EL1, CPACR, TTBR0/1, TCR, MAIR, AMAIR (WI), ESR, FAR,
ELR, SPSR, VBAR, AFSR0/1, PAR, CONTEXTIDR, TPIDR_EL0/EL1, TPIDRRO_EL0, CNTKCTL, CSSELR,
SP_EL0, SPSel, DAIF, NZCV, CNTFRQ. Read-only: MIDR, MPIDR, REVIDR, CurrentEL, CTR_EL0,
DCZID_EL0, CLIDR/CCSIDR/AIDR (0), ID_AA64PFR0/DFR0/MMFR0 (advertise only what exists; the
rest of the feature-ID space reads as zero; ID_AA64MMFR0_EL1 = 40-bit PARange, 16-bit ASIDs, 4K/16K/64K granules), CNTVCT_EL0/CNTPCT_EL0 (instruction-count
based unless a counter source is installed). Debug registers (op0=2) are RAZ/WI.
Anything else is UNDEFINED. EL0 access follows `SCTLR_EL1.UMA` and `CNTKCTL_EL1`.

Not implemented (UNDEF on access): generic timer control/compare registers
(CNTV_*/CNTP_*), PMU, GIC system-register interface.

## MMU (stage 1, EL1&0)

Implemented: translation through `TTBR0_EL1`/`TTBR1_EL1` (region chosen by VA bit 55), 4K, 16K
and 64K granules, `T0SZ`/`T1SZ` 16-39 (input addresses 25-48 bits), `EPD0/1`, `TBI0/1`,
`IPS` (capped at the advertised 40-bit PARange), page and block descriptors (levels allowed per
granule), table/page/block validity rules, hierarchical `APTable`/`UXNTable`/`PXNTable`, access
flag faults, permission faults (AP, UXN/PXN, `SCTLR_EL1.WXN`), address size faults, external
aborts on table walks, ASIDs (8/16-bit, `TCR_EL1.A1/AS`) with non-global entries tagged, and a
512-entry software TLB plus a one-entry fetch cache. MAIR attribute types are used only to
distinguish Device from Normal memory.

Behaviours worth knowing (all cross-checked against QEMU unless stated):

- Instruction-fetch permission depends on UXN/PXN/WXN only, **not** on AP[1]: EL0 can execute a
  page it cannot read (arm64 Linux execute-only mappings). A page writable at EL0 is never
  executable at EL1 (implicit PXN).
- With TBI, branch targets (`BR/BLR/RET/ERET`) lose their tag, so `ELR`/`FAR` for fetch faults
  are tag-free; data-access `FAR` keeps the tag.
- A page-straddling access translates both pages before touching memory; a fault reports the
  lowest address of the faulting page and no partial write happens.
- Unaligned access to Device memory raises an alignment fault; `SCTLR_EL1.A` makes every
  unaligned access fault. (QEMU does **not** model the Device case, so this is covered by
  unit tests only.)
- TTBR writes do not flush the TLB (entries are ASID-tagged); writes to TCR/MAIR/SCTLR and any
  TLBI flush it. Stale entries after a descriptor change persist until TLBI, as on hardware.

Not implemented: stage 2, hardware AF/dirty update (`HAFDBS`), PAN/UAO, 52-bit addresses/LPA2,
LVA, MTE, `TCR_EL1.TBID`, `HPD`, `SCTLR_EL1.SA` stack alignment checks. Big-endian
(`SCTLR_EL1.EE/E0E`) is not retained and stops execution with `Unsupported`.

With the MMU **off**, accesses are identity-mapped and unaligned data accesses are permitted
(real hardware treats MMU-off data accesses as Device memory and faults on unaligned ones).

## PSCI

`bbn-virt` services PSCI 1.0 through HVC or SMC: `VERSION`, `FEATURES`, `SYSTEM_OFF`
(`StopReason::PowerOff`), `SYSTEM_RESET` (`StopReason::Reset`), `MIGRATE_INFO_TYPE`, and
single-CPU `CPU_ON`/`AFFINITY_INFO`. `CPU_SUSPEND`/`CPU_OFF` return NOT_SUPPORTED. Other
function IDs are not PSCI and raise UNDEFINED. There is no SMP yet.

## Known deviations from the architecture

- Illegal exception return (`ERET` with an invalid SPSR mode) faults on the `ERET` itself
  instead of setting PSTATE.IL and faulting on the next instruction.
- `PSTATE.NZCV` is left unchanged on exception entry (saved in SPSR). The ARM ARM pseudocode
  was not re-checked; software cannot normally observe this.
- `PAR_EL1.NS` is set on successful `AT` (matching QEMU; not verified against the ARM ARM).
- No SP alignment check; MMU-off data accesses are not treated as Device memory (see above).
- Exclusive monitor: single local monitor keyed on the virtual address and size; stores by
  other agents (DMA) do not clear it.

## Verification

| Check | Result (this revision) |
| :-- | :-- |
| `ctest`: bus, pl011, cpu_vectors, cpu_system, mmu, psci, machine, mmu_golden | 8 of 8 pass |
| Generated vectors: 128 basic + 35 system; 126 cross-checked on Unicorn | 0 disagreements |
| Integer ISA fuzz vs Unicorn (`tools/difftest/difftest.py`), 60k cases + 32k more after the MMU change | 0 state mismatches (only CRC32, unimplemented, differs) |
| MMU fuzz vs **QEMU 8.2.2** (`tools/mmu/mmu_diff.py`, `-M virt -cpu max`) | 200+ random scenarios, ~8,000 compared transcript lines, 0 mismatches after fixes |
| Golden replay of 40 QEMU-verified scenarios (`mmu_golden`) | pass (skipped if keystone is not installed) |
| ASan + UBSan: all unit tests, goldens, integer fuzz | clean |
| Mutation check: 4 integer-ISA + 7 MMU deliberate bugs | all detected |
| Throughput, Release, 1 shared Xeon 2.3 GHz core, ALU/load/store loop | ~65-85 MIPS MMU off, ~68 MIPS MMU on; A/B against the Phase 1 build shows no regression (host timing is noisy) |

What the QEMU oracle found in this implementation (all fixed): tags were not stripped from
branch targets under TBI; EL0 exec was wrongly gated on AP[1]; EL1 could execute EL0-writable
pages; page-straddling accesses checked Device alignment before translating the second page.
What it found in QEMU/Unicorn (not copied): no alignment fault for unaligned Device accesses
(QEMU) and none for unaligned store-exclusive on the failing path (Unicorn). Those cases are
excluded from comparison and asserted in unit tests instead.
