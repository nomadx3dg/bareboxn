# bareboxn architecture

bareboxn is an independent system emulator: it implements its own AArch64 CPU,
guest-physical memory system and virtual hardware. QEMU, Unicorn and others are used
only as references and test oracles, never linked into the runtime.

This document records the current design, the decisions taken and their rationale,
and how the supplied feasibility report was reviewed. Anything not implemented is
listed explicitly in [CPU_STATUS.md](CPU_STATUS.md) and in "Known gaps" below.

## Layout

| Path | Responsibility |
| :-- | :-- |
| `src/core/` | Bit helpers shared by everything. |
| `src/memory/` | `Bus`: guest-physical address space, lazily committed RAM, MMIO dispatch. |
| `src/cpu/` | AArch64 interpreter: state, decode/execute, exceptions, system registers. |
| `src/devices/` | Device models (PL011 UART so far). Depend only on `memory/`. |
| `src/machine/` | `VirtMachine` (`bbn-virt`): wires CPU, bus and devices together. |
| `tools/bbn-run.cpp` | Run a flat binary on `bbn-virt`. |
| `tools/difftest/` | Differential fuzzer against Unicorn (QEMU TCG). |
| `tests/` | Unit tests, generated instruction vectors, end-to-end program tests. |

Dependency rule (from the report, kept): the CPU core and devices build and test with no
Android, JNI or UI code. Everything is a single static library (`bbn_core`) for now; it
will be split along the report's module lines (`bbn-jit`, `bbn-android`, ...) when those
modules actually exist, not before.

## Machine model: `bbn-virt`

The physical memory map deliberately matches QEMU's AArch64 `virt` board so existing
kernels, device trees and firmware can be compared 1:1:

| Region | Base | Status |
| :-- | :-- | :-- |
| pflash (firmware) | `0x00000000` | reserved |
| GIC | `0x08000000` | reserved (Phase 2) |
| PL011 UART | `0x09000000` | **implemented** |
| RTC | `0x09010000` | reserved |
| virtio-mmio | `0x0a000000` | reserved (Phase 3) |
| RAM | `0x40000000` | **implemented**, configurable size |

Accesses to reserved/unmapped addresses raise a synchronous external abort in the guest
(DFSC `0x10`, EA set), never a silent success.

## Decisions

**D1. C++20, CMake, no third-party runtime dependencies.** Keeps the NDK build trivial and
the binary small. (An NDK build has *not* been exercised yet; see Known gaps.)

**D2. Interpreter first, with explicit architectural state.** The interpreter decodes each
instruction directly. It is the reference semantics for the later JIT: the JIT must match
it instruction-for-instruction under the same differential harness.

**D3. Fail loudly instead of approximating.** A feature that is not implemented is either
UNDEFINED (the architecturally correct result for an absent feature) or stops the CPU with
`StopReason::Unsupported` and a message (e.g. guest enables the MMU). ID registers
advertise only what exists (no FP/SIMD, CRC32, atomics, PAuth, ...), so a guest that
probes features behaves correctly, and a guest that ignores them fails visibly.

**D4. Correctness oracles are layered, and none is trusted blindly.**
(1) Hand-written expectations from the ARM ARM, generated into `tests/vectors_*.inc` with
Keystone-assembled programs; (2) every straight-line vector is also executed on Unicorn;
(3) a random differential fuzzer compares tens of thousands of single instructions per run. The fuzzer
already found a case where Unicorn deviates from the architecture (unaligned
store-exclusive does not fault in QEMU TCG on the failing-monitor path), so such cases are
excluded from comparison and covered by explicit tests instead. The ARM ARM, not QEMU,
is the source of truth.

**D5. Deterministic time by default.** `CNTVCT_EL0` counts retired instructions unless the
machine installs a counter source. Deterministic runs make guest bugs reproducible.

**D6. RAM is anonymous `mmap(MAP_NORESERVE)`.** Untouched guest RAM costs no resident
memory (tested: a 1 GiB region stays far below 64 MiB RSS). Android's overcommit and
low-memory-killer behaviour with this strategy still needs measurement on devices.

**D7. Local exclusive monitor only.** Sufficient for a single vCPU. SMP needs a global
monitor shared by CPUs and cleared by other agents' stores.

## Review of the Perplexity feasibility report

Method: claims were checked against primary or authoritative sources where feasible
inside this session, and against the running code/tests where they concern behaviour.
"Not verified" means exactly that; it is not an endorsement.

### Incorrect or imprecise

1. **"KVM/arm64 depends on ARMv8.1 Virtualization Host Extensions."** Incorrect. KVM/arm64
   runs on ARMv8.0 CPUs in non-VHE ("nVHE") mode; VHE (ARMv8.1+) is a performance
   difference, and pKVM can use either mode. Source: Marc Zyngier (KVM/arm64 maintainer) on
   linux-arm-kernel, <https://patchwork.kernel.org/comment/23506343>. The report's
   conclusion (never make hardware virtualization the baseline) is still right, but for
   different reasons: the real constraints are that ordinary Android apps cannot open
   `/dev/kvm` and that AVF/pKVM availability is device- and version-dependent.
2. **"SIMD/FP only when required by the target kernel and userspace."** In practice this
   gates *any* useful guest userspace: the AArch64 procedure-call standard passes
   floating-point arguments in SIMD registers and libc string/memory routines use NEON.
   FP/ASIMD should be treated as a Phase-2 requirement, not optional. (Engineering
   judgement; not re-verified against distro sources in this session.) Until implemented,
   `ID_AA64PFR0_EL1` advertises FP/AdvSIMD as absent and every such encoding is UNDEFINED.
3. **Test target "Linux kernel built with a minimal configuration"** before a trustworthy
   CPU: this ordering is right, but the report omits the intermediate, cheap oracle that
   caught real bugs here: per-instruction differential testing against Unicorn/QEMU.

### Missing technical requirements

- **PSCI / secondary-CPU bring-up** for SMP guests (an HVC/SMC conduit exists as a hook:
  `Cpu::set_hypercall_handler`; the PSCI implementation does not).
- **Software TLB.** The report lists a TLB for correctness; it is also the dominant
  interpreter performance structure. A page walk per access is a known bottleneck.
- **Decoded-instruction / translation-block cache and I-cache coherence rules** (`IC`/`DC`
  currently no-op because memory is always coherent).
- **Host W^X for the JIT.** Android does not allow arbitrary RWX mappings in all
  configurations; a dual-mapped (memfd) code cache is the usual answer. Not verified here.
- **Global exclusive monitor and memory ordering** for multi-threaded vCPUs.
- **Device tree generation** and the Linux arm64 boot-protocol header parsing.
- **ID-register discipline** (see D3): the report does not discuss controlling which
  features the guest sees, which is the main compatibility lever against newer kernels.

### Architectural comments

- **GICv3-first** is reasonable but not free: virtio-mmio devices only need SPIs (no ITS),
  and a single-core Phase 2 could ship GICv2 faster. Decide when starting Phase 2; both are
  accepted by Linux on QEMU `virt`.
- **Eight modules from day one** (`bbn-cpu`, `bbn-jit`, ...) is premature for a codebase
  that does not yet have a JIT or Android layer; directory boundaries are kept, library
  splits are deferred.
- **"Beat QEMU on footprint/startup"** is plausible but unmeasured. The only number in this
  repository today is the interpreter baseline in `docs/CPU_STATUS.md`.

### Not verified in this session

QEMU/Android/FEX/Box64 documentation claims other than the KVM/VHE point above (including
the Box64 "5-10x DynaRec" figure and the pKVM enablement details). Several report
citations carry tracking parameters or point to commit-pinned mirrors; they should be
re-checked before being relied on.

## Known gaps (honest status)

- No MMU, TLB, generic timer, GIC, virtio, FP/SIMD, LSE atomics, UEFI, device tree, SMP.
- No JIT. No Android app, JNI or NDK build has been produced or tested.
- No Linux or BSD guest has been booted. Nothing in this repository claims otherwise.
- Without an MMU, memory accesses are identity-mapped and unaligned data accesses are
  permitted (real hardware treats MMU-off data accesses as Device memory and faults on
  unaligned ones). This is intentional for bare-metal tests and will be replaced by proper
  memory-type handling with the MMU.
- Deviations from the architecture are documented in `docs/CPU_STATUS.md`.
