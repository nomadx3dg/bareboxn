# bareboxn

A native, rootless Linux and BSD OS emulator.

bareboxn (pronounced "barebon") is an independent AArch64 system emulator written in
C++20. It does not use QEMU as a backend; QEMU and Unicorn are used only as references
and test oracles. The long-term target is an Android-native (NDK) emulator for ARM64
Linux and BSD guests.

## Status

Early foundation. What exists today:

- AArch64 integer interpreter (EL0/EL1, exceptions, system registers) - see
  [docs/CPU_STATUS.md](docs/CPU_STATUS.md)
- Stage-1 MMU (4K/16K/64K granules, ASIDs, TBI, permissions, access-flag faults) with a software
  TLB, `AT`/`TLBI`, verified against QEMU system emulation
- Minimal PSCI (version, features, system off/reset) on `bbn-virt`
- Guest-physical memory bus with lazily committed RAM and MMIO dispatch
- PL011 UART and a minimal `bbn-virt` machine (QEMU `virt`-compatible memory map)
- `bbn-run`, a runner for flat bare-metal binaries
- Unit tests, generated instruction vectors, and differential fuzzers against Unicorn (instructions)
  and QEMU system emulation (MMU)

What does **not** exist yet: FP/SIMD, interrupt controller, timers, virtio, SMP, JIT,
Android app. No Linux or BSD guest boots yet. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design decisions, the review of the
feasibility report, and known gaps.

## Build and test

```sh
cmake -S . -B build -G Ninja      # or omit -G Ninja to use Makefiles
cmake --build build
ctest --test-dir build --output-on-failure
```

Requires a C++20 compiler and CMake 3.16+ (tested with GCC 13.3 on Linux x86-64; other
compilers, macOS and the Android NDK have not been tried yet).

## Run a bare-metal image

```sh
build/bbn-run --regs image.bin            # loads at 0x40000000, UART -> stdout
```

Exit status: `0` on `HLT` or PSCI power-off, `2` on instruction limit/WFI, `3` on unsupported guest
behaviour, `4` on PSCI reset, `1` on error.

## Verification tools (optional, Python)

```sh
pip install keystone-engine unicorn capstone
python3 tests/gen_vectors.py --verify-unicorn             # regenerate + cross-check vectors
python3 tools/difftest/difftest.py --build-dir build -n 20000     # instruction fuzz vs Unicorn
# MMU fuzz vs real QEMU (needs qemu-system-aarch64; golden replay in ctest does not):
python3 tools/mmu/mmu_diff.py --build-dir build --seeds 1-40
```

## License

BSD 3-Clause, see [LICENSE](LICENSE).
