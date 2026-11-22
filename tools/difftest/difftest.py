#!/usr/bin/env python3
"""Differential fuzzer: bareboxn's AArch64 interpreter vs. Unicorn (QEMU TCG).

Generates random single instructions from the implemented classes (data-processing
immediate/register, loads/stores, branches), executes each on both engines from an
identical random initial state, and compares X0-X30, SP, NZCV, PC and a window of
memory. "Both raise an exception" counts as a match (exception details differ).

    pip install unicorn capstone
    cmake --build build && python3 tools/difftest/difftest.py --build-dir build -n 20000

Unicorn's default CPU enables extensions bareboxn does not advertise (LSE atomics,
PAuth, ...). Mismatches where Unicorn executes but bareboxn raises UNDEFINED are
therefore reported in a separate "unimplemented-extension candidate" bucket and
listed with disassembly so they can be reviewed rather than hidden.
"""
import argparse, collections, os, random, struct, subprocess, sys, zlib

try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UcError, UC_ERR_FETCH_UNMAPPED
    from unicorn import arm64_const as C
except ImportError:
    sys.exit("difftest needs the 'unicorn' package (pip install unicorn)")
try:
    import capstone
    CS = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
except ImportError:
    CS = None

RAM_BASE, RAM_SIZE = 0x100000, 0x100000
CODE = 0x180000
WIN_BASE, WIN_SIZE = 0x170000, 0x2000
DATA_PTR = 0x171000
M64 = (1 << 64) - 1
INTERESTING = [0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000,
               0xFFFFFFFF, 0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
               0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA]


def rv(r):
    k = r.random()
    if k < 0.45:
        return r.choice(INTERESTING)
    if k < 0.65:
        return r.getrandbits(32)
    if k < 0.75:
        return (-r.getrandbits(8)) & M64
    return r.getrandbits(64)


def small(r):  # small signed offsets keep register-offset addressing inside the data window
    return (r.randrange(-0x100, 0x100)) & M64


def gen_dpimm(r):
    return (r.getrandbits(32) & ~(7 << 26)) | (4 << 26)


def gen_dpreg(r):
    return (r.getrandbits(32) & ~(7 << 25)) | (5 << 25)


def gen_ldst(r):
    w = r.getrandbits(32)
    w |= (1 << 27)
    w &= ~((1 << 26) | (1 << 25))  # V=0, op0 pattern x1x0
    return w


def gen_branch(r):
    k = r.randrange(7)
    w = r.getrandbits(32)
    if k == 0:
        return 0x14000000 | (w & 0x03FFFFFF) | ((w >> 31) << 31)          # B / BL
    if k == 1:
        return 0x34000000 | (w & 0x80FFFFFF)                               # CBZ/CBNZ
    if k == 2:
        return 0x36000000 | (w & 0x80FFFFFF)                               # TBZ/TBNZ
    if k == 3:
        return 0x54000000 | (w & 0x00FFFFE0) | (w & 0xF)                   # B.cond
    return 0xD61F0000 | ((r.choice([0, 1, 2])) << 21) | (w & 0x3E0)        # BR / BLR / RET


GENS = {"dpimm": gen_dpimm, "dpreg": gen_dpreg, "ldst": gen_ldst, "branch": gen_branch}


def skip_unpredictable(w, cls):
    if cls != "ldst":
        return False
    rt, rn, rt2, rs = w & 31, (w >> 5) & 31, (w >> 10) & 31, (w >> 16) & 31
    if rn != 31 and (rt == rn or rt2 == rn):
        return True
    if rt == rt2 and ((w >> 27) & 7) in (5, 1):
        return True
    if ((w >> 27) & 7) == 1 and rs in (rt, rn, rt2) and rs != 31:
        return True
    return False


def unaligned_exclusive(w, x, sp):
    """Exclusive/ordered accesses must be naturally aligned. The ARM ARM faults even when the
    store-exclusive would fail; QEMU does not on every path, so such cases are not compared
    (alignment faults are covered by tests/test_cpu_system.cpp instead)."""
    if (w >> 24) & 0x3F != 0x08:
        return False
    size = w >> 30
    total = (1 << size) * (2 if (w >> 21) & 1 and not (w >> 23) & 1 else 1)
    rn = (w >> 5) & 31
    addr = sp if rn == 31 else x[rn]
    return addr % total != 0


def make_state(r, cls):
    x = [rv(r) for _ in range(31)]
    sp = rv(r)
    if cls == "ldst":
        x = [small(r) if r.random() < 0.8 else rv(r) for _ in range(31)]
        sp = DATA_PTR + (r.randrange(0, 0x800) & ~0xF)
    return x, sp, r.getrandbits(4)


def prep_base(w, x, sp, r, cls):
    if cls != "ldst":
        return
    rn = (w >> 5) & 31
    off = (r.randrange(-0x400, 0x400) & ~0xF) + r.choice([0, 0, 0, 1, 3, 7])
    if rn < 31:
        x[rn] = DATA_PTR + off


class Ref:
    def __init__(self, pattern):
        self.pattern = pattern
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mu.mem_map(RAM_BASE, RAM_SIZE)
        self.xr = [getattr(C, "UC_ARM64_REG_X%d" % i) for i in range(31)]

    def run(self, insn, sp, nzcv, x):
        mu = self.mu
        mu.mem_write(RAM_BASE, self.pattern)
        mu.mem_write(CODE, struct.pack("<I", insn))
        for i in range(31):
            mu.reg_write(self.xr[i], x[i])
        mu.reg_write(C.UC_ARM64_REG_SP, sp)
        mu.reg_write(C.UC_ARM64_REG_NZCV, nzcv << 28)
        try:
            mu.emu_start(CODE, CODE + 4, count=1)
        except UcError as e:
            # A taken branch to unmapped memory faults on the *next* fetch in Unicorn, after
            # the branch itself has retired; the register state is already final.
            if e.errno != UC_ERR_FETCH_UNMAPPED:
                return ("exc",)
        pc = mu.reg_read(C.UC_ARM64_REG_PC)
        regs = [mu.reg_read(self.xr[i]) for i in range(31)]
        nz = (mu.reg_read(C.UC_ARM64_REG_NZCV) >> 28) & 0xF
        crc = zlib.crc32(bytes(mu.mem_read(WIN_BASE, WIN_SIZE))) & 0xFFFFFFFF
        return ("ok", pc, mu.reg_read(C.UC_ARM64_REG_SP), nz, regs, crc)


def parse_bbn(line):
    t = line.split()
    if t[0] == "exc":
        return ("exc",)
    return ("ok", int(t[1], 16), int(t[2], 16), int(t[3], 16), [int(v, 16) for v in t[4:35]], int(t[35], 16))


# Extensions that bareboxn intentionally does not implement or advertise (ID_AA64ISAR0_EL1 = 0).
# Unicorn's default CPU implements them, so these are expected, not failures.
UNIMPLEMENTED_EXTENSIONS = ("crc32",)


def disasm(w):
    if not CS:
        return "%08x" % w
    for i in CS.disasm(struct.pack("<I", w), 0):
        return "%s %s" % (i.mnemonic, i.op_str)
    return "(undecoded) %08x" % w


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("-n", type=int, default=20000, help="cases per class")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--classes", default=",".join(GENS))
    ap.add_argument("--show", type=int, default=12, help="mismatches to print per bucket")
    a = ap.parse_args()

    r = random.Random(a.seed)
    pattern = bytes(r.getrandbits(8) for _ in range(RAM_SIZE))
    pat_path = os.path.join(a.build_dir, "difftest.pattern")
    open(pat_path, "wb").write(pattern)
    exe = os.path.join(a.build_dir, "bbn-difftest")
    p = subprocess.Popen([exe, pat_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    ref = Ref(pattern)

    total = collections.Counter()
    mism = collections.defaultdict(list)
    compared_ok = collections.Counter()
    for cls in a.classes.split(","):
        n = 0
        while n < a.n:
            w = GENS[cls](r)
            if skip_unpredictable(w, cls):
                continue
            x, sp, nzcv = make_state(r, cls)
            prep_base(w, x, sp, r, cls)
            if cls == "ldst" and unaligned_exclusive(w, x, sp):
                continue
            ref_res = ref.run(w, sp, nzcv, x)
            p.stdin.write("%x %x %x %s\n" % (w, sp, nzcv, " ".join("%x" % v for v in x)))
            p.stdin.flush()
            bbn_res = parse_bbn(p.stdout.readline())
            n += 1
            total[cls] += 1
            if ref_res == bbn_res or (ref_res[0] == "exc" and bbn_res[0] == "exc"):
                if ref_res[0] == "ok":
                    compared_ok[cls] += 1
                continue
            if ref_res[0] == "ok" and bbn_res[0] == "exc":
                bucket = "%s: reference executes, bareboxn UNDEF/faults (extension candidate)" % cls
            elif ref_res[0] == "exc":
                bucket = "%s: bareboxn executes, reference faults/UNDEF" % cls
            else:
                bucket = "%s: STATE MISMATCH" % cls
            mism[bucket].append((w, ref_res, bbn_res))
    p.stdin.close()
    p.wait()

    print("cases:", dict(total))
    print("cases executed identically on both (non-exception):", dict(compared_ok))
    bad = 0
    expected = 0
    for bucket, items in sorted(mism.items()):
        if "extension candidate" in bucket:
            known = [t for t in items if disasm(t[0]).startswith(UNIMPLEMENTED_EXTENSIONS)]
            items = [t for t in items if t not in known]
            expected += len(known)
            if not items:
                continue
        print("\n== %s: %d" % (bucket, len(items)))
        seen = collections.Counter()
        shown = 0
        for w, rr, bb in items:
            d = disasm(w)
            key = d.split()[0] if d else "?"
            seen[key] += 1
            if shown < a.show and seen[key] <= 2:
                print("  %08x  %-34s ref=%s bbn=%s" % (w, d, rr[0], bb[0]) +
                      ("" if rr[0] == "exc" or bb[0] == "exc" else "  [%s]" % describe_diff(rr, bb)))
                shown += 1
        print("  by mnemonic:", dict(seen.most_common(15)))
        bad += len(items)
    print("\nexpected (documented unimplemented extensions):", expected)
    print("TOTAL MISMATCHES:", bad)
    return 0 if bad == 0 else 1


def describe_diff(rr, bb):
    names = ["pc", "sp", "nzcv"]
    out = []
    for i, nme in enumerate(names, 1):
        if rr[i] != bb[i]:
            out.append("%s ref=%x bbn=%x" % (nme, rr[i], bb[i]))
    for i in range(31):
        if rr[4][i] != bb[4][i]:
            out.append("x%d ref=%x bbn=%x" % (i, rr[4][i], bb[4][i]))
    if rr[5] != bb[5]:
        out.append("memory")
    return "; ".join(out[:4])


if __name__ == "__main__":
    sys.exit(main())
