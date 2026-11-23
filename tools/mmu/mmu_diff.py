#!/usr/bin/env python3
"""Differential MMU fuzzer: runs random bare-metal translation scenarios on QEMU
(qemu-system-aarch64, -M virt -cpu max) and on bareboxn (bbn-run) and compares transcripts.

    python3 tools/mmu/mmu_diff.py --build-dir build --seeds 1-40

Each scenario randomises the granule (4K/16K/64K), VA width, TTBR0/TTBR1 regions, leaf level
(page/block), descriptor attributes, hierarchical table attributes, malformed descriptors,
TBI, SCTLR.A/WXN, and then probes loads/stores (EL1 and EL0-permission via LDTR/STTR),
page-straddling accesses, AT instructions, instruction fetch at EL0/EL1, and descriptor
rewrite + TLBI. Syndrome registers are compared after masking bits QEMU and the architecture
leave implementation-defined (ISV/SAS/SRT/CM, PAR padding).
"""
import argparse, hashlib, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mmulib import *

class Rng:
    """Self-contained deterministic PRNG (splitmix64): golden seeds must mean the same scenario on
    every Python version, which the standard `random` module does not guarantee."""

    def __init__(self, seed):
        self.s = (seed * 0x9E3779B97F4A7C15 + 0x1234567) & M64
        self.seed = seed

    def _next(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & M64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        return z ^ (z >> 31)

    def random(self):
        return (self._next() >> 11) / float(1 << 53)

    def randrange(self, a, b=None):
        if b is None: a, b = 0, a
        return a + self._next() % (b - a)

    def choice(self, seq):
        return seq[self._next() % len(seq)]

    def randbytes(self, n):
        out = bytearray()
        i = 0
        while len(out) < n:
            out += hashlib.blake2b(b"%d:%d" % (self.seed, i), digest_size=64).digest()
            i += 1
        return bytes(out[:n])


QEMU = ["qemu-system-aarch64", "-M", "virt", "-cpu", "max", "-m", "128M", "-display", "none",
        "-nic", "none", "-monitor", "none", "-no-reboot"]


PROTECTED = [(UART & ~0xFFFFF, (UART & ~0xFFFFF) + 0x100000), (CODE_BASE, HARNESS_END), (TABLE_BASE, TABLE_END)]


def rnd_attrs(r, allow_bad=True):
    a = AF if r.random() < 0.88 else 0
    a |= r.choice([AP_EL1_RW, AP_ALL_RW, AP_EL1_RO, AP_ALL_RO])
    a |= r.choice([0, SH_IS, 2 << 8])
    a |= ATTR(0 if r.random() < 0.75 else 1)
    if r.random() < 0.3: a |= UXN
    if r.random() < 0.3: a |= PXN
    if r.random() < 0.4: a |= NG
    return a


def make_scenario(seed):
    r = Rng(seed)
    g = r.choice([12, 14, 16])
    ia0 = r.randrange(31, 49)
    use1 = r.random() < 0.5
    ia1 = r.randrange(31, 49)
    tbi0, tbi1 = r.random() < 0.4, r.random() < 0.4
    wxn, align = r.random() < 0.25, r.random() < 0.2
    mem = {}
    pt0 = PT(g, 64 - ia0, TABLE_BASE, TABLE_BASE + 0x20000, mem, TABLE_BASE + 0x80000)
    pt1 = PT(g, 64 - ia1, TABLE_BASE + 0x10000, TABLE_BASE + 0x80000, mem, TABLE_END) if use1 else None
    # harness identity mappings (code is read-only+executable so WXN cannot break the runtime)
    code = AF | SH_IS | ATTR(0) | AP_EL1_RO
    pt0.identity(CODE_BASE, HARNESS_END, code)
    pt0.identity(TABLE_BASE, TABLE_END, AF | SH_IS | ATTR(0) | AP_EL1_RW | UXN | PXN)
    pt0.map(UART & ~((1 << g) - 1), UART & ~((1 << g) - 1), 3, AF | SH_IS | ATTR(1) | AP_EL1_RW | UXN | PXN)

    pattern = r.randbytes(DATA_END - DATA_BASE)
    prog = Program(sctlr_extra=(wxn << 19) | (align << 1))
    leaves = []  # (pt, upper, va_base, pa_base, level, size)
    pagesz = 1 << g
    for pt, upper in [(pt0, False)] + ([(pt1, True)] if pt1 else []):
        for i in range(r.randrange(5, 10)):
            level = 3 if r.random() < 0.6 else r.choice([l for l in (1, 2) if l >= pt.start and (g == 12 or l == 2)] or [3])
            size = 1 << pt.shift(level)
            span = 1 << pt.ia
            vb = (r.randrange(0, span // size) * size) % span
            if pt is pt0 and any(vb < hi and lo < vb + size for lo, hi in PROTECTED):
                continue  # never overwrite the identity mappings the harness itself runs from
            if upper:
                vb |= (~((1 << pt.ia) - 1)) & M64
            pa_base = DATA_BASE & ~(size - 1)
            if level == 3:
                pa_base = DATA_BASE + r.randrange(0, (DATA_END - DATA_BASE) // size) * size if size <= (DATA_END - DATA_BASE) else DATA_BASE & ~(size - 1)
            try:
                attrs = rnd_attrs(r)
                roll = r.random()
                if roll < 0.06:
                    pt.set_desc(vb, level, 0)                                 # invalid
                elif roll < 0.09:
                    pt.set_desc(vb, level, (pa_base | attrs) | (2 if level == 3 else 0))  # 0b10: invalid
                elif roll < 0.12:
                    pt.set_desc(vb, level, (pa_base | (1 << 44) | attrs) | (3 if level == 3 else 1))  # address size
                else:
                    pt.map(vb, pa_base, level, attrs)
                    if r.random() < 0.15 and level > pt.start:
                        lv = r.randrange(pt.start, level)
                        span = 1 << pt.shift(lv)       # VA range governed by that table descriptor
                        lo = vb & ~(span - 1)
                        if upper or not any(lo < hi and a < lo + span for a, hi in PROTECTED):
                            pt.table_attrs(vb, lv, r.choice([APT_NO_EL0, APT_RO, UXNT, PXNT, APT_RO | UXNT]))
                leaves.append((pt, upper, vb, pa_base, level, size))
            except AssertionError:
                continue
    # one deliberately broken walk: table pointer into the void
    if r.random() < 0.3 and pt0.nlev > 1:
        va = r.randrange(0, 1 << pt0.ia) & ~((1 << pt0.shift(pt0.start + 1)) - 1)
        if not (0x08000000 <= va < 0x80000000):
            try:
                ea = pt0.entry_pa(va, pt0.start)
                if mem.get(ea, 0) == 0:
                    mem[ea] = 0x0000_0020_0000_0000 | 3 if r.random() < 0.5 else (1 << 41) | 3  # unassigned PA / beyond 40-bit PA
                    leaves.append((pt0, False, va, 0, pt0.start, 1 << pt0.shift(pt0.start)))
            except AssertionError:
                pass

    def tag(va, upper):
        if (tbi1 if upper else tbi0) and r.random() < 0.7:
            return (va & 0x00FFFFFFFFFFFFFF) | (r.randrange(0, 256) << 56)
        return va

    shadow = dict(mem)
    nprobe = 0
    for (pt, upper, vb, pa_base, level, size) in leaves:
        if nprobe > 220: break
        try:
            prog.ctx = "| leaf L%d desc=%#x" % (level, shadow.get(pt.entry_pa(vb, level), 0))
        except AssertionError:
            prog.ctx = "| leaf L%d (walk broken)" % level
        page = 1 << g
        base_off = DATA_BASE - pa_base if level != 3 else 0
        if level != 3:
            if not (0 <= base_off < size): continue
            base_off += r.randrange(0, 8) * page
            if base_off + 2 * page > size: base_off = max(0, base_off - 8 * page)
        for _ in range(r.randrange(2, 5)):
            # QEMU does not fault on unaligned Device-memory accesses (the architecture does), so
            # such cases are not compared; they are covered by tests/test_mmu.cpp instead.
            try:
                cur = shadow.get(pt.entry_pa(vb, level), 0)
            except AssertionError:
                cur = 0
            dev_leaf = ((cur >> 2) & 7) != 0  # attribute bits matter even if the entry is rewritten valid later
            offs = [0, 8, 16, page - 8] if dev_leaf else [0, 8, 16, page - 8, page - 4, page - 3, page - 1, 1, 3]
            va = vb + base_off + r.randrange(0, 2) * page + r.choice(offs)
            va &= M64
            kind = r.choice(["ld", "ld", "st", "ldtr", "sttr", "at", "exec1", "exec0", "ldh", "pte"])
            tva = tag(va, upper)
            nprobe += 1
            if kind == "ld": prog.load(tva)
            elif kind == "ldh": prog.load(tva, "ldrh w0, [x1]")
            elif kind == "ldtr": prog.load(tva, "ldtr x0, [x1]")
            elif kind == "st":
                prog.store(tva); prog.load(tva)
            elif kind == "sttr":
                prog.store(tva, mnem="sttr x2, [x1]"); prog.load(tva, "ldtr x0, [x1]")
            elif kind == "at":
                prog.at(tva, r.choice(["s1e1r", "s1e1w", "s1e0r", "s1e0w"]))
            elif kind in ("exec1", "exec0"):
                ev = (vb + base_off + 0x40) & ~3  # away from the offsets data probes write
                pa = pa_base + (ev - vb & (size - 1)) if level != 3 else pa_base + (ev & (size - 1))
                if DATA_BASE <= pa < DATA_END - 8 and (ev & 3) == 0:
                    prog.exec(tag(ev, upper), 1 if kind == "exec1" else 0, pa)
            elif kind == "pte":
                # rewrite this leaf's descriptor (toggle valid/AP), invalidate, probe again
                try:
                    ea = pt.entry_pa(vb, level)
                except AssertionError:
                    continue
                d = mem.get(ea, 0)
                nd = d ^ r.choice([1 << 6, 1 << 7, 1 << 54, 1 << 10, 1])
                prog.load(tva)
                prog.pte_write(ea, nd)
                shadow[ea] = nd
                prog.ctx = "| leaf L%d desc=%#x (rewritten)" % (level, nd)
                prog.tlbi_all()
                prog.load(tva)
    tcr = tcr_value(g, 64 - ia0, (64 - ia1) if use1 else None, tbi0, tbi1, as16=r.random() < 0.5, a1=r.random() < 0.3)
    ttbr0 = TABLE_BASE | (r.randrange(0, 256) << 48)
    ttbr1 = (TABLE_BASE + 0x10000) | (r.randrange(0, 256) << 48) if use1 else 0
    img = finalize(prog, MAIR_VALUE, tcr, ttbr0, ttbr1, mem, pattern)
    notes = prog.notes
    desc = "g=%dK ia0=%d%s tbi=%d%d wxn=%d A=%d leaves=%d" % (1 << (g - 10), ia0, (" ia1=%d" % ia1) if use1 else "", tbi0, tbi1, wxn, align, len(leaves))
    return img, desc, notes


def norm(line):
    t = line.split()
    if not t: return line
    if t[0] == "E":
        esr, far = int(t[1], 16), int(t[2], 16)
        ec = esr >> 26
        if ec in (0x24, 0x25):       # data abort: keep DFSC, WnR, EA (drop ISV/SAS/SRT/CM...)
            return "E dabt ec=%x fsc=%02x wnr=%d far=%x" % (ec, esr & 0x3F, (esr >> 6) & 1, far)
        if ec in (0x20, 0x21):
            return "E iabt ec=%x fsc=%02x far=%x" % (ec, esr & 0x3F, far)
        if ec == 0x15:
            return "E svc imm=%x" % (esr & 0xFFFF)   # FAR is UNKNOWN for SVC
        return "E ec=%x esr=%x far=%x" % (ec, esr, far)
    if t[0] == "P":
        par = int(t[1], 16)
        if par & 1:
            return "P fault fst=%02x" % ((par >> 1) & 0x3F)
        return "P ok pa=%x attr=%02x" % (par & 0x0000FFFFFFFFF000, par >> 56)  # SH/NS/RES bits not compared
    return line


def run_qemu(path, timeout=15):
    out = path + ".q.out"
    if os.path.exists(out): os.remove(out)
    try:
        p = subprocess.run(QEMU + ["-serial", "file:" + out, "-device", "loader,file=%s,addr=0x%x,cpu-num=0" % (path, RAM_BASE)],
                           capture_output=True, timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        rc = 124  # guest never powered off (e.g. exception loop)
    return open(out).read() if os.path.exists(out) else "", rc


def run_bbn(exe, path):
    p = subprocess.run([exe, "--ram", "128", "--load-addr", hex(RAM_BASE), "--max-insns", "20000000", path], capture_output=True, timeout=60)
    return p.stdout.decode("latin1"), p.returncode, p.stderr.decode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default="build")
    ap.add_argument("--seeds", default="1-20")
    ap.add_argument("--record", metavar="DIR", help="after a QEMU/bareboxn match, store the transcript as a golden file")
    ap.add_argument("--check", metavar="DIR", help="compare bareboxn against golden files only (QEMU not needed)")
    a = ap.parse_args()
    lo, hi = (int(x) for x in a.seeds.split("-")) if "-" in a.seeds else (int(a.seeds), int(a.seeds))
    exe = os.path.join(a.build_dir, "bbn-run")
    bad = 0
    lines_total = 0
    for seed in range(lo, hi + 1):
        img, desc, notes = make_scenario(seed)
        path = "/tmp/mmu_%d.bin" % seed
        open(path, "wb").write(img)
        b, brc, berr = run_bbn(exe, path)
        bn = [norm(l) for l in b.splitlines()]
        if a.check:
            golden = os.path.join(a.check, "seed_%d.txt" % seed)
            qn = open(golden).read().splitlines()
            qrc = 0
        else:
            q, qrc = run_qemu(path)
            qn = [norm(l) for l in q.splitlines()]
        lines_total += len(qn)
        if qn != bn or qrc != 0 or brc != 0 or not qn:
            bad += 1
            print("MISMATCH seed=%d (%s) qemu_rc=%d bbn_rc=%d %s" % (seed, desc, qrc, brc, berr.strip()[:100]))
            shown = 0
            for i in range(max(len(qn), len(bn))):
                x = qn[i] if i < len(qn) else "<missing>"; y = bn[i] if i < len(bn) else "<missing>"
                if x != y and shown < 4:
                    print("   line %d  [%s]\n     qemu: %s\n     bbn : %s" % (i, notes[i] if i < len(notes) else "?", x, y)); shown += 1
        else:
            if a.record:
                os.makedirs(a.record, exist_ok=True)
                open(os.path.join(a.record, "seed_%d.txt" % seed), "w").write("\n".join(qn) + "\n")
            os.remove(path)
        for ext in (".q.out",):
            if os.path.exists(path + ext): os.remove(path + ext)
    print("seeds %d-%d: %d scenarios, %d transcript lines compared, %d mismatching" % (lo, hi, hi - lo + 1, lines_total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
