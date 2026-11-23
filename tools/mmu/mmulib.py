"""Page-table builder and bare-metal MMU probe-program generator.

Used by tests/gen_vectors.py (expected results written by hand from the ARM ARM) and by
tools/mmu/mmu_diff.py (the same programs run on QEMU and on bareboxn and compared).
"""
import struct
import keystone

KS = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
M64 = (1 << 64) - 1

# Descriptor attribute bits
AF, SH_IS, NG = 1 << 10, 3 << 8, 1 << 11
AP_EL1_RW, AP_ALL_RW, AP_EL1_RO, AP_ALL_RO = 0, 1 << 6, 2 << 6, 3 << 6
UXN, PXN = 1 << 54, 1 << 53
def ATTR(i): return i << 2
# Table-descriptor hierarchical attributes
APT_NO_EL0, APT_RO = 1 << 61, 1 << 62
UXNT, PXNT = 1 << 60, 1 << 59

# Physical layout of the probe image (flat binary loaded at RAM_BASE)
RAM_BASE = 0x40100000  # above the 1 MiB QEMU reserves for its device tree
CODE_BASE = RAM_BASE              # code + vectors + scratch (identity mapped, EL1 RWX)
HARNESS_END = RAM_BASE + 0x40000
VBAR = RAM_BASE + 0x10000
TABLE_BASE = RAM_BASE + 0x100000  # page tables (identity mapped, EL1 RW XN)
TABLE_END = RAM_BASE + 0x200000
DATA_BASE = RAM_BASE + 0x200000   # backing store for test pages (not identity mapped)
DATA_END = RAM_BASE + 0x600000
IMAGE_SIZE = DATA_END - RAM_BASE
UART = 0x09000000
MAIR_VALUE = 0x00FF  # attr0 = Normal WB, attr1 = Device-nGnRnE


class PT:
    """One translation table tree (TTBR0 or TTBR1 region) for a granule and T*SZ."""

    def __init__(self, g, txsz, root_pa, alloc_pa, mem, limit=None):
        self.limit = limit
        self.g, self.txsz = g, txsz
        self.ia = 64 - txsz
        self.stride = g - 3
        self.nlev = -(-(self.ia - g) // self.stride)
        self.start = 4 - self.nlev
        self.topbits = self.ia - g - (self.nlev - 1) * self.stride
        self.root = root_pa
        self.alloc = alloc_pa
        self.mem = mem  # shared dict: pa -> u64
        assert root_pa % (8 << self.topbits) == 0 and root_pa % 64 == 0
        assert alloc_pa % (1 << g) == 0

    def shift(self, level): return self.g + (3 - level) * self.stride
    def index(self, va, level):
        bits = self.topbits if level == self.start else self.stride
        return (va >> self.shift(level)) & ((1 << bits) - 1)

    def _table(self, va, level, table_attrs=0):
        """Return the PA of the table at `level` that holds the entry for va, creating tables."""
        table = self.root
        for lv in range(self.start, level):
            ea = table + 8 * self.index(va, lv)
            d = self.mem.get(ea, 0)
            if d & 1 and d & 2:
                table = d & ((1 << 48) - 1) & ~((1 << self.g) - 1)
            else:
                assert not (d & 1), "block already present on the way down"
                table = self.alloc
                self.alloc += 1 << self.g
                assert self.limit is None or self.alloc <= self.limit, "table region exhausted"
                self.mem[ea] = table | 3
        return table

    def set_desc(self, va, level, raw):
        self.mem[self._table(va, level) + 8 * self.index(va, level)] = raw

    def map(self, va, pa, level=3, attrs=AF | SH_IS):
        sh = self.shift(level)
        assert pa % (1 << sh) == 0, "output address not aligned to the block size"
        typ = 3 if level == 3 else 1
        self.set_desc(va, level, pa | attrs | typ)

    def entry_pa(self, va, level):
        return self._table(va, level) + 8 * self.index(va, level)

    def table_attrs(self, va, level, bits):
        """OR hierarchical attribute bits into the table descriptor at `level` (points to level+1)."""
        ea = self._table(va, level) + 8 * self.index(va, level)
        assert self.mem.get(ea, 0) & 3 == 3
        self.mem[ea] |= bits

    def identity(self, base, end, attrs):
        step = 1 << self.g
        for a in range(base, end, step):
            self.map(a, a, 3, attrs)


def tcr_value(g, txsz0, txsz1=None, tbi0=False, tbi1=False, as16=False, a1=False):
    tg0 = {12: 0, 14: 2, 16: 1}[g]
    tg1 = {12: 2, 14: 1, 16: 3}[g]
    v = txsz0 | (tg0 << 14) | (2 << 32)  # IPS = 40 bits
    v |= (3 << 12) | (1 << 8) | (1 << 10)  # SH0/IRGN0/ORGN0: inner shareable WB
    if txsz1 is None:
        v |= (1 << 23)  # EPD1: TTBR1 walks disabled
    else:
        v |= (txsz1 << 16) | (tg1 << 30) | (3 << 28) | (1 << 24) | (1 << 26)
    if tbi0: v |= 1 << 37
    if tbi1: v |= 1 << 38
    if as16: v |= 1 << 36
    if a1: v |= 1 << 22
    return v


def mov64(reg, val):
    val &= M64
    parts = [(val >> s) & 0xFFFF for s in (0, 16, 32, 48)]
    out = ["movz %s, #0x%x" % (reg, parts[0])]
    for i in (1, 2, 3):
        if parts[i]:
            out.append("movk %s, #0x%x, lsl #%d" % (reg, parts[i], 16 * i))
    return "\n".join(out)


class Program:
    """Straight-line probe program. Each probe prints one transcript line."""

    def __init__(self, sctlr_extra=0):
        self.body = []
        self.sctlr = 0x30D00800 | 1 | sctlr_extra
        self.n = 0
        self.exec_targets = []  # (va, pa) pairs that need an `svc #0` planted at pa
        self.notes = []         # one human-readable note per transcript line (diagnostics only)
        self.ctx = ""

    def _label(self):
        self.n += 1
        return "L%d" % self.n

    # ---- data probes (print "V <x0>" or "E <esr> <far>") ----
    def load(self, va, mnem="ldr x0, [x1]"):
        self.notes.append("%s va=%#x %s" % (mnem, va, self.ctx))
        self.body.append(mov64("x1", va) + "\nmov w13, #86\nmov x0, #0\n%s\nbl put_val" % mnem)

    def store(self, va, value=0x1122334455667788, mnem="str x2, [x1]"):
        self.notes.append("%s va=%#x %s" % (mnem, va, self.ctx))
        self.body.append(mov64("x1", va) + "\n" + mov64("x2", value) + "\nmov w13, #75\nmov x0, #0\n%s\nbl put_val" % mnem)

    def at(self, va, op="s1e1r"):
        self.notes.append("at %s va=%#x %s" % (op, va, self.ctx))
        self.body.append(mov64("x1", va) + "\nat %s, x1\nmrs x0, par_el1\nmov w13, #80\nbl put_val" % op)

    def exec(self, va, el, pa):
        """Jump to va at EL0/EL1; the page holds `svc #0` at pa, so success shows as an SVC."""
        self.exec_targets.append(pa)
        self.notes.append("exec EL%d va=%#x %s" % (el, va, self.ctx))
        lab = self._label()
        spsr = 0x3C5 if el == 1 else 0
        self.body.append(mov64("x1", va) + "\nadr x28, %s\nmsr elr_el1, x1\n" % lab + mov64("x2", spsr) +
                         "\nmsr spsr_el1, x2\neret\n%s:" % lab)

    def pte_write(self, pte_pa, value):
        self.body.append(mov64("x1", pte_pa) + "\n" + mov64("x2", value) + "\nstr x2, [x1]\ndsb ishst")

    def tlbi_all(self):
        self.body.append("dsb ishst\ntlbi vmalle1\ndsb ish\nisb")

    def set_ttbr0(self, value):
        self.body.append(mov64("x1", value) + "\nmsr ttbr0_el1, x1\nisb")

    def raw(self, text):
        self.body.append(text)

    def sources(self, mair, tcr, ttbr0, ttbr1, exit_mode):
        pro = "\n".join([
            mov64("x0", mair), "msr mair_el1, x0",
            mov64("x0", tcr), "msr tcr_el1, x0",
            mov64("x0", ttbr0), "msr ttbr0_el1, x0",
            mov64("x0", ttbr1), "msr ttbr1_el1, x0",
            mov64("x0", VBAR), "msr vbar_el1, x0",
            "isb",
            mov64("x0", self.sctlr), "msr sctlr_el1, x0",
            "isb",
            mov64("x24", UART), "mov x28, #0",
        ])
        if exit_mode == "psci":
            end = mov64("x0", 0x84000008) + "\nhvc #0\nb ."
        else:
            end = "hlt #0"
        main = pro + "\n" + "\n".join(self.body) + "\n" + end + "\n" + RUNTIME
        vec = {}
        vec[VBAR + 0x200] = "b handler"
        vec[VBAR + 0x400] = "b handler"
        return main, vec


# Shared runtime: printing helpers and the exception handler (all live in the identity-mapped
# harness region, executed at EL1). Output format, one line each:
#   V/K/P <x0 hex16>        probe result        E <esr hex16> <far hex16>   exception
RUNTIME = """
putc:
strb w0, [x24]
ret
puthex:
mov x9, #60
puthex_loop:
lsr x10, x0, x9
and x10, x10, #15
cmp x10, #10
add x11, x10, #48
add x12, x10, #87
csel x11, x12, x11, hs
strb w11, [x24]
subs x9, x9, #4
b.ge puthex_loop
ret
put_val:
mov x16, x30
mov x15, x0
mov w0, w13
bl putc
mov w0, #32
bl putc
mov x0, x15
bl puthex
mov w0, #10
bl putc
ret x16
"""

HANDLER = """
handler:
mrs x14, esr_el1
mrs x15, far_el1
mov w0, #69
bl putc
mov w0, #32
bl putc
mov x0, x14
bl puthex
mov w0, #32
bl putc
mov x0, x15
bl puthex
mov w0, #10
bl putc
cbnz x28, handler_resume
mrs x9, elr_el1
add x9, x9, #8
msr elr_el1, x9
eret
handler_resume:
msr elr_el1, x28
mov x28, #0
mov x9, #0x3c5
msr spsr_el1, x9
eret
"""


def assemble(src, addr):
    enc, _ = KS.asm(src, addr)
    return bytes(enc)


def finalize(prog, mair, tcr, ttbr0, ttbr1, mem, pattern, exit_mode="psci"):
    """Assemble everything into a flat image; returns bytes."""
    img = bytearray(IMAGE_SIZE)
    img[DATA_BASE - RAM_BASE:DATA_END - RAM_BASE] = pattern[:DATA_END - DATA_BASE]
    main, vec = prog.sources(mair, tcr, ttbr0, ttbr1, exit_mode)
    full = main + "\n" + HANDLER
    code = assemble(full, CODE_BASE)
    assert len(code) < (VBAR - CODE_BASE), "program too large: %d" % len(code)
    img[0:len(code)] = code
    handler_addr = CODE_BASE + _find_label(full, "handler")
    for addr in vec:
        stub = assemble("b 0x%x" % handler_addr, addr)
        img[addr - RAM_BASE:addr - RAM_BASE + 4] = stub
    for pa, d in mem.items():
        img[pa - RAM_BASE:pa - RAM_BASE + 8] = struct.pack("<Q", d)
    for pa in prog.exec_targets:
        img[pa - RAM_BASE:pa - RAM_BASE + 4] = struct.pack("<I", 0xD4000001)  # svc #0
    return bytes(img)


def _find_label(src, label):
    """Byte offset of `label` in `src`, found by bisecting on assembled prefix length."""
    lines = src.split("\n")
    idx = next(i for i, l in enumerate(lines) if l.strip() == label + ":")
    prefix = "\n".join(lines[:idx])
    return len(assemble(prefix, CODE_BASE)) if prefix.strip() else 0
