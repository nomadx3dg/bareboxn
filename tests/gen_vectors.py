#!/usr/bin/env python3
"""Generates tests/vectors_basic.inc and tests/vectors_system.inc.

Programs are written as assembly and encoded with Keystone, so no opcode is hand-encoded.
Expected results are written by hand from the ARM Architecture Reference Manual; with
--verify-unicorn every straight-line "basic" vector is additionally executed on Unicorn
(QEMU TCG) and its expectations are checked against that independent implementation.

    pip install keystone-engine unicorn
    python3 tests/gen_vectors.py [--verify-unicorn]
"""
import argparse, os, struct, sys
import keystone

KS = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
RAM = 0x40000000
CODE = RAM
DATA = RAM + 0x10000
VBAR = RAM + 0x1000
M64 = (1 << 64) - 1
PAT = bytes(range(1, 17)) + bytes(range(17, 33))      # 01 02 03 ... at DATA
SIGN = bytes([0x80, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x80]) + bytes(8)


def asm(src, addr):
    enc, _ = KS.asm(src, addr)
    assert enc, src
    return list(struct.unpack("<%dI" % (len(enc) // 4), bytes(enc)))


class Vec:
    def __init__(self, name, segs, init, expect, mem_init=None, mem_expect=None,
                 max_insns=2000, stop="Halt", entry=CODE, ref=False):
        self.name, self.init, self.expect = name, init, expect
        self.mem_init, self.mem_expect = mem_init or {}, mem_expect or {}
        self.max_insns, self.stop, self.entry, self.ref = max_insns, stop, entry, ref
        if isinstance(segs, str):
            segs = {CODE: segs}
        if CODE in segs and "hlt" not in segs[CODE]:
            segs = dict(segs)
            segs[CODE] += "\nhlt #0"
        self.segs = {a: asm(s, a) for a, s in segs.items()}
        self.src = segs


def basic(name, src, init=None, expect=None, **kw):
    return Vec(name, src + "\nhlt #0", init or {}, expect or {}, ref=kw.pop("ref", True), **kw)


def f(n):  # NZCV nibble helper: "NZ" -> bits
    return (8 if "N" in n else 0) | (4 if "Z" in n else 0) | (2 if "C" in n else 0) | (1 if "V" in n else 0)


def le(v, n):
    return int(v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")


B = []  # basic vectors
# ---- add/sub immediate and flags
B += [
    basic("add_imm", "add x0, x1, #5", {"x1": 10}, {"x0": 15}),
    basic("add_imm_lsl12", "add x0, x1, #1, lsl #12", {"x1": 1}, {"x0": 0x1001}),
    basic("subs_zero", "subs x0, x1, #1", {"x1": 1}, {"x0": 0, "nzcv": f("ZC")}),
    basic("subs_borrow", "subs x0, x1, #1", {"x1": 0}, {"x0": M64, "nzcv": f("N")}),
    basic("adds_signed_overflow64", "adds x0, x1, x2", {"x1": 0x7FFFFFFFFFFFFFFF, "x2": 1},
          {"x0": 1 << 63, "nzcv": f("NV")}),
    basic("adds_carry64", "adds x0, x1, x2", {"x1": M64, "x2": 1}, {"x0": 0, "nzcv": f("ZC")}),
    basic("adds_overflow32_clears_upper", "adds w0, w1, w2",
          {"x0": M64, "x1": 0x7FFFFFFF, "x2": 1}, {"x0": 0x80000000, "nzcv": f("NV")}),
    basic("add_sp_imm", "add sp, sp, #16", {"sp": 0x1000}, {"sp": 0x1010}),
    basic("sub_from_sp", "sub x0, sp, #8", {"sp": 0x1000}, {"x0": 0xFF8}),
    basic("cmp_uses_xzr_dest", "cmp x1, x2", {"x1": 5, "x2": 5}, {"nzcv": f("ZC")}),
    basic("add_shifted_reg", "add x0, x1, x2, lsl #3", {"x1": 5, "x2": 3}, {"x0": 29}),
    basic("sub_shifted_asr", "sub x0, x1, x2, asr #1", {"x1": 10, "x2": 8}, {"x0": 6}),
    basic("add_ext_uxtw_shift", "add x0, x1, w2, uxtw #2", {"x1": 0x100, "x2": 0xFFFFFFFF00000003}, {"x0": 0x10C}),
    basic("add_ext_sxtb", "add x0, x1, w2, sxtb", {"x1": 0x100, "x2": 0x80}, {"x0": 0x80}),
    basic("subs_ext_sxtw", "subs x0, x1, w2, sxtw", {"x1": 0, "x2": 0x80000000}, {"x0": 0x80000000, "nzcv": 0}),
    basic("adc_carry_set", "subs xzr, x3, #0\nadc x0, x1, x2", {"x1": 1, "x2": 2}, {"x0": 4}),
    basic("sbc_carry_set", "subs xzr, x3, #0\nsbc x0, x1, x2", {"x1": 5, "x2": 3}, {"x0": 2}),
    basic("sbc_carry_clear", "cmp x3, #1\nsbc x0, x1, x2", {"x1": 5, "x2": 3}, {"x0": 1}),
]
# ---- logical
B += [
    basic("and_imm", "and x0, x1, #0xff00", {"x1": 0x12345678}, {"x0": 0x5600}),
    basic("orr_imm_pattern", "orr x0, xzr, #0x5555555555555555", {}, {"x0": 0x5555555555555555}),
    basic("eor_imm32", "eor w0, w1, #0xf0f0f0f0", {"x1": M64}, {"x0": 0x0F0F0F0F}),
    basic("ands_imm_zero", "ands x0, x1, #1", {"x1": 2}, {"x0": 0, "nzcv": f("Z")}),
    basic("orr_shifted", "orr x0, x1, x2, lsl #4", {"x1": 1, "x2": 1}, {"x0": 0x11}),
    basic("bic", "bic x0, x1, x2", {"x1": 0xFF, "x2": 0x0F}, {"x0": 0xF0}),
    basic("orn", "orn x0, x1, x2", {"x1": 0, "x2": M64 ^ 0xF}, {"x0": 0xF}),
    basic("eon", "eon x0, x1, x2", {"x1": 0xFF, "x2": 0x0F}, {"x0": M64 ^ 0xF0}),
    basic("tst_sets_n", "tst x1, x2", {"x1": 1 << 63, "x2": 1 << 63}, {"nzcv": f("N")}),
    basic("bics_clears_cv", "adds xzr, x5, x6\nbics x0, x1, x2",
          {"x5": M64, "x6": 1, "x1": 0xF0, "x2": 0x0F}, {"x0": 0xF0, "nzcv": 0}),
]
# ---- moves / bitfields / extract / pc-relative
B += [
    basic("movz_lsl16", "movz x0, #0x1234, lsl #16", {}, {"x0": 0x12340000}),
    basic("movk_sequence", "movz x0, #0x1111\nmovk x0, #0x2222, lsl #16\nmovk x0, #0x3333, lsl #32\nmovk x0, #0x4444, lsl #48",
          {}, {"x0": 0x4444333322221111}),
    basic("movn32", "movn w0, #1", {"x0": M64}, {"x0": 0xFFFFFFFE}),
    basic("movn64", "movn x0, #0", {}, {"x0": M64}),
    basic("ubfx", "ubfx x0, x1, #8, #8", {"x1": 0xAABBCCDD}, {"x0": 0xCC}),
    basic("sbfx", "sbfx x0, x1, #8, #8", {"x1": 0x8000}, {"x0": M64 ^ 0x7F}),
    basic("bfi_clear", "bfi x0, x1, #4, #8", {"x0": M64, "x1": 0}, {"x0": M64 ^ 0xFF0}),
    basic("lsl_imm", "lsl x0, x1, #4", {"x1": 1}, {"x0": 0x10}),
    basic("lsr_imm", "lsr x0, x1, #4", {"x1": 0xF0}, {"x0": 0xF}),
    basic("asr_imm", "asr x0, x1, #4", {"x1": 1 << 63}, {"x0": 0xF800000000000000}),
    basic("sxtb", "sxtb x0, w1", {"x1": 0x80}, {"x0": M64 ^ 0x7F}),
    basic("uxth", "uxth w0, w1", {"x1": 0x12345678}, {"x0": 0x5678}),
    basic("sxtw", "sxtw x0, w1", {"x1": 0x80000000}, {"x0": 0xFFFFFFFF80000000}),
    basic("ubfx32", "ubfx w0, w1, #28, #4", {"x1": 0xF0000000}, {"x0": 0xF}),
    basic("extr", "extr x0, x1, x2, #8", {"x1": 0x1122334455667788, "x2": 0x99AABBCCDDEEFF00}, {"x0": 0x8899AABBCCDDEEFF}),
    basic("ror_imm", "ror x0, x1, #4", {"x1": 1}, {"x0": 0x1000000000000000}),
    basic("adr", "adr x0, lbl\nnop\nlbl:\nnop", {}, {"x0": CODE + 8}),
    basic("adrp", "nop\nadrp x0, 0x40005000", {}, {"x0": 0x40005000}),
]
# ---- conditional ops
B += [
    basic("ccmp_taken", "cmp x1, #5\nccmp x2, #3, #0, eq", {"x1": 5, "x2": 3}, {"nzcv": f("ZC")}),
    basic("ccmp_not_taken_uses_imm", "cmp x1, #5\nccmp x2, #3, #4, eq", {"x1": 4, "x2": 3}, {"nzcv": f("Z")}),
    basic("ccmn_reg", "cmp x1, #5\nccmn x2, x3, #0, eq", {"x1": 5, "x2": M64, "x3": 1}, {"nzcv": f("ZC")}),
    basic("csel_true", "cmp x1, x2\ncsel x0, x3, x4, lt", {"x1": 1, "x2": 2, "x3": 7, "x4": 9}, {"x0": 7}),
    basic("csinc_false", "cmp x1, x2\ncsinc x0, x3, x4, ge", {"x1": 1, "x2": 2, "x3": 7, "x4": 9}, {"x0": 10}),
    basic("csinv_false", "cmp x1, x2\ncsinv x0, x3, x4, ge", {"x1": 1, "x2": 2, "x3": 7, "x4": 9}, {"x0": M64 ^ 9}),
    basic("csneg_false", "cmp x1, x2\ncsneg x0, x3, x4, ge", {"x1": 1, "x2": 2, "x3": 7, "x4": 9}, {"x0": (-9) & M64}),
    basic("cset", "cmp x1, x2\ncset x0, eq", {"x1": 3, "x2": 3}, {"x0": 1}),
    basic("csel32_clears_upper", "cmp x1, x2\ncsel w0, w3, w4, eq", {"x1": 3, "x2": 3, "x3": M64, "x4": 0}, {"x0": 0xFFFFFFFF}),
]
# ---- multiply / divide / shifts / bit ops
B += [
    basic("madd", "madd x0, x1, x2, x3", {"x1": 3, "x2": 4, "x3": 5}, {"x0": 17}),
    basic("msub", "msub x0, x1, x2, x3", {"x1": 3, "x2": 4, "x3": 5}, {"x0": (-7) & M64}),
    basic("mul32_wraps", "mul w0, w1, w2", {"x1": 0x10000, "x2": 0x10000, "x0": M64}, {"x0": 0}),
    basic("smull", "smull x0, w1, w2", {"x1": 0xFFFFFFFF, "x2": 2}, {"x0": (-2) & M64}),
    basic("umull", "umull x0, w1, w2", {"x1": 0xFFFFFFFF, "x2": 2}, {"x0": 0x1FFFFFFFE}),
    basic("smaddl", "smaddl x0, w1, w2, x3", {"x1": 0xFFFFFFFF, "x2": 3, "x3": 10}, {"x0": 7}),
    basic("umulh", "umulh x0, x1, x2", {"x1": M64, "x2": M64}, {"x0": M64 - 1}),
    basic("smulh_neg", "smulh x0, x1, x2", {"x1": 1 << 63, "x2": 2}, {"x0": M64}),
    basic("smulh_pos", "smulh x0, x1, x2", {"x1": M64, "x2": M64}, {"x0": 0}),
    basic("udiv", "udiv x0, x1, x2", {"x1": 100, "x2": 7}, {"x0": 14}),
    basic("udiv_by_zero", "udiv x0, x1, x2", {"x1": 100, "x2": 0}, {"x0": 0}),
    basic("sdiv_trunc", "sdiv x0, x1, x2", {"x1": (-100) & M64, "x2": 7}, {"x0": (-14) & M64}),
    basic("sdiv_intmin_neg1", "sdiv x0, x1, x2", {"x1": 1 << 63, "x2": M64}, {"x0": 1 << 63}),
    basic("sdiv32_intmin_neg1", "sdiv w0, w1, w2", {"x1": 0x80000000, "x2": 0xFFFFFFFF}, {"x0": 0x80000000}),
    basic("lslv_mod64", "lsl x0, x1, x2", {"x1": 3, "x2": 65}, {"x0": 6}),
    basic("lsrv_mod32", "lsr w0, w1, w2", {"x1": 4, "x2": 33}, {"x0": 2}),
    basic("asrv", "asr x0, x1, x2", {"x1": 1 << 63, "x2": 63}, {"x0": M64}),
    basic("rorv", "ror x0, x1, x2", {"x1": 1, "x2": 1}, {"x0": 1 << 63}),
    basic("rbit", "rbit x0, x1", {"x1": 1}, {"x0": 1 << 63}),
    basic("rev64", "rev x0, x1", {"x1": 0x0102030405060708}, {"x0": 0x0807060504030201}),
    basic("rev32_w", "rev w0, w1", {"x1": 0x01020304}, {"x0": 0x04030201}),
    basic("rev16", "rev16 x0, x1", {"x1": 0x0102030405060708}, {"x0": 0x0201040306050807}),
    basic("rev32_x", "rev32 x0, x1", {"x1": 0x0102030405060708}, {"x0": 0x0403020108070605}),
    basic("clz64", "clz x0, x1", {"x1": 1}, {"x0": 63}),
    basic("clz64_zero", "clz x0, x1", {"x1": 0}, {"x0": 64}),
    basic("clz32_zero", "clz w0, w1", {"x1": 0}, {"x0": 32}),
    basic("cls64_ones", "cls x0, x1", {"x1": M64}, {"x0": 63}),
    basic("cls64_one", "cls x0, x1", {"x1": 1}, {"x0": 62}),
    basic("cls32", "cls w0, w1", {"x1": 0xFFFF}, {"x0": 15}),
]
# ---- branches (straight-line outcome only; verified against Unicorn too where it makes sense)
B += [
    Vec("b_skips", {CODE: "mov x0, #99\nb skip\nmov x0, #1\nskip:\nmov x1, #2\nhlt #0"}, {}, {"x0": 99, "x1": 2}),
    Vec("bl_ret", {CODE: "mov x0, #0\nbl 0x40000100\nadd x0, x0, #1\nhlt #0",
                   CODE + 0x100: "add x0, x0, #10\nret"}, {}, {"x0": 11, "x30": CODE + 8}),
    Vec("cbz_cbnz", {CODE: "mov x0, #0\ncbz x1, a\nmov x0, #1\na:\ncbnz x2, b\nmov x0, #2\nb:\nhlt #0"},
        {"x1": 0, "x2": 0}, {"x0": 2}),
    Vec("cbz32_ignores_upper", {CODE: "mov x0, #0\ncbz w1, a\nmov x0, #1\na:\nhlt #0"}, {"x1": 1 << 32}, {"x0": 0}),
    Vec("tbz_tbnz", {CODE: "mov x0, #0\ntbnz x1, #63, a\nmov x0, #1\na:\ntbz x1, #0, b\nmov x0, #2\nb:\nhlt #0"},
        {"x1": (1 << 63) | 1}, {"x0": 2}),
    Vec("loop_bne", {CODE: "mov x0, #0\nl:\nadd x0, x0, #1\ncmp x0, #10\nb.ne l\nhlt #0"}, {}, {"x0": 10}),
    Vec("br_blr", {CODE: "blr x1\nhlt #0", CODE + 0x100: "mov x2, #7\nbr x30"}, {"x1": CODE + 0x100}, {"x2": 7}),
]
for v in B:
    if v.name in ("b_skips", "cbz_cbnz", "cbz32_ignores_upper", "tbz_tbnz", "loop_bne"):
        v.ref = True  # single-segment programs: cross-check on Unicorn as well
# ---- loads and stores
LD = lambda n, a, i, e, **k: basic(n, a, i, e, mem_init={DATA: PAT}, **k)
B += [
    LD("ldr64", "ldr x0, [x1]", {"x1": DATA}, {"x0": 0x0807060504030201}),
    LD("ldr32_off", "ldr w0, [x1, #4]", {"x1": DATA}, {"x0": 0x08070605}),
    LD("ldrb", "ldrb w0, [x1, #3]", {"x1": DATA}, {"x0": 4}),
    LD("ldrh", "ldrh w0, [x1, #2]", {"x1": DATA}, {"x0": 0x0403}),
    LD("ldr_unaligned", "ldr x0, [x1, #1]", {"x1": DATA}, {"x0": 0x0908070605040302}),
    LD("ldur_neg", "ldur x0, [x1, #-8]", {"x1": DATA + 8}, {"x0": 0x0807060504030201}),
    LD("ldr_preindex", "ldr x0, [x1, #8]!", {"x1": DATA}, {"x0": 0x100F0E0D0C0B0A09, "x1": DATA + 8}),
    LD("ldr_postindex", "ldr x0, [x1], #8", {"x1": DATA}, {"x0": 0x0807060504030201, "x1": DATA + 8}),
    LD("ldr_reg_lsl3", "ldr x0, [x1, x2, lsl #3]", {"x1": DATA, "x2": 1}, {"x0": 0x100F0E0D0C0B0A09}),
    LD("ldr_reg_uxtw2", "ldr w0, [x1, w2, uxtw #2]", {"x1": DATA, "x2": 0xFFFFFFFF00000001}, {"x0": 0x08070605}),
    LD("ldr_reg_sxtw", "ldr x0, [x1, w2, sxtw]", {"x1": DATA + 16, "x2": 0xFFFFFFF8}, {"x0": 0x100F0E0D0C0B0A09}),
    LD("ldrb_reg", "ldrb w0, [x1, x2]", {"x1": DATA, "x2": 5}, {"x0": 6}),
    LD("ldp64", "ldp x0, x1, [x2]", {"x2": DATA}, {"x0": 0x0807060504030201, "x1": 0x100F0E0D0C0B0A09}),
    LD("ldp32_off", "ldp w0, w1, [x2, #8]", {"x2": DATA}, {"x0": 0x0C0B0A09, "x1": 0x100F0E0D}),
    LD("ldp_postindex", "ldp x0, x1, [x2], #16", {"x2": DATA}, {"x0": 0x0807060504030201, "x2": DATA + 16}),
    LD("ldp_preindex", "ldp x0, x1, [x2, #16]!", {"x2": DATA}, {"x0": 0x1817161514131211, "x2": DATA + 16}),
    LD("ldr_pc_literal", "ldr x0, #0x10000", {}, {"x0": 0x0807060504030201}),
    basic("ldrsb_x", "ldrsb x0, [x1]", {"x1": DATA}, {"x0": M64 ^ 0x7F}, mem_init={DATA: SIGN}),
    basic("ldrsb_w", "ldrsb w0, [x1]", {"x1": DATA, "x0": M64}, {"x0": 0xFFFFFF80}, mem_init={DATA: SIGN}),
    basic("ldrsh_w", "ldrsh w0, [x1]", {"x1": DATA, "x0": M64}, {"x0": 0xFFFFFF80}, mem_init={DATA: SIGN}),
    basic("ldrsh_x", "ldrsh x0, [x1]", {"x1": DATA}, {"x0": M64 ^ 0x7F}, mem_init={DATA: SIGN}),
    basic("ldrsw", "ldrsw x0, [x1, #4]", {"x1": DATA}, {"x0": 0xFFFFFFFF80000000}, mem_init={DATA: SIGN}),
    basic("ldpsw", "ldpsw x0, x1, [x2]", {"x2": DATA}, {"x0": 0xFFFFFFFFFFFF7FFF ^ 0x0000000000007F7F ^ 0x0000000000000000 if False else 0xFFFFFFFF007FFF80, "x1": 0xFFFFFFFF80000000}, mem_init={DATA: SIGN}),
    basic("ldrsw_literal", "ldrsw x0, #0x10004", {}, {"x0": 0xFFFFFFFF80000000}, mem_init={DATA: SIGN}),
    basic("str64", "str x0, [x1, #8]", {"x0": 0x1122334455667788, "x1": DATA}, {},
          mem_init={DATA: bytes(16)}, mem_expect={DATA + 8: le(0x1122334455667788, 8)}),
    basic("strb_strh", "strb w0, [x1]\nstrh w0, [x1, #2]", {"x0": 0xAABBCCDD, "x1": DATA}, {},
          mem_init={DATA: bytes(8)}, mem_expect={DATA: bytes([0xDD, 0, 0xDD, 0xCC, 0, 0, 0, 0])}),
    basic("str32_zr", "str wzr, [x1]", {"x1": DATA}, {}, mem_init={DATA: PAT}, mem_expect={DATA: bytes([0, 0, 0, 0, 5])}),
    basic("str_preindex_neg", "str x0, [x1, #-8]!", {"x0": 0xAB, "x1": DATA + 8}, {"x1": DATA},
          mem_init={DATA: bytes(16)}, mem_expect={DATA: le(0xAB, 8)}),
    basic("stp_preindex_sp", "stp x0, x1, [sp, #-16]!", {"x0": 1, "x1": 2, "sp": DATA + 16}, {"sp": DATA},
          mem_init={DATA: bytes(16)}, mem_expect={DATA: le(1, 8) + le(2, 8)}),
    basic("stp_ldp_roundtrip", "stp x0, x1, [x2]\nldp x3, x4, [x2]", {"x0": 11, "x1": 22, "x2": DATA}, {"x3": 11, "x4": 22},
          mem_init={DATA: bytes(16)}),
    # exclusives / ordered
    LD("ldxr_stxr_ok", "ldxr x0, [x1]\nstxr w2, x3, [x1]", {"x1": DATA, "x3": 0xDEAD},
       {"x0": 0x0807060504030201, "x2": 0}, mem_expect={DATA: le(0xDEAD, 8)}),
    LD("stxr_without_ldxr_fails", "stxr w2, x3, [x1]", {"x1": DATA, "x3": 0xDEAD, "x2": 55}, {"x2": 1},
       mem_expect={DATA: PAT[:8]}),
    LD("clrex_kills_monitor", "ldxr x0, [x1]\nclrex\nstxr w2, x3, [x1]", {"x1": DATA, "x3": 9}, {"x2": 1},
       mem_expect={DATA: PAT[:8]}),
    LD("stxr_wrong_address_fails", "ldxr x0, [x1]\nstxr w2, x3, [x4]", {"x1": DATA, "x4": DATA + 8, "x3": 9}, {"x2": 1}),
    LD("ldaxr_stlxr_byte", "ldaxrb w0, [x1]\nstlxrb w2, w3, [x1]", {"x1": DATA, "x3": 0x77}, {"x0": 1, "x2": 0},
       mem_expect={DATA: bytes([0x77, 2])}),
    LD("ldar_stlr", "ldar x0, [x1]\nstlr x0, [x2]", {"x1": DATA, "x2": DATA + 16}, {"x0": 0x0807060504030201},
       mem_expect={DATA + 16: le(0x0807060504030201, 8)}),
    LD("ldxp_stxp", "ldxp x0, x1, [x2]\nstxp w3, x4, x5, [x2]", {"x2": DATA, "x4": 0xAA, "x5": 0xBB},
       {"x0": 0x0807060504030201, "x1": 0x100F0E0D0C0B0A09, "x3": 0}, mem_expect={DATA: le(0xAA, 8) + le(0xBB, 8)}),
]
# fix the ldpsw expectation (bytes 80 FF 7F 00 | 00 00 00 80): w0=0x007FFF80 (positive), w1=0x80000000 -> sign-extended
for v in B:
    if v.name == "ldpsw":
        v.expect = {"x0": 0x007FFF80, "x1": 0xFFFFFFFF80000000}

# ---------------------------------------------------------------- system vectors
S = []
def prog_vbar(rest):  # install VBAR_EL1 = VBAR then run `rest`
    return "movz x9, #0x1000\nmovk x9, #0x4000, lsl #16\nmsr vbar_el1, x9\n" + rest

ESR = lambda ec, iss=0: (ec << 26) | (1 << 25) | iss
EL1H = 5
DAIF_ALL = 0xF << 6

S += [
    Vec("svc_from_el1", {CODE: prog_vbar("svc #0x42\nhlt #0"),
                         VBAR + 0x200: "mrs x1, esr_el1\nmrs x2, elr_el1\nmrs x3, spsr_el1\nhlt #1"}, {},
        {"x1": ESR(0x15, 0x42), "x2": CODE + 0x10, "x3": DAIF_ALL | EL1H, "el": 1}),
    Vec("svc_eret_roundtrip", {CODE: prog_vbar("svc #1\nmov x6, #77\nhlt #0"),
                               VBAR + 0x200: "add x5, x5, #1\neret"}, {}, {"x5": 1, "x6": 77}),
    Vec("brk", {CODE: prog_vbar("brk #0x123\nhlt #0"),
                VBAR + 0x200: "mrs x1, esr_el1\nmrs x2, elr_el1\nhlt #1"}, {},
        {"x1": ESR(0x3C, 0x123), "x2": CODE + 0x0C}),
    Vec("udf_is_undefined", {CODE: prog_vbar(".word 0\nhlt #0"),
                             VBAR + 0x200: "mrs x1, esr_el1\nmrs x2, elr_el1\nhlt #1"}, {},
        {"x1": ESR(0), "x2": CODE + 0x0C}),
    Vec("fp_is_undefined_not_silent", {CODE: prog_vbar("fmov d0, d1\nhlt #0"),
                                       VBAR + 0x200: "mrs x1, esr_el1\nhlt #1"}, {}, {"x1": ESR(0)}),
    Vec("unmapped_load_data_abort", {CODE: prog_vbar("ldr x0, [x1]\nhlt #0"),
                                     VBAR + 0x200: "mrs x2, esr_el1\nmrs x3, far_el1\nhlt #1"},
        {"x1": 0x1000, "x0": 5}, {"x2": ESR(0x25, 0x210), "x3": 0x1000, "x0": 5}),
    Vec("unmapped_store_data_abort_wnr", {CODE: prog_vbar("str x0, [x1]\nhlt #0"),
                                          VBAR + 0x200: "mrs x2, esr_el1\nmrs x3, far_el1\nhlt #1"},
        {"x1": 0x2000}, {"x2": ESR(0x25, 0x250), "x3": 0x2000}),
    Vec("fault_has_no_writeback", {CODE: prog_vbar("ldr x0, [x1, #8]!\nhlt #0"),
                                   VBAR + 0x200: "hlt #1"}, {"x1": 0x3000, "x0": 5}, {"x1": 0x3000, "x0": 5}),
    Vec("fetch_from_unmapped", {CODE: prog_vbar("br x1"),
                                VBAR + 0x200: "mrs x2, esr_el1\nmrs x3, far_el1\nmrs x4, elr_el1\nhlt #1"},
        {"x1": 0x100000}, {"x2": ESR(0x21, 0x210), "x3": 0x100000, "x4": 0x100000}),
    Vec("pc_alignment_fault", {CODE: prog_vbar("br x1"),
                               VBAR + 0x200: "mrs x2, esr_el1\nmrs x3, far_el1\nhlt #1"},
        {"x1": CODE + 0x102}, {"x2": ESR(0x22), "x3": CODE + 0x102}),
    Vec("ldxr_unaligned_faults", {CODE: prog_vbar("ldxr x0, [x1]\nhlt #0"),
                                  VBAR + 0x200: "mrs x2, esr_el1\nmrs x3, far_el1\nhlt #1"},
        {"x1": DATA + 1}, {"x2": ESR(0x25, 0x21), "x3": DATA + 1}),
    Vec("stxr_unaligned_faults_even_if_monitor_clear", {CODE: prog_vbar("stxr w2, x0, [x1]\nhlt #0"),
                                  VBAR + 0x200: "mrs x3, esr_el1\nhlt #1"},
        {"x1": DATA + 4}, {"x3": ESR(0x25, 0x61)}),
    Vec("mmio_access_to_ram_hole_faults", {CODE: prog_vbar("ldr w0, [x1]\nhlt #0"),
                                           VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"},
        {"x1": 0x0A000000}, {"x2": ESR(0x25, 0x210)}),
    # ---- exception levels and stack pointers
    Vec("drop_to_el0_and_svc", {CODE: prog_vbar("movz x1, #0x100\nmovk x1, #0x4000, lsl #16\nmsr elr_el1, x1\nmsr spsr_el1, xzr\neret"),
                                CODE + 0x100: "svc #7",
                                VBAR + 0x400: "mrs x2, esr_el1\nmrs x3, spsr_el1\nmrs x4, currentel\nmrs x5, elr_el1\nhlt #1"}, {},
        {"x2": ESR(0x15, 7), "x3": 0, "x4": 4, "x5": CODE + 0x104, "el": 1}),
    Vec("el0_privileged_sysreg_is_undefined", {CODE: prog_vbar("movz x1, #0x100\nmovk x1, #0x4000, lsl #16\nmsr elr_el1, x1\nmsr spsr_el1, xzr\neret"),
                                CODE + 0x100: "mrs x0, sctlr_el1",
                                VBAR + 0x400: "mrs x2, esr_el1\nmrs x5, elr_el1\nhlt #1"}, {},
        {"x2": ESR(0), "x5": CODE + 0x100}),
    Vec("el0_eret_is_undefined", {CODE: prog_vbar("movz x1, #0x100\nmovk x1, #0x4000, lsl #16\nmsr elr_el1, x1\nmsr spsr_el1, xzr\neret"),
                                CODE + 0x100: "eret",
                                VBAR + 0x400: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0)}),
    Vec("el0_data_abort_uses_lower_el_ec", {CODE: prog_vbar("movz x1, #0x100\nmovk x1, #0x4000, lsl #16\nmsr elr_el1, x1\nmsr spsr_el1, xzr\neret"),
                                CODE + 0x100: "mov x1, #0x5000\nldr x0, [x1]",
                                VBAR + 0x400: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0x24, 0x210)}),
    Vec("el0_uses_sp_el0_and_exception_uses_sp_el1", {CODE: prog_vbar("movz x1, #0x100\nmovk x1, #0x4000, lsl #16\nmsr elr_el1, x1\nmov x1, #0x7000\nmsr sp_el0, x1\nmov x1, #0x6000\nmov sp, x1\nmsr spsr_el1, xzr\neret"),
                                CODE + 0x100: "mov x1, sp\nsvc #0",
                                VBAR + 0x400: "mov x2, sp\nhlt #1"}, {}, {"x1": 0x7000, "x2": 0x6000}),
    Vec("spsel_banking", {CODE: "mov x1, #0x2000\nmov sp, x1\nmsr spsel, #0\nmov x1, #0x3000\nmov sp, x1\nmrs x2, sp_el0\nmsr spsel, #1\nmov x3, sp\nmrs x4, spsel\nhlt #0"},
        {}, {"x2": 0x3000, "x3": 0x2000, "x4": 1}),
    Vec("exception_from_el1t_uses_offset_0", {CODE: prog_vbar("msr spsel, #0\nsvc #0\nhlt #0"),
                                              VBAR + 0x000: "mrs x1, spsr_el1\nhlt #1"}, {}, {"x1": DAIF_ALL | 4 ^ 0 if False else (0xF << 6) | 0}),
    Vec("daif_set_clear", {CODE: "msr daifclr, #0xf\nmrs x0, daif\nmsr daifset, #2\nmrs x1, daif\nmsr daifset, #0xf\nmrs x2, daif\nmsr daifclr, #4\nmrs x3, daif"},
        {}, {"x0": 0, "x1": 0x80, "x2": 0x3C0, "x3": 0x3C0 & ~(1 << 8)}),
    Vec("eret_illegal_return_el2", {CODE: prog_vbar("mov x1, #9\nmsr spsr_el1, x1\nmsr elr_el1, x1\neret"),
                                    VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0x0E)}),
    # ---- system registers
    Vec("id_registers", {CODE: "mrs x0, midr_el1\nmrs x1, mpidr_el1\nmrs x2, id_aa64pfr0_el1\nmrs x3, id_aa64isar0_el1\nmrs x4, currentel\nmrs x5, ctr_el0\nmrs x6, dczid_el0\nmrs x7, id_aa64mmfr1_el1\nmrs x8, id_aa64dfr0_el1\nmrs x9, cntfrq_el0"},
        {}, {"x0": 0x000FBB00, "x1": 0x80000000, "x2": 0x00FF0011, "x3": 0, "x4": 4, "x5": 0x84448004, "x6": 0x10, "x7": 0, "x8": 0x00101006, "x9": 62500000}),
    Vec("rw_sysregs", {CODE: "mov x1, #0x1234\nmsr tpidr_el0, x1\nmrs x2, tpidr_el0\nmsr tpidr_el1, x1\nmrs x3, tpidr_el1\nmsr vbar_el1, x1\nmrs x4, vbar_el1\nmsr mair_el1, x1\nmrs x5, mair_el1\nmsr tcr_el1, x1\nmrs x6, tcr_el1\nmsr nzcv, x1\nmrs x7, nzcv"},
        {}, {"x2": 0x1234, "x3": 0x1234, "x4": 0x1234, "x5": 0x1234, "x6": 0x1234, "x7": 0}),
    Vec("nzcv_msr", {CODE: "movz x1, #0xA000, lsl #16\nmsr nzcv, x1\nmrs x2, nzcv"}, {}, {"x2": 0xA0000000, "nzcv": f("NC")}),
    Vec("debug_regs_raz_wi", {CODE: "mov x1, #5\nmsr mdscr_el1, x1\nmrs x2, mdscr_el1\nmsr oslar_el1, xzr"}, {}, {"x2": 0}),
    Vec("write_to_readonly_sysreg_undefined", {CODE: prog_vbar("msr s3_0_c0_c0_0, x1\nhlt #0"),
                                               VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0)}),
    Vec("unimplemented_timer_reg_is_undefined", {CODE: prog_vbar("mrs x0, cntv_ctl_el0\nhlt #0"),
                                                  VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0)}),
    Vec("hvc_without_el2_is_undefined", {CODE: prog_vbar("hvc #0\nhlt #0"),
                                         VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0)}),
    Vec("cache_and_tlb_maintenance_are_nops", {CODE: "dc civac, x0\nic iallu\ndsb sy\nisb\ndmb ish\ntlbi vmalle1\nnop\nyield\nsev\nmov x1, #5"}, {}, {"x1": 5}),
    Vec("dc_zva_undefined", {CODE: prog_vbar("dc zva, x0\nhlt #0"), VBAR + 0x200: "mrs x2, esr_el1\nhlt #1"}, {}, {"x2": ESR(0)}),
    Vec("counter_is_monotonic", {CODE: "mrs x0, cntvct_el0\nnop\nnop\nmrs x1, cntvct_el0\nsub x2, x1, x0"}, {}, {"x2": 3}),
    Vec("mmu_enable_is_reported_unsupported", {CODE: "mov x0, #1\nmsr sctlr_el1, x0\nmov x1, #2"}, {}, {"x1": 0}, stop="Unsupported"),
]
# fix one expectation that was written awkwardly above: SPSR from EL1t is EL1t(4)|DAIF all masked
for v in S:
    if v.name == "exception_from_el1t_uses_offset_0":
        v.expect = {"x1": DAIF_ALL | 4}
    if v.name == "mmu_enable_is_reported_unsupported":
        v.expect = {"x1": 0}  # stop is reported after msr retires; the following mov never runs


def cpp_bytes(b):
    return "{" + ",".join("0x%02x" % x for x in b) + "}"


def emit(vecs, path):
    with open(path, "w") as out:
        out.write("// GENERATED by tests/gen_vectors.py -- do not edit by hand.\n")
        out.write("static const std::vector<Vec> kVectors = {\n")
        for v in vecs:
            out.write('  {"%s", /*segs*/{' % v.name)
            out.write(",".join("{0x%xull,{%s}}" % (a, ",".join("0x%08x" % w for w in ws)) for a, ws in v.segs.items()))
            out.write("}, /*init*/{%s}, /*mem_init*/{%s}, /*expect*/{%s}, /*mem_expect*/{%s}, 0x%xull, %d, \"%s\"},\n" % (
                ",".join('{"%s",0x%xull}' % (k, x & M64) for k, x in v.init.items()),
                ",".join("{0x%xull,std::vector<uint8_t>%s}" % (a, cpp_bytes(b)) for a, b in v.mem_init.items()),
                ",".join('{"%s",0x%xull}' % (k, x & M64) for k, x in v.expect.items()),
                ",".join("{0x%xull,std::vector<uint8_t>%s}" % (a, cpp_bytes(b)) for a, b in v.mem_expect.items()),
                v.entry, v.max_insns, v.stop))
        out.write("};\n")


def verify_unicorn(vecs):
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as C
    bad = 0
    n = 0
    for v in vecs:
        if not v.ref or len(v.segs) != 1:
            continue
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(RAM, 0x100000)
        words = v.segs[CODE]
        mu.mem_write(CODE, struct.pack("<%dI" % len(words), *words))
        for a, b in v.mem_init.items():
            mu.mem_write(a, b)
        for k, x in v.init.items():
            reg = C.UC_ARM64_REG_SP if k == "sp" else C.UC_ARM64_REG_NZCV if k == "nzcv" else getattr(C, "UC_ARM64_REG_" + k.upper())
            mu.reg_write(reg, x << 28 if k == "nzcv" else x)
        mu.emu_start(CODE, CODE + 4 * (len(words) - 1))  # stop before the final HLT
        n += 1
        for k, x in v.expect.items():
            reg = C.UC_ARM64_REG_SP if k == "sp" else C.UC_ARM64_REG_NZCV if k == "nzcv" else getattr(C, "UC_ARM64_REG_" + k.upper())
            got = mu.reg_read(reg)
            if k == "nzcv":
                got >>= 28
            if got != x:
                print("UNICORN DISAGREES %s %s: expected %#x, unicorn %#x" % (v.name, k, x, got)); bad += 1
        for a, b in v.mem_expect.items():
            got = bytes(mu.mem_read(a, len(b)))
            if got != b:
                print("UNICORN DISAGREES %s mem %#x: expected %s, unicorn %s" % (v.name, a, b.hex(), got.hex())); bad += 1
    print("unicorn cross-check: %d vectors, %d disagreements" % (n, bad))
    return bad


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify-unicorn", action="store_true")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    emit(B, os.path.join(here, "vectors_basic.inc"))
    emit(S, os.path.join(here, "vectors_system.inc"))
    print("wrote %d basic and %d system vectors" % (len(B), len(S)))
    if a.verify_unicorn:
        sys.exit(1 if verify_unicorn(B) else 0)
