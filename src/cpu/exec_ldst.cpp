// Load/store instructions (general-purpose registers). SIMD&FP forms (V=1) are UNDEFINED.
#include "core/bits.h"
#include "cpu/cpu.h"

namespace bbn {

void Cpu::exec_ldst(uint32_t i) {
  if (bit(i, 26)) return undef();  // SIMD&FP load/store: not implemented
  switch (bits(i, 29, 27)) {
    case 7: return exec_ldst_reg(i);
    case 5: return exec_ldst_pair(i);
    case 3: if (bits(i, 25, 24) == 0) return exec_ldst_literal(i); break;
    case 1: if (bits(i, 25, 24) == 0) return exec_ldst_exclusive(i); break;
    default: break;
  }
  undef();
}

void Cpu::exec_ldst_reg(uint32_t i) {
  const unsigned size = bits(i, 31, 30), opc = bits(i, 23, 22);
  const unsigned rn = bits(i, 9, 5), rt = bits(i, 4, 0);
  const uint64_t base = rd_sp(rn);
  uint64_t addr;
  bool writeback = false;
  uint64_t wb_val = 0;
  bool is_register_offset = false, is_imm_scaled = false, is_unscaled = false;

  if (bit(i, 24)) {  // unsigned scaled 12-bit offset
    addr = base + (uint64_t{bits(i, 21, 10)} << size);
    is_imm_scaled = true;
  } else if (!bit(i, 21)) {
    const int64_t imm9 = sext(bits(i, 20, 12), 9);
    switch (bits(i, 11, 10)) {
      case 0: addr = base + static_cast<uint64_t>(imm9); is_unscaled = true; break;  // LDUR/STUR
      case 1: addr = base; writeback = true; wb_val = base + static_cast<uint64_t>(imm9); break;
      case 2: addr = base + static_cast<uint64_t>(imm9); unpriv_ = true; break;  // LDTR/STTR
      default: addr = base + static_cast<uint64_t>(imm9); writeback = true; wb_val = addr; break;
    }
  } else {
    if (bits(i, 11, 10) != 2) return undef();  // atomics (LSE) / PAC loads: not implemented
    const unsigned option = bits(i, 15, 13);
    if (!(option == 2 || option == 3 || option == 6 || option == 7)) return undef();
    const unsigned shift = bit(i, 12) ? size : 0;
    addr = base + extend_val(rd(bits(i, 20, 16)), option, shift);
    is_register_offset = true;
  }

  // Decode the operation from (size, opc).
  enum { Store, Load, LoadSigned64, LoadSigned32, Prefetch } op;
  switch (opc) {
    case 0: op = Store; break;
    case 1: op = Load; break;
    case 2:
      if (size == 3) op = Prefetch; else op = LoadSigned64;
      break;
    default:
      if (size >= 2) return undef();
      op = LoadSigned32;
      break;
  }
  if (op == Prefetch) {
    // PRFM (immediate/literal-free forms): hint, no architectural effect. Pre/post-indexed
    // and unprivileged forms are unallocated.
    if (!(is_imm_scaled || is_unscaled || is_register_offset)) return undef();
    return;
  }

  const unsigned bytes = 1u << size;
  if (op == Store) {
    if (!mem_write(addr, bytes, rd(rt))) return;
    if (writeback) wr_sp(rn, wb_val);
    return;
  }
  uint64_t v = 0;
  if (!mem_read(addr, bytes, v)) return;
  if (op == LoadSigned64) v = static_cast<uint64_t>(sext(v, bytes * 8));
  else if (op == LoadSigned32) v = static_cast<uint32_t>(sext(v, bytes * 8));
  if (writeback) wr_sp(rn, wb_val);
  wr(rt, v);
}

void Cpu::exec_ldst_pair(uint32_t i) {
  const unsigned opc = bits(i, 31, 30), type = bits(i, 24, 23);
  const bool load = bit(i, 22);
  const unsigned rt = bits(i, 4, 0), rt2 = bits(i, 14, 10), rn = bits(i, 9, 5);
  if (opc == 3 || (opc == 1 && !load)) return undef();  // opc 11 reserved; STGP needs MTE
  if (type == 0 && opc == 1) return undef();            // no LDNPSW
  const bool is64 = opc == 2;
  const unsigned scale = is64 ? 3 : 2;
  const unsigned bytes = 1u << scale;
  const int64_t off = sext(bits(i, 21, 15), 7) * (int64_t{1} << scale);

  const uint64_t base = rd_sp(rn);
  uint64_t addr = base;
  bool writeback = false;
  uint64_t wb_val = 0;
  switch (type) {
    case 0: case 2: addr = base + static_cast<uint64_t>(off); break;       // STNP/LDNP, offset
    case 1: wb_val = base + static_cast<uint64_t>(off); writeback = true; break;  // post-index
    default: addr = base + static_cast<uint64_t>(off); wb_val = addr; writeback = true; break;
  }

  if (load) {
    uint64_t a = 0, b = 0;
    if (!mem_read(addr, bytes, a) || !mem_read(addr + bytes, bytes, b)) return;
    if (opc == 1) {  // LDPSW
      a = static_cast<uint64_t>(sext(a, 32));
      b = static_cast<uint64_t>(sext(b, 32));
    }
    if (writeback) wr_sp(rn, wb_val);
    wr(rt, a);
    wr(rt2, b);
  } else {
    if (!mem_write(addr, bytes, rd(rt)) || !mem_write(addr + bytes, bytes, rd(rt2))) return;
    if (writeback) wr_sp(rn, wb_val);
  }
}

void Cpu::exec_ldst_literal(uint32_t i) {
  const unsigned opc = bits(i, 31, 30), rt = bits(i, 4, 0);
  if (opc == 3) return;  // PRFM (literal)
  const uint64_t addr = cur_pc_ + static_cast<uint64_t>(sext(bits(i, 23, 5), 19) * 4);
  uint64_t v = 0;
  if (!mem_read(addr, opc == 1 ? 8 : 4, v)) return;
  if (opc == 2) v = static_cast<uint64_t>(sext(v, 32));  // LDRSW
  wr(rt, v);
}

void Cpu::exec_ldst_exclusive(uint32_t i) {
  const unsigned size = bits(i, 31, 30);
  const bool o2 = bit(i, 23), l = bit(i, 22), o1 = bit(i, 21), o0 = bit(i, 15);
  const unsigned rs = bits(i, 20, 16), rt2 = bits(i, 14, 10), rn = bits(i, 9, 5), rt = bits(i, 4, 0);
  const uint64_t addr = rd_sp(rn);

  if (!o2 && !o1) {  // LDXR / LDAXR / STXR / STLXR
    const unsigned bytes = 1u << size;
    if (l) {
      uint64_t v;
      if (!mem_read(addr, bytes, v, true)) return;
      mon_ = {true, addr, bytes};
      wr(rt, v);
    } else {
      if (addr & (bytes - 1)) return raise_data_abort(addr, true, 0x21, false);
      const bool ok = mon_.valid && mon_.addr == addr && mon_.size == bytes;
      if (ok && !mem_write(addr, bytes, rd(rt), true)) return;
      mon_.valid = false;
      wr(rs, ok ? 0 : 1);
    }
    return;
  }
  if (!o2 && o1) {  // LDXP / LDAXP / STXP / STLXP
    if (size < 2) return undef();
    const unsigned elem = size == 3 ? 8 : 4;
    const unsigned total = elem * 2;
    if (l) {
      uint64_t a, b;
      if (addr & (total - 1)) return raise_data_abort(addr, false, 0x21, false);
      if (!mem_read(addr, elem, a) || !mem_read(addr + elem, elem, b)) return;
      mon_ = {true, addr, total};
      wr(rt, a);
      wr(rt2, b);
    } else {
      if (addr & (total - 1)) return raise_data_abort(addr, true, 0x21, false);
      const bool ok = mon_.valid && mon_.addr == addr && mon_.size == total;
      if (ok && (!mem_write(addr, elem, rd(rt)) || !mem_write(addr + elem, elem, rd(rt2)))) return;
      mon_.valid = false;
      wr(rs, ok ? 0 : 1);
    }
    return;
  }
  if (o2 && !o1) {  // LDAR / STLR (o0 = 0 would be LORegion LDLAR/STLLR: not implemented)
    if (!o0) return undef();
    const unsigned bytes = 1u << size;
    if (l) {
      uint64_t v;
      if (!mem_read(addr, bytes, v, true)) return;
      wr(rt, v);
    } else {
      mem_write(addr, bytes, rd(rt), true);
    }
    return;
  }
  undef();  // CAS / CASP (LSE atomics): not advertised in ID_AA64ISAR0_EL1
}

}  // namespace bbn
