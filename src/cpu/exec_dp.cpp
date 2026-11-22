// Data-processing instructions: immediate and register forms.
#include <bit>

#include "core/bits.h"
#include "cpu/cpu.h"

namespace bbn {
namespace {

// ARM ARM DecodeBitMasks(). Returns false for reserved encodings.
bool decode_bitmasks(bool n, uint32_t imms, uint32_t immr, bool immediate, unsigned m,
                     uint64_t& wmask, uint64_t& tmask) {
  const uint32_t v = (uint32_t{n} << 6) | (~imms & 0x3Fu);
  if (v == 0) return false;
  const unsigned len = 31 - static_cast<unsigned>(std::countl_zero(v));
  if (len < 1 || m < (1u << len)) return false;
  const uint32_t levels = (1u << len) - 1;
  if (immediate && (imms & levels) == levels) return false;
  const uint32_t s = imms & levels;
  const uint32_t r = immr & levels;
  const uint32_t d = (s - r) & levels;
  const unsigned esize = 1u << len;
  const uint64_t welem = mask_n(s + 1);
  const uint64_t telem = mask_n(d + 1);
  auto replicate = [&](uint64_t e) {
    uint64_t out = 0;
    for (unsigned i = 0; i < m; i += esize) out |= e << i;
    return out;
  };
  wmask = replicate(ror(welem, r, esize));
  tmask = replicate(telem);
  return true;
}

uint64_t rev_bytes_in_chunks(uint64_t v, unsigned chunk_bytes, unsigned total_bytes) {
  uint64_t out = 0;
  for (unsigned base = 0; base < total_bytes; base += chunk_bytes) {
    for (unsigned i = 0; i < chunk_bytes; ++i) {
      const uint64_t byte = (v >> ((base + i) * 8)) & 0xFF;
      out |= byte << ((base + chunk_bytes - 1 - i) * 8);
    }
  }
  return out;
}

}  // namespace

void Cpu::exec_dp_imm(uint32_t i) {
  const bool sf = bit(i, 31);
  const unsigned rd_ = bits(i, 4, 0);
  const unsigned rn = bits(i, 9, 5);
  const unsigned dsize = sf ? 64 : 32;
  const uint64_t dmask = mask_n(dsize);

  switch (bits(i, 25, 23)) {
    case 0: case 1: {  // ADR / ADRP
      int64_t imm = sext((uint64_t{bits(i, 23, 5)} << 2) | bits(i, 30, 29), 21);
      uint64_t base = cur_pc_;
      if (sf) {  // ADRP
        base &= ~uint64_t{0xFFF};
        imm *= 4096;
      }
      wr(rd_, base + static_cast<uint64_t>(imm));
      return;
    }
    case 2: {  // ADD/SUB (immediate)
      const bool sub = bit(i, 30), setf = bit(i, 29);
      uint64_t imm = bits(i, 21, 10);
      if (bit(i, 22)) imm <<= 12;
      const uint64_t op1 = rd_sp(rn) & dmask;
      const uint64_t res = sub ? add_with_carry(op1, ~imm & dmask, 1, sf, setf)
                               : add_with_carry(op1, imm, 0, sf, setf);
      if (setf) wr(rd_, res); else wr_sp(rd_, res);
      return;
    }
    case 4: {  // logical (immediate)
      const unsigned opc = bits(i, 30, 29);
      if (!sf && bit(i, 22)) return undef();
      uint64_t wmask, tmask;
      if (!decode_bitmasks(bit(i, 22), bits(i, 15, 10), bits(i, 21, 16), true, dsize, wmask, tmask))
        return undef();
      const uint64_t op1 = rd(rn) & dmask;
      uint64_t res = opc == 1 ? (op1 | wmask) : opc == 2 ? (op1 ^ wmask) : (op1 & wmask);
      res &= dmask;
      if (opc == 3) {
        set_nz(res, sf);
        s_.c = false;
        s_.v = false;
        wr(rd_, res);
      } else {
        wr_sp(rd_, res);
      }
      return;
    }
    case 5: {  // move wide
      const unsigned opc = bits(i, 30, 29), hw = bits(i, 22, 21);
      if (opc == 1 || (!sf && hw > 1)) return undef();
      const unsigned pos = hw * 16;
      const uint64_t imm = uint64_t{bits(i, 20, 5)} << pos;
      if (opc == 0) wr(rd_, ~imm & dmask);                                     // MOVN
      else if (opc == 2) wr(rd_, imm);                                         // MOVZ
      else wr(rd_, ((rd(rd_) & ~(uint64_t{0xFFFF} << pos)) | imm) & dmask);    // MOVK
      return;
    }
    case 6: {  // bitfield: SBFM / BFM / UBFM
      const unsigned opc = bits(i, 30, 29), immr = bits(i, 21, 16), imms = bits(i, 15, 10);
      if (opc == 3 || bit(i, 22) != sf || (!sf && (immr > 31 || imms > 31))) return undef();
      uint64_t wmask, tmask;
      if (!decode_bitmasks(bit(i, 22), imms, immr, false, dsize, wmask, tmask)) return undef();
      const uint64_t src = rd(rn) & dmask;
      const uint64_t rot = ror(src, immr, dsize);
      uint64_t res;
      if (opc == 1) {  // BFM
        const uint64_t dst = rd(rd_) & dmask;
        const uint64_t bot = (dst & ~wmask) | (rot & wmask);
        res = (dst & ~tmask) | (bot & tmask);
      } else {
        const uint64_t bot = rot & wmask;
        if (opc == 0) {  // SBFM
          const uint64_t top = ((src >> imms) & 1) ? dmask : 0;
          res = (top & ~tmask) | (bot & tmask);
        } else {  // UBFM
          res = bot & tmask;
        }
      }
      wr(rd_, res & dmask);
      return;
    }
    case 7: {  // EXTR
      const unsigned rm = bits(i, 20, 16), lsb = bits(i, 15, 10);
      if (bits(i, 30, 29) != 0 || bit(i, 22) != sf || bit(i, 21) || (!sf && lsb > 31))
        return undef();
      const uint64_t hi = rd(rn) & dmask, lo = rd(rm) & dmask;
      const uint64_t res = lsb == 0 ? lo : (((lo >> lsb) | (hi << (dsize - lsb))) & dmask);
      wr(rd_, res);
      return;
    }
    default:  // 3: add/sub with tags (MTE, not implemented)
      return undef();
  }
}

void Cpu::exec_dp_reg(uint32_t i) {
  const bool sf = bit(i, 31);
  const unsigned rd_ = bits(i, 4, 0), rn = bits(i, 9, 5), rm = bits(i, 20, 16);
  const unsigned dsize = sf ? 64 : 32;
  const uint64_t dmask = mask_n(dsize);

  if (!bit(i, 28)) {
    if (!bit(i, 24)) {  // logical (shifted register)
      const unsigned opc = bits(i, 30, 29), shift = bits(i, 23, 22), imm6 = bits(i, 15, 10);
      if (!sf && imm6 > 31) return undef();
      uint64_t op2 = shift_val(rd(rm) & dmask, shift, imm6, dsize);
      if (bit(i, 21)) op2 = ~op2 & dmask;
      const uint64_t op1 = rd(rn) & dmask;
      uint64_t res = opc == 1 ? (op1 | op2) : opc == 2 ? (op1 ^ op2) : (op1 & op2);
      res &= dmask;
      if (opc == 3) {
        set_nz(res, sf);
        s_.c = false;
        s_.v = false;
      }
      wr(rd_, res);
      return;
    }
    const bool sub = bit(i, 30), setf = bit(i, 29);
    uint64_t op2;
    uint64_t op1;
    if (!bit(i, 21)) {  // add/sub (shifted register)
      const unsigned shift = bits(i, 23, 22), imm6 = bits(i, 15, 10);
      if (shift == 3 || (!sf && imm6 > 31)) return undef();
      op2 = shift_val(rd(rm) & dmask, shift, imm6, dsize);
      op1 = rd(rn) & dmask;
      const uint64_t res = sub ? add_with_carry(op1, ~op2 & dmask, 1, sf, setf)
                               : add_with_carry(op1, op2 & dmask, 0, sf, setf);
      wr(rd_, res);
      return;
    }
    // add/sub (extended register)
    const unsigned option = bits(i, 15, 13), imm3 = bits(i, 12, 10);
    if (bits(i, 23, 22) != 0 || imm3 > 4) return undef();
    op2 = extend_val(rd(rm), option, imm3) & dmask;
    op1 = rd_sp(rn) & dmask;
    const uint64_t res = sub ? add_with_carry(op1, ~op2 & dmask, 1, sf, setf)
                             : add_with_carry(op1, op2, 0, sf, setf);
    if (setf) wr(rd_, res); else wr_sp(rd_, res);
    return;
  }

  // bit 28 set
  switch (bits(i, 27, 24)) {
    case 0xA: {  // 1010: carry / conditional compare / conditional select
      switch (bits(i, 23, 21)) {
        case 0: {  // add/sub with carry
          if (bits(i, 15, 10) != 0) return undef();
          const bool sub = bit(i, 30), setf = bit(i, 29);
          const uint64_t op1 = rd(rn) & dmask;
          uint64_t op2 = rd(rm) & dmask;
          if (sub) op2 = ~op2 & dmask;
          wr(rd_, add_with_carry(op1, op2, s_.c ? 1 : 0, sf, setf));
          return;
        }
        case 2: {  // conditional compare (register / immediate)
          if (!bit(i, 29) || bit(i, 10) || bit(i, 4)) return undef();
          const unsigned cond = bits(i, 15, 12), nzcv = bits(i, 3, 0);
          if (cond_holds(cond)) {
            const uint64_t op1 = rd(rn) & dmask;
            const uint64_t op2 = (bit(i, 11) ? uint64_t{rm} : rd(rm)) & dmask;
            if (bit(i, 30)) add_with_carry(op1, ~op2 & dmask, 1, sf, true);  // CCMP
            else add_with_carry(op1, op2, 0, sf, true);                      // CCMN
          } else {
            s_.n = nzcv & 8; s_.z = nzcv & 4; s_.c = nzcv & 2; s_.v = nzcv & 1;
          }
          return;
        }
        case 4: {  // conditional select
          if (bit(i, 29) || bit(i, 11)) return undef();
          const bool op = bit(i, 30), op2 = bit(i, 10);
          uint64_t res;
          if (cond_holds(bits(i, 15, 12))) {
            res = rd(rn);
          } else {
            const uint64_t m = rd(rm);
            if (!op) res = op2 ? m + 1 : m;           // CSEL / CSINC
            else res = op2 ? (~m + 1) : ~m;           // CSNEG / CSINV
          }
          wr(rd_, res & dmask);
          return;
        }
        case 6: {  // data-processing (1 source / 2 source)
      if (bit(i, 29)) return undef();
      const unsigned opcode = bits(i, 15, 10);
      if (bit(i, 30)) {  // 1 source
        if (bits(i, 20, 16) != 0) return undef();
        const uint64_t v = rd(rn) & dmask;
        uint64_t res;
        switch (opcode) {
          case 0: {  // RBIT
            res = 0;
            for (unsigned b = 0; b < dsize; ++b) res |= ((v >> b) & 1) << (dsize - 1 - b);
            break;
          }
          case 1: res = rev_bytes_in_chunks(v, 2, dsize / 8); break;           // REV16
          case 2: res = sf ? rev_bytes_in_chunks(v, 4, 8)                      // REV32
                           : rev_bytes_in_chunks(v, 4, 4); break;              // REV (32)
          case 3:
            if (!sf) return undef();
            res = rev_bytes_in_chunks(v, 8, 8);                                // REV (64)
            break;
          case 4:  // CLZ
            res = sf ? static_cast<uint64_t>(std::countl_zero(v))
                     : static_cast<uint64_t>(std::countl_zero(static_cast<uint32_t>(v)));
            break;
          case 5: {  // CLS: count bits after the sign bit equal to it
            const bool s = (v >> (dsize - 1)) & 1;
            unsigned n = 0;
            for (int b = static_cast<int>(dsize) - 2; b >= 0 && (((v >> b) & 1) == s); --b) ++n;
            res = n;
            break;
          }
          default: return undef();
        }
        wr(rd_, res & dmask);
        return;
      }
      // 2 source
      const uint64_t a = rd(rn) & dmask, b = rd(rm) & dmask;
      uint64_t res;
      switch (opcode) {
        case 2:  // UDIV
          res = b == 0 ? 0 : a / b;
          break;
        case 3: {  // SDIV (divide-by-zero => 0; INT_MIN / -1 => INT_MIN, no trap)
          const int64_t sa = sf ? static_cast<int64_t>(a) : sext(a, 32);
          const int64_t sb = sf ? static_cast<int64_t>(b) : sext(b, 32);
          if (sb == 0) res = 0;
          else if (sb == -1) res = static_cast<uint64_t>(0) - static_cast<uint64_t>(sa);
          else res = static_cast<uint64_t>(sa / sb);
          break;
        }
        case 8: case 9: case 10: case 11:  // LSLV LSRV ASRV RORV
          res = shift_val(a, opcode & 3, static_cast<unsigned>(b % dsize), dsize);
          break;
        default: return undef();  // CRC32*, PACGA, SUBP, IRG, GMI: features not advertised
      }
      wr(rd_, res & dmask);
      return;
    }
        default: return undef();
      }
    }
    case 0xB: {  // 1011: data-processing (3 source)
      if (bits(i, 30, 29) != 0) return undef();
      const unsigned op31 = bits(i, 23, 21), ra = bits(i, 14, 10);
      const bool o0 = bit(i, 15);
      if (op31 == 0) {
        const uint64_t prod = (rd(rn) & dmask) * (rd(rm) & dmask);
        const uint64_t acc = rd(ra) & dmask;
        wr(rd_, (o0 ? acc - prod : acc + prod) & dmask);
        return;
      }
      if (!sf) return undef();
      const uint64_t a = rd(rn), b = rd(rm);
      switch (op31) {
        case 1: {  // SMADDL / SMSUBL
          const int64_t prod = sext(a, 32) * sext(b, 32);
          wr(rd_, o0 ? rd(ra) - static_cast<uint64_t>(prod) : rd(ra) + static_cast<uint64_t>(prod));
          return;
        }
        case 5: {  // UMADDL / UMSUBL
          const uint64_t prod = (a & 0xFFFFFFFFull) * (b & 0xFFFFFFFFull);
          wr(rd_, o0 ? rd(ra) - prod : rd(ra) + prod);
          return;
        }
        case 2:  // SMULH
          if (o0) return undef();
          wr(rd_, static_cast<uint64_t>(
                      (static_cast<__int128>(static_cast<int64_t>(a)) * static_cast<int64_t>(b)) >> 64));
          return;
        case 6:  // UMULH
          if (o0) return undef();
          wr(rd_, static_cast<uint64_t>(
                      (static_cast<unsigned __int128>(a) * b) >> 64));
          return;
        default: return undef();
      }
    }
    default: return undef();
  }
}

}  // namespace bbn
