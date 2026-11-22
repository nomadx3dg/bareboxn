#include "devices/pl011.h"

namespace bbn {
namespace {
enum : uint32_t {
  DR = 0x000, RSR = 0x004, FR = 0x018, ILPR = 0x020, IBRD = 0x024, FBRD = 0x028,
  LCR_H = 0x02C, CR = 0x030, IFLS = 0x034, IMSC = 0x038, RIS = 0x03C, MIS = 0x040,
  ICR = 0x044, DMACR = 0x048,
  PERIPH_ID0 = 0xFE0, CELL_ID0 = 0xFF0,
};
constexpr uint32_t FR_RXFE = 1u << 4, FR_TXFE = 1u << 7, FR_RXFF = 1u << 6;
constexpr uint32_t INT_RX = 1u << 4, INT_TX = 1u << 5, INT_OE = 1u << 10;
// AMBA PeriphID0..3 and PrimeCellID0..3 for a PL011 (as exposed by QEMU/hardware).
constexpr uint8_t kPeriphId[4] = {0x11, 0x10, 0x14, 0x00};
constexpr uint8_t kCellId[4] = {0x0D, 0xF0, 0x05, 0xB1};
}  // namespace

void Pl011::reset() {
  rx_.clear();
  rsr_ = ilpr_ = ibrd_ = fbrd_ = lcr_h_ = 0;
  cr_ = 0x0300;  // TXE | RXE
  ifls_ = 0x12;
  imsc_ = ris_ = dmacr_ = 0;
  last_irq_ = false;
}

bool Pl011::push_rx(uint8_t byte) {
  if (rx_.size() >= kFifoDepth) {
    ris_ |= INT_OE;
    update_irq();
    return false;
  }
  rx_.push_back(byte);
  ris_ |= INT_RX;
  update_irq();
  return true;
}

void Pl011::update_irq() {
  bool level = irq_level();
  if (level != last_irq_) {
    last_irq_ = level;
    if (irq_cb_) irq_cb_(level);
  }
}

uint32_t Pl011::read_reg(uint32_t reg) {
  switch (reg) {
    case DR: {
      if (rx_.empty()) return 0;
      uint32_t v = rx_.front();
      rx_.pop_front();
      if (rx_.empty()) ris_ &= ~INT_RX;
      update_irq();
      return v;
    }
    case RSR: return rsr_;
    case FR: return FR_TXFE | (rx_.empty() ? FR_RXFE : 0) | (rx_.size() >= kFifoDepth ? FR_RXFF : 0);
    case ILPR: return ilpr_;
    case IBRD: return ibrd_;
    case FBRD: return fbrd_;
    case LCR_H: return lcr_h_;
    case CR: return cr_;
    case IFLS: return ifls_;
    case IMSC: return imsc_;
    case RIS: return ris_;
    case MIS: return ris_ & imsc_;
    case DMACR: return dmacr_;
    default:
      if (reg >= PERIPH_ID0 && reg < PERIPH_ID0 + 16) return kPeriphId[(reg - PERIPH_ID0) / 4];
      if (reg >= CELL_ID0 && reg < CELL_ID0 + 16) return kCellId[(reg - CELL_ID0) / 4];
      return 0;  // reserved/unimplemented registers read as zero
  }
}

void Pl011::write_reg(uint32_t reg, uint32_t value) {
  switch (reg) {
    case DR:
      if (tx_) tx_(static_cast<uint8_t>(value & 0xFF));
      ris_ |= INT_TX;  // FIFO is at/below the trigger level again immediately
      update_irq();
      break;
    case RSR: rsr_ = 0; break;  // ECR: any write clears the error flags
    case ILPR: ilpr_ = value & 0xFF; break;
    case IBRD: ibrd_ = value & 0xFFFF; break;
    case FBRD: fbrd_ = value & 0x3F; break;
    case LCR_H: lcr_h_ = value & 0xFF; break;
    case CR: cr_ = value & 0xFFFF; break;
    case IFLS: ifls_ = value & 0x3F; break;
    case IMSC: imsc_ = value & 0x7FF; update_irq(); break;
    case ICR: ris_ &= ~(value & 0x7FF); update_irq(); break;
    case DMACR: dmacr_ = value & 0x7; break;
    default: break;  // read-only / reserved: write ignored
  }
}

bool Pl011::read(uint64_t offset, unsigned size, uint64_t& value) {
  if (size > 4 || offset >= kRegionSize) return false;
  uint32_t word = read_reg(static_cast<uint32_t>(offset & ~uint64_t{3}));
  unsigned shift = static_cast<unsigned>(offset & 3) * 8;
  if (shift + size * 8 > 32) return false;  // access straddles a register
  value = (word >> shift) & (size == 4 ? 0xFFFFFFFFu : ((1u << (size * 8)) - 1u));
  return true;
}

bool Pl011::write(uint64_t offset, unsigned size, uint64_t value) {
  if (size > 4 || offset >= kRegionSize) return false;
  unsigned shift = static_cast<unsigned>(offset & 3) * 8;
  if (shift + size * 8 > 32) return false;
  write_reg(static_cast<uint32_t>(offset & ~uint64_t{3}), static_cast<uint32_t>(value) << shift);
  return true;
}

}  // namespace bbn
