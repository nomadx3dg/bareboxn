// ARM PrimeCell PL011 UART (register-compatible subset sufficient for Linux's
// amba-pl011 driver and bare-metal firmware): data, flags, control, interrupt
// registers and the AMBA identification registers.
//
// Model simplifications (see docs/ARCHITECTURE.md):
//  * The TX FIFO drains instantly, so FR.TXFE is always set.
//  * Transmission is not gated on CR.UARTEN/TXE (matches QEMU's behaviour,
//    which lets early firmware print without programming the UART).
//  * Baud-rate/line-control registers are stored but have no effect.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>

#include "memory/bus.h"

namespace bbn {

class Pl011 : public MmioDevice {
 public:
  using TxSink = std::function<void(uint8_t)>;
  using IrqCallback = std::function<void(bool level)>;

  static constexpr uint64_t kRegionSize = 0x1000;
  static constexpr size_t kFifoDepth = 16;

  explicit Pl011(TxSink sink = nullptr) : tx_(std::move(sink)) { reset(); }

  void reset();
  void set_irq_callback(IrqCallback cb) { irq_cb_ = std::move(cb); }
  bool irq_level() const { return (ris_ & imsc_) != 0; }

  // Host -> guest byte. Returns false (byte dropped, overrun flagged) if the RX FIFO is full.
  bool push_rx(uint8_t byte);

  bool read(uint64_t offset, unsigned size, uint64_t& value) override;
  bool write(uint64_t offset, unsigned size, uint64_t value) override;

 private:
  uint32_t read_reg(uint32_t reg);
  void write_reg(uint32_t reg, uint32_t value);
  void update_irq();

  TxSink tx_;
  IrqCallback irq_cb_;
  std::deque<uint8_t> rx_;
  uint32_t rsr_ = 0, ilpr_ = 0, ibrd_ = 0, fbrd_ = 0, lcr_h_ = 0, cr_ = 0, ifls_ = 0;
  uint32_t imsc_ = 0, ris_ = 0, dmacr_ = 0;
  bool last_irq_ = false;
};

}  // namespace bbn
