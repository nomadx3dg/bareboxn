// "bbn-virt": the machine model bareboxn guests run on. The physical memory map is
// intentionally identical to QEMU's AArch64 `virt` board so that existing kernels,
// device trees and firmware can be used for comparison. Only devices that are
// implemented are mapped; see docs/ARCHITECTURE.md for the roadmap.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "cpu/cpu.h"
#include "devices/pl011.h"
#include "memory/bus.h"

namespace bbn {

struct VirtMemMap {
  static constexpr uint64_t kFlashBase = 0x00000000;   // reserved (pflash firmware, later)
  static constexpr uint64_t kGicDistBase = 0x08000000; // reserved (GICv3, Phase 2)
  static constexpr uint64_t kUartBase = 0x09000000;    // PL011
  static constexpr uint64_t kRtcBase = 0x09010000;     // reserved
  static constexpr uint64_t kVirtioBase = 0x0a000000;  // reserved (virtio-mmio, Phase 3)
  static constexpr uint64_t kRamBase = 0x40000000;
};

struct VirtConfig {
  uint64_t ram_size = 128ull << 20;
  Pl011::TxSink uart_sink;  // receives bytes the guest writes to the UART
  CpuConfig cpu;
  bool enable_psci = true;  // service HVC/SMC PSCI calls (what the device tree conduit expects)
};

class VirtMachine {
 public:
  explicit VirtMachine(VirtConfig cfg);
  VirtMachine(const VirtMachine&) = delete;
  VirtMachine& operator=(const VirtMachine&) = delete;

  bool ok() const { return ok_; }  // false if RAM allocation / mapping failed
  Bus& bus() { return bus_; }
  Cpu& cpu() { return cpu_; }
  Pl011& uart() { return uart_; }
  uint64_t ram_base() const { return VirtMemMap::kRamBase; }
  uint64_t ram_size() const { return cfg_.ram_size; }

  // Copy a flat binary into guest RAM. Returns false if it does not fit.
  bool load_blob(uint64_t addr, const void* data, size_t len);
  bool load_file(uint64_t addr, const std::string& path, std::string* error = nullptr);

 private:
  VirtConfig cfg_;
  Bus bus_;
  Pl011 uart_;
  Cpu cpu_;
  bool ok_ = false;
};

}  // namespace bbn
