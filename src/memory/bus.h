// Guest physical address space: lazily-committed RAM regions and MMIO dispatch.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bbn {

// Interface implemented by every memory-mapped device model.
// `offset` is relative to the start of the region the device is mapped at.
// `size` is the access width in bytes (1, 2, 4 or 8). Returning false makes the
// access fault (reported to the guest as a synchronous external abort).
class MmioDevice {
 public:
  virtual ~MmioDevice() = default;
  virtual bool read(uint64_t offset, unsigned size, uint64_t& value) = 0;
  virtual bool write(uint64_t offset, unsigned size, uint64_t value) = 0;
};

enum class BusResult : uint8_t {
  Ok,
  Unmapped,     // no region covers the whole access
  DeviceFault,  // a device rejected the access (e.g. unsupported width)
};

// Anonymous host memory reserved with MAP_NORESERVE: pages are committed by the
// host kernel only when the guest first touches them, and read as zero before.
class HostRam {
 public:
  static std::unique_ptr<HostRam> create(uint64_t size);
  ~HostRam();
  HostRam(const HostRam&) = delete;
  HostRam& operator=(const HostRam&) = delete;
  uint8_t* data() { return data_; }
  uint64_t size() const { return size_; }

 private:
  HostRam(uint8_t* d, uint64_t s) : data_(d), size_(s) {}
  uint8_t* data_;
  uint64_t size_;
};

class Bus {
 public:
  Bus() = default;
  Bus(const Bus&) = delete;
  Bus& operator=(const Bus&) = delete;

  // Region registration. Returns false (and leaves the map unchanged) if the
  // range is empty, wraps, overlaps an existing region, or allocation fails.
  // The device must outlive the Bus.
  bool add_ram(uint64_t base, uint64_t size, const std::string& name);
  bool add_mmio(uint64_t base, uint64_t size, MmioDevice* dev, const std::string& name);

  // Guest-visible accesses (little-endian). `size` in {1,2,4,8}.
  BusResult read(uint64_t addr, unsigned size, uint64_t& value);
  BusResult write(uint64_t addr, unsigned size, uint64_t value);

  // Instruction fetch: only RAM is executable.
  bool fetch32(uint64_t addr, uint32_t& insn);

  // Bulk access to RAM for loaders / DMA. Fail (return false/nullptr) unless the
  // whole range lies inside a single RAM region.
  bool read_bytes(uint64_t addr, void* dst, size_t len);
  bool write_bytes(uint64_t addr, const void* src, size_t len);
  uint8_t* ram_ptr(uint64_t addr, size_t len);

  struct RegionInfo {
    uint64_t base;
    uint64_t size;
    bool is_ram;
    std::string name;
  };
  std::vector<RegionInfo> regions() const;

 private:
  struct Region {
    uint64_t base = 0;
    uint64_t size = 0;
    std::unique_ptr<HostRam> ram;  // non-null for RAM
    MmioDevice* dev = nullptr;     // non-null for MMIO
    std::string name;
  };
  Region* find(uint64_t addr, size_t len);
  bool insert(Region&& r);

  std::vector<Region> regions_;  // sorted by base, non-overlapping
  Region* last_hit_ = nullptr;   // invalidated whenever regions_ changes
};

}  // namespace bbn
