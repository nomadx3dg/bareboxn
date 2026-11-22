#include "memory/bus.h"

#include <algorithm>
#include <cstring>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#endif

namespace bbn {

std::unique_ptr<HostRam> HostRam::create(uint64_t size) {
  if (size == 0 || size > (uint64_t{1} << 46)) return nullptr;
#if defined(__unix__) || defined(__APPLE__)
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_NORESERVE
  flags |= MAP_NORESERVE;
#endif
  void* p = mmap(nullptr, static_cast<size_t>(size), PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED) return nullptr;
  return std::unique_ptr<HostRam>(new HostRam(static_cast<uint8_t*>(p), size));
#else
  return nullptr;
#endif
}

HostRam::~HostRam() {
#if defined(__unix__) || defined(__APPLE__)
  if (data_) munmap(data_, static_cast<size_t>(size_));
#endif
}

bool Bus::insert(Region&& r) {
  if (r.size == 0 || r.base + r.size < r.base) return false;  // empty or wraps
  for (const Region& e : regions_) {
    if (r.base < e.base + e.size && e.base < r.base + r.size) return false;  // overlap
  }
  regions_.push_back(std::move(r));
  std::sort(regions_.begin(), regions_.end(),
            [](const Region& a, const Region& b) { return a.base < b.base; });
  last_hit_ = nullptr;
  return true;
}

bool Bus::add_ram(uint64_t base, uint64_t size, const std::string& name) {
  if (size == 0 || base + size < base) return false;
  for (const Region& e : regions_) {
    if (base < e.base + e.size && e.base < base + size) return false;
  }
  auto ram = HostRam::create(size);
  if (!ram) return false;
  Region r;
  r.base = base;
  r.size = size;
  r.ram = std::move(ram);
  r.name = name;
  return insert(std::move(r));
}

bool Bus::add_mmio(uint64_t base, uint64_t size, MmioDevice* dev, const std::string& name) {
  if (!dev) return false;
  Region r;
  r.base = base;
  r.size = size;
  r.dev = dev;
  r.name = name;
  return insert(std::move(r));
}

Bus::Region* Bus::find(uint64_t addr, size_t len) {
  auto covers = [&](const Region& r) {
    return addr >= r.base && len <= r.size && addr - r.base <= r.size - len;
  };
  if (last_hit_ && covers(*last_hit_)) return last_hit_;
  // Last region with base <= addr.
  auto it = std::upper_bound(regions_.begin(), regions_.end(), addr,
                             [](uint64_t a, const Region& r) { return a < r.base; });
  if (it == regions_.begin()) return nullptr;
  --it;
  if (!covers(*it)) return nullptr;
  last_hit_ = &*it;
  return last_hit_;
}

BusResult Bus::read(uint64_t addr, unsigned size, uint64_t& value) {
  Region* r = find(addr, size);
  if (!r) return BusResult::Unmapped;
  if (r->ram) {
    uint64_t v = 0;
    std::memcpy(&v, r->ram->data() + (addr - r->base), size);  // little-endian host
    value = v;
    return BusResult::Ok;
  }
  uint64_t v = 0;
  if (!r->dev->read(addr - r->base, size, v)) return BusResult::DeviceFault;
  value = size == 8 ? v : (v & ((uint64_t{1} << (size * 8)) - 1));
  return BusResult::Ok;
}

BusResult Bus::write(uint64_t addr, unsigned size, uint64_t value) {
  Region* r = find(addr, size);
  if (!r) return BusResult::Unmapped;
  if (r->ram) {
    std::memcpy(r->ram->data() + (addr - r->base), &value, size);
    return BusResult::Ok;
  }
  if (!r->dev->write(addr - r->base, size, value)) return BusResult::DeviceFault;
  return BusResult::Ok;
}

bool Bus::fetch32(uint64_t addr, uint32_t& insn) {
  Region* r = find(addr, 4);
  if (!r || !r->ram) return false;
  std::memcpy(&insn, r->ram->data() + (addr - r->base), 4);
  return true;
}

uint8_t* Bus::ram_ptr(uint64_t addr, size_t len) {
  Region* r = find(addr, len ? len : 1);
  if (!r || !r->ram) return nullptr;
  return r->ram->data() + (addr - r->base);
}

bool Bus::read_bytes(uint64_t addr, void* dst, size_t len) {
  if (len == 0) return true;
  uint8_t* p = ram_ptr(addr, len);
  if (!p) return false;
  std::memcpy(dst, p, len);
  return true;
}

bool Bus::write_bytes(uint64_t addr, const void* src, size_t len) {
  if (len == 0) return true;
  uint8_t* p = ram_ptr(addr, len);
  if (!p) return false;
  std::memcpy(p, src, len);
  return true;
}

std::vector<Bus::RegionInfo> Bus::regions() const {
  std::vector<RegionInfo> out;
  for (const Region& r : regions_) out.push_back({r.base, r.size, r.ram != nullptr, r.name});
  return out;
}

}  // namespace bbn
