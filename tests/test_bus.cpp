#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>

#include "bbn_test.h"
#include "memory/bus.h"

namespace {
struct Recorder : bbn::MmioDevice {
  uint64_t last_off = ~0ull, last_val = 0; unsigned last_size = 0; int reads = 0, writes = 0;
  bool reject = false;
  bool read(uint64_t o, unsigned s, uint64_t& v) override { ++reads; last_off = o; last_size = s; v = 0x1122334455667788ull; return !reject; }
  bool write(uint64_t o, unsigned s, uint64_t v) override { ++writes; last_off = o; last_size = s; last_val = v; return !reject; }
};
}  // namespace

BBN_TEST(ram_roundtrip_all_sizes_little_endian) {
  bbn::Bus bus;
  CHECK(bus.add_ram(0x40000000, 0x10000, "ram"));
  uint64_t v = 0;
  CHECK(bus.write(0x40000100, 8, 0x0102030405060708ull) == bbn::BusResult::Ok);
  CHECK(bus.read(0x40000100, 1, v) == bbn::BusResult::Ok); CHECK_EQ(v, 0x08ull);
  CHECK(bus.read(0x40000100, 2, v) == bbn::BusResult::Ok); CHECK_EQ(v, 0x0708ull);
  CHECK(bus.read(0x40000100, 4, v) == bbn::BusResult::Ok); CHECK_EQ(v, 0x05060708ull);
  CHECK(bus.read(0x40000104, 4, v) == bbn::BusResult::Ok); CHECK_EQ(v, 0x01020304ull);
  CHECK(bus.read(0x40000101, 8, v) == bbn::BusResult::Ok);  // unaligned is fine on RAM
  CHECK_EQ(v & 0xFF, 0x07ull);
}

BBN_TEST(unmapped_and_boundary_accesses_fail) {
  bbn::Bus bus;
  bus.add_ram(0x1000, 0x1000, "ram");
  uint64_t v;
  CHECK(bus.read(0x0, 4, v) == bbn::BusResult::Unmapped);
  CHECK(bus.read(0x2000, 1, v) == bbn::BusResult::Unmapped);
  CHECK(bus.read(0x1FFC, 4, v) == bbn::BusResult::Ok);
  CHECK(bus.read(0x1FFD, 4, v) == bbn::BusResult::Unmapped);  // straddles the end
  CHECK(bus.write(0x1FFF, 2, 0) == bbn::BusResult::Unmapped);
  CHECK(bus.read(~0ull - 1, 4, v) == bbn::BusResult::Unmapped);  // address wrap
}

BBN_TEST(overlap_and_degenerate_regions_rejected) {
  bbn::Bus bus; Recorder d;
  CHECK(bus.add_ram(0x1000, 0x1000, "a"));
  CHECK(!bus.add_ram(0x1800, 0x1000, "overlap"));
  CHECK(!bus.add_mmio(0x1FFF, 2, &d, "overlap-mmio"));
  CHECK(!bus.add_ram(0x5000, 0, "empty"));
  CHECK(!bus.add_ram(~0ull - 10, 100, "wraps"));
  CHECK(!bus.add_mmio(0x9000, 0x10, nullptr, "null-device"));
  CHECK(bus.add_mmio(0x2000, 0x10, &d, "ok-adjacent"));
  CHECK_EQ(bus.regions().size(), 2u);
}

BBN_TEST(mmio_dispatch_offsets_sizes_and_faults) {
  bbn::Bus bus; Recorder d;
  CHECK(bus.add_ram(0x40000000, 0x1000, "ram"));
  CHECK(bus.add_mmio(0x09000000, 0x1000, &d, "dev"));
  uint64_t v = 0;
  CHECK(bus.read(0x09000018, 4, v) == bbn::BusResult::Ok);
  CHECK_EQ(d.last_off, 0x18ull); CHECK_EQ(d.last_size, 4u); CHECK_EQ(v, 0x55667788ull);  // masked to access size
  CHECK(bus.write(0x09000FFC, 2, 0xABCD) == bbn::BusResult::Ok);
  CHECK_EQ(d.last_off, 0xFFCull); CHECK_EQ(d.last_val, 0xABCDull);
  CHECK(bus.read(0x09000FFE, 4, v) == bbn::BusResult::Unmapped);  // straddles end of device
  d.reject = true;
  CHECK(bus.read(0x09000000, 8, v) == bbn::BusResult::DeviceFault);
  CHECK(bus.write(0x09000000, 1, 0) == bbn::BusResult::DeviceFault);
}

BBN_TEST(instruction_fetch_only_from_ram) {
  bbn::Bus bus; Recorder d;
  bus.add_ram(0x1000, 0x1000, "ram"); bus.add_mmio(0x2000, 0x1000, &d, "dev");
  const uint32_t w = 0xD503201F;
  CHECK(bus.write_bytes(0x1000, &w, 4));
  uint32_t r = 0;
  CHECK(bus.fetch32(0x1000, r)); CHECK_EQ(r, w);
  CHECK(!bus.fetch32(0x2000, r));
  CHECK_EQ(d.reads, 0);  // fetch must not have side effects on devices
  CHECK(!bus.fetch32(0x9000, r));
}

BBN_TEST(bulk_access_and_host_pointers) {
  bbn::Bus bus; Recorder d;
  bus.add_ram(0x1000, 0x1000, "r1"); bus.add_ram(0x2000, 0x1000, "r2"); bus.add_mmio(0x3000, 0x100, &d, "d");
  uint8_t buf[8] = {1, 2, 3, 4, 5, 6, 7, 8}, out[8] = {};
  CHECK(bus.write_bytes(0x1FF0, buf, 8)); CHECK(bus.read_bytes(0x1FF0, out, 8)); CHECK(!memcmp(buf, out, 8));
  CHECK(!bus.write_bytes(0x1FFC, buf, 8));    // crosses region boundary: refused, no partial write
  CHECK(!bus.read_bytes(0x3000, out, 4));     // MMIO is not bulk-accessible
  CHECK(bus.ram_ptr(0x1000, 16) != nullptr);
  CHECK(bus.ram_ptr(0x3000, 4) == nullptr);
  CHECK(bus.write_bytes(0x1000, nullptr, 0));  // zero-length is a no-op
}

BBN_TEST(ram_is_lazily_committed_and_zero_filled) {
  // A 1 GiB region must not consume 1 GiB of resident memory until touched.
  bbn::Bus bus;
  CHECK(bus.add_ram(0x40000000, 1ull << 30, "big"));
  uint64_t v = 1;
  CHECK(bus.read(0x40000000 + (1ull << 29), 8, v) == bbn::BusResult::Ok); CHECK_EQ(v, 0ull);
  CHECK(bus.write(0x40000000 + (1ull << 30) - 8, 8, 0xAA) == bbn::BusResult::Ok);
#ifdef __linux__
  std::ifstream f("/proc/self/statm"); long pages = 0, rss = 0; f >> pages >> rss;
  CHECK(rss * 4096 < 64l * 1024 * 1024);
#endif
}

BBN_TEST_MAIN()
