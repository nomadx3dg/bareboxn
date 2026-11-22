// bbn-difftest: single-instruction executor used by tools/difftest/difftest.py to compare
// bareboxn's AArch64 interpreter against an independent reference (Unicorn/QEMU TCG).
//
// Usage: bbn-difftest <pattern-file>     (1 MiB of initial RAM contents)
// stdin  line: INSN SP NZCV X0 ... X30                      (hex, one case per line)
// stdout line: ok PC SP NZCV X0 ... X30 CRC32(data-window)  or  exc EC
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <vector>

#include "cpu/cpu.h"

namespace {
constexpr uint64_t kRamBase = 0x100000, kRamSize = 0x100000;
constexpr uint64_t kCodeAddr = 0x180000, kVbar = 0x1A0000;
constexpr uint64_t kWinBase = 0x170000, kWinSize = 0x2000;

uint32_t crc32(const uint8_t* p, size_t n) {
  static uint32_t table[256];
  static bool init = false;
  if (!init) {
    for (uint32_t i = 0; i < 256; ++i) {
      uint32_t c = i;
      for (int k = 0; k < 8; ++k) c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
      table[i] = c;
    }
    init = true;
  }
  uint32_t c = 0xFFFFFFFFu;
  for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
  return c ^ 0xFFFFFFFFu;
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) { std::fprintf(stderr, "usage: bbn-difftest <pattern-file>\n"); return 1; }
  std::ifstream pf(argv[1], std::ios::binary);
  std::vector<char> pattern((std::istreambuf_iterator<char>(pf)), std::istreambuf_iterator<char>());
  if (pattern.size() != kRamSize) { std::fprintf(stderr, "pattern must be %llu bytes\n", (unsigned long long)kRamSize); return 1; }

  bbn::Bus bus;
  if (!bus.add_ram(kRamBase, kRamSize, "ram")) return 1;
  bbn::Cpu cpu(bus);

  std::string line;
  while (std::getline(std::cin, line)) {
    std::istringstream in(line);
    uint64_t insn, sp, nzcv, x[31];
    in >> std::hex >> insn >> sp >> nzcv;
    for (auto& r : x) in >> r;
    if (!in) { std::printf("error bad-line\n"); std::fflush(stdout); continue; }

    bus.write_bytes(kRamBase, pattern.data(), pattern.size());
    const uint32_t w = static_cast<uint32_t>(insn);
    bus.write_bytes(kCodeAddr, &w, 4);
    cpu.reset(kCodeAddr);
    auto& s = cpu.state();
    for (int i = 0; i < 31; ++i) s.x[i] = x[i];
    s.sp_el1 = sp;
    s.n = nzcv & 8; s.z = nzcv & 4; s.c = nzcv & 2; s.v = nzcv & 1;
    s.vbar_el1 = kVbar;
    s.esr_el1 = ~uint64_t{0};  // sentinel: any synchronous exception overwrites ESR_EL1
    cpu.step();

    if (s.esr_el1 != ~uint64_t{0}) {
      std::printf("exc %llx\n", (unsigned long long)(s.esr_el1 >> 26));
    } else {
      uint8_t win[kWinSize];
      bus.read_bytes(kWinBase, win, kWinSize);
      std::printf("ok %llx %llx %x", (unsigned long long)s.pc, (unsigned long long)s.sp_el1,
                  (s.n << 3) | (s.z << 2) | (s.c << 1) | (unsigned)s.v);
      for (int i = 0; i < 31; ++i) std::printf(" %llx", (unsigned long long)s.x[i]);
      std::printf(" %x\n", crc32(win, kWinSize));
    }
    std::fflush(stdout);
  }
  return 0;
}
