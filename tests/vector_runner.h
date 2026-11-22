// Runs generated instruction vectors (tests/gen_vectors.py) on a bbn-virt machine.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "bbn_test.h"
#include "machine/virt.h"

struct Seg { uint64_t addr; std::vector<uint32_t> words; };
struct NamedVal { const char* name; uint64_t value; };
struct MemBlob { uint64_t addr; std::vector<uint8_t> bytes; };
struct Vec {
  const char* name;
  std::vector<Seg> segs;
  std::vector<NamedVal> init;
  std::vector<MemBlob> mem_init;
  std::vector<NamedVal> expect;
  std::vector<MemBlob> mem_expect;
  uint64_t entry;
  uint64_t max_insns;
  const char* stop;  // "Halt" or "Unsupported"
};

inline bool reg_ref(bbn::CpuState& s, const std::string& n, uint64_t*& p, uint64_t& tmp) {
  if (n.size() >= 2 && n[0] == 'x') { int i = std::atoi(n.c_str() + 1); if (i < 0 || i > 30) return false; p = &s.x[i]; return true; }
  if (n == "sp") { p = &s.sp_el1; return true; }
  if (n == "sp_el0") { p = &s.sp_el0; return true; }
  if (n == "pc") { p = &s.pc; return true; }
  if (n == "esr_el1") { p = &s.esr_el1; return true; }
  if (n == "far_el1") { p = &s.far_el1; return true; }
  if (n == "el") { tmp = s.el; p = &tmp; return true; }
  if (n == "nzcv") { tmp = (s.n << 3) | (s.z << 2) | (s.c << 1) | s.v; p = &tmp; return true; }
  return false;
}

inline void run_vector(const Vec& v) {
  bbn::VirtConfig cfg;
  cfg.ram_size = 1 << 20;
  bbn::VirtMachine m(cfg);
  if (!m.ok()) { CHECK(false); return; }
  for (auto& sg : v.segs) CHECK(m.load_blob(sg.addr, sg.words.data(), sg.words.size() * 4));
  for (auto& mi : v.mem_init) CHECK(m.load_blob(mi.addr, mi.bytes.data(), mi.bytes.size()));
  m.cpu().reset(v.entry);
  auto& s = m.cpu().state();
  for (auto& iv : v.init) {
    std::string n = iv.name;
    if (n == "nzcv") { s.n = iv.value & 8; s.z = iv.value & 4; s.c = iv.value & 2; s.v = iv.value & 1; continue; }
    uint64_t* p; uint64_t tmp;
    if (!reg_ref(s, n, p, tmp)) { std::fprintf(stderr, "  [%s] bad init reg %s\n", v.name, iv.name); CHECK(false); continue; }
    *p = iv.value;
  }
  const bbn::StopReason r = m.cpu().run(v.max_insns);
  const bbn::StopReason want = std::strcmp(v.stop, "Unsupported") == 0 ? bbn::StopReason::Unsupported : bbn::StopReason::Halt;
  if (r != want) {
    std::fprintf(stderr, "  [%s] stop reason %d, wanted %d (pc=0x%llx %s)\n", v.name, (int)r, (int)want,
                 (unsigned long long)s.pc, m.cpu().stop_message().c_str());
    CHECK(false);
  }
  for (auto& ev : v.expect) {
    uint64_t* p; uint64_t tmp;
    if (!reg_ref(s, ev.name, p, tmp)) { std::fprintf(stderr, "  [%s] bad expect reg %s\n", v.name, ev.name); CHECK(false); continue; }
    if (*p != ev.value) {
      std::fprintf(stderr, "  [%s] %s = 0x%llx, expected 0x%llx\n", v.name, ev.name, (unsigned long long)*p, (unsigned long long)ev.value);
      CHECK(false);
    }
  }
  for (auto& me : v.mem_expect) {
    std::vector<uint8_t> got(me.bytes.size());
    m.bus().read_bytes(me.addr, got.data(), got.size());
    if (got != me.bytes) { std::fprintf(stderr, "  [%s] memory at 0x%llx differs\n", v.name, (unsigned long long)me.addr); CHECK(false); }
  }
}

inline void run_all_vectors(const std::vector<Vec>& vecs) {
  for (const Vec& v : vecs) run_vector(v);
}
