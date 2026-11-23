// bbn-run: load a flat AArch64 binary into a bbn-virt machine and run it.
// UART output goes to stdout; diagnostics go to stderr.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "machine/virt.h"

namespace {
void usage() {
  std::fprintf(stderr,
               "usage: bbn-run [options] <image.bin>\n"
               "  --load-addr <hex>   guest physical load address (default 0x40000000)\n"
               "  --entry <hex>       entry point (default: load address)\n"
               "  --ram <MiB>         guest RAM size (default 128)\n"
               "  --max-insns <n>     instruction budget (default 100000000)\n"
               "  --regs              dump registers on exit\n"
               "exit status: 0 on HLT/PSCI power off, 2 on instruction limit/WFI, 3 on unsupported feature,\n               4 on PSCI reset, 1 on error\n");
}
}  // namespace

int main(int argc, char** argv) {
  uint64_t load = bbn::VirtMemMap::kRamBase, entry = 0;
  bool have_entry = false, dump = false;
  uint64_t ram_mib = 128, max_insns = 100000000ull;
  std::string path;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (a == "--load-addr") { const char* v = next(); if (!v) { usage(); return 1; } load = std::strtoull(v, nullptr, 0); }
    else if (a == "--entry") { const char* v = next(); if (!v) { usage(); return 1; } entry = std::strtoull(v, nullptr, 0); have_entry = true; }
    else if (a == "--ram") { const char* v = next(); if (!v) { usage(); return 1; } ram_mib = std::strtoull(v, nullptr, 0); }
    else if (a == "--max-insns") { const char* v = next(); if (!v) { usage(); return 1; } max_insns = std::strtoull(v, nullptr, 0); }
    else if (a == "--regs") dump = true;
    else if (a == "-h" || a == "--help") { usage(); return 0; }
    else if (!a.empty() && a[0] == '-') { usage(); return 1; }
    else path = a;
  }
  if (path.empty()) { usage(); return 1; }

  bbn::VirtConfig cfg;
  cfg.ram_size = ram_mib << 20;
  cfg.uart_sink = [](uint8_t b) { std::fputc(b, stdout); };
  bbn::VirtMachine m(cfg);
  if (!m.ok()) { std::fprintf(stderr, "bbn-run: failed to create machine (RAM allocation?)\n"); return 1; }
  std::string err;
  if (!m.load_file(load, path, &err)) { std::fprintf(stderr, "bbn-run: %s\n", err.c_str()); return 1; }
  m.cpu().reset(have_entry ? entry : load);

  const bbn::StopReason r = m.cpu().run(max_insns);
  std::fflush(stdout);
  int rc = 1;
  switch (r) {
    case bbn::StopReason::Halt: case bbn::StopReason::PowerOff: rc = 0; break;
    case bbn::StopReason::Reset: std::fprintf(stderr, "bbn-run: guest requested reset\n"); rc = 4; break;
    case bbn::StopReason::InsnLimit:
      std::fprintf(stderr, "bbn-run: instruction limit reached at pc=0x%llx\n", (unsigned long long)m.cpu().state().pc);
      rc = 2; break;
    case bbn::StopReason::Wfi:
      std::fprintf(stderr, "bbn-run: guest executed WFI with no interrupt source (pc=0x%llx)\n", (unsigned long long)m.cpu().state().pc);
      rc = 2; break;
    case bbn::StopReason::Unsupported:
      std::fprintf(stderr, "bbn-run: unsupported: %s (pc=0x%llx)\n", m.cpu().stop_message().c_str(), (unsigned long long)m.cpu().state().pc);
      rc = 3; break;
    default: break;
  }
  if (dump) {
    const auto& s = m.cpu().state();
    for (int i = 0; i < 31; ++i) std::fprintf(stderr, "x%-2d=%016llx%s", i, (unsigned long long)s.x[i], (i % 4 == 3) ? "\n" : " ");
    std::fprintf(stderr, "\npc=%016llx sp=%016llx el=%u nzcv=%c%c%c%c insns=%llu\n", (unsigned long long)s.pc,
                 (unsigned long long)m.cpu().sp(), s.el, s.n ? 'N' : '-', s.z ? 'Z' : '-', s.c ? 'C' : '-', s.v ? 'V' : '-',
                 (unsigned long long)m.cpu().instructions_retired());
    std::fprintf(stderr, "esr_el1=%016llx far_el1=%016llx elr_el1=%016llx spsr_el1=%016llx sctlr_el1=%016llx\n",
                 (unsigned long long)s.esr_el1, (unsigned long long)s.far_el1, (unsigned long long)s.elr_el1,
                 (unsigned long long)s.spsr_el1, (unsigned long long)s.sctlr_el1);
  }
  return rc;
}
