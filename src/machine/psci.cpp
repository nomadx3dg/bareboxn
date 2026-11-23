#include "machine/psci.h"

namespace bbn {
namespace {
constexpr uint32_t kFnMask = 0xFFFFFFFF;
// Function IDs: 0x84000000 + n (SMC32) and 0xC4000000 + n (SMC64).
constexpr uint32_t PSCI_VERSION = 0x84000000, CPU_SUSPEND = 0x84000001, CPU_OFF = 0x84000002,
                   CPU_ON = 0x84000003, AFFINITY_INFO = 0x84000004, MIGRATE_INFO_TYPE = 0x84000006,
                   SYSTEM_OFF = 0x84000008, SYSTEM_RESET = 0x84000009, PSCI_FEATURES = 0x8400000A;
uint32_t base32(uint32_t fn) { return fn & ~0x40000000u; }  // fold SMC64 IDs onto SMC32
uint64_t cpu_mpidr_aff(Cpu& cpu) { return cpu.mpidr() & 0xFFFFFF; }
}  // namespace

bool Psci::handle(Cpu& cpu, bool /*is_smc*/, uint16_t /*imm*/) {
  CpuState& s = cpu.state();
  const uint32_t fn = static_cast<uint32_t>(s.x[0] & kFnMask);
  if ((fn & 0xBFFF0000u) != 0x84000000u) return false;  // not in the PSCI function range
  auto ret = [&](int64_t v) { s.x[0] = static_cast<uint64_t>(v); return true; };
  const uint32_t id = base32(fn);
  switch (id) {
    case PSCI_VERSION: return ret(0x00010000);  // 1.0
    case SYSTEM_OFF:
      cpu.request_stop(StopReason::PowerOff);
      return ret(0);
    case SYSTEM_RESET:
      cpu.request_stop(StopReason::Reset);
      return ret(0);
    case MIGRATE_INFO_TYPE: return ret(2);  // Trusted OS not present / not migratable
    case PSCI_FEATURES: {
      const uint32_t q = base32(static_cast<uint32_t>(s.x[1]));
      switch (q) {
        case PSCI_VERSION: case PSCI_FEATURES: case SYSTEM_OFF: case SYSTEM_RESET:
        case MIGRATE_INFO_TYPE: case CPU_ON: case AFFINITY_INFO:
          return ret(0);
        default: return ret(kNotSupported);
      }
    }
    case CPU_ON:  // only CPU 0 exists and it is running
      return ret((s.x[1] & 0xFFFFFF) == cpu_mpidr_aff(cpu) ? kAlreadyOn : kInvalidParams);
    case AFFINITY_INFO:
      return ret((s.x[1] & 0xFFFFFF) == cpu_mpidr_aff(cpu) ? 0 : kInvalidParams);
    case CPU_SUSPEND: case CPU_OFF:
    default: return ret(kNotSupported);
  }
}

}  // namespace bbn
