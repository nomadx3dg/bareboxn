// Minimal Power State Coordination Interface (PSCI 1.0) for a single-CPU machine, serviced
// through the HVC/SMC hypercall hook. Implemented: VERSION, FEATURES, SYSTEM_OFF,
// SYSTEM_RESET, MIGRATE_INFO_TYPE, CPU_ON/AFFINITY_INFO (single CPU semantics).
// CPU_SUSPEND/CPU_OFF are reported NOT_SUPPORTED.
#pragma once

#include <cstdint>

#include "cpu/cpu.h"

namespace bbn {

struct Psci {
  static constexpr int64_t kNotSupported = -1, kInvalidParams = -2, kAlreadyOn = -4;
  // Returns true if the call was handled (every PSCI-range function ID is, even if unsupported).
  static bool handle(Cpu& cpu, bool is_smc, uint16_t imm);
};

}  // namespace bbn
