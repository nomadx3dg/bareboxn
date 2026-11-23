#include "bbn_test.h"
#include "machine/virt.h"

namespace {
constexpr uint32_t HVC_0 = 0xD4000002, SMC_0 = 0xD4000003;
constexpr uint64_t CODE = 0x40000000;
struct Rig {
  std::unique_ptr<bbn::VirtMachine> m;
  explicit Rig(bool psci = true) {
    bbn::VirtConfig cfg; cfg.ram_size = 1 << 20; cfg.enable_psci = psci;
    m = std::make_unique<bbn::VirtMachine>(cfg);
    m->cpu().reset(CODE);
  }
  bbn::StopReason call(uint32_t insn, uint64_t fn, uint64_t a1 = 0) {
    m->bus().write_bytes(CODE, &insn, 4);
    auto& s = m->cpu().state();
    s.pc = CODE; s.x[0] = fn; s.x[1] = a1; s.esr_el1 = 0;
    return m->cpu().step();
  }
  int64_t ret() { return static_cast<int64_t>(m->cpu().state().x[0]); }
};
}  // namespace

BBN_TEST(version_features_and_migrate_info) {
  Rig r;
  CHECK(r.call(HVC_0, 0x84000000) == bbn::StopReason::None); CHECK_EQ(r.ret(), 0x10000ll);
  r.call(SMC_0, 0x84000000);                                   // SMC conduit works too
  CHECK_EQ(r.ret(), 0x10000ll);
  r.call(HVC_0, 0x8400000A, 0x84000008); CHECK_EQ(r.ret(), 0ll);   // FEATURES(SYSTEM_OFF)
  r.call(HVC_0, 0x8400000A, 0x84000001); CHECK_EQ(r.ret(), -1ll);  // CPU_SUSPEND unsupported
  r.call(HVC_0, 0x84000006); CHECK_EQ(r.ret(), 2ll);
  r.call(HVC_0, 0xC4000003, 0x80000000); CHECK(true);
}

BBN_TEST(system_off_and_reset_stop_the_cpu) {
  Rig r;
  CHECK(r.call(HVC_0, 0x84000008) == bbn::StopReason::PowerOff);
  CHECK(r.call(HVC_0, 0x84000009) == bbn::StopReason::Reset);
  CHECK(r.call(HVC_0, 0xC4000008) == bbn::StopReason::PowerOff);  // SMC64 encoding of the same call
}

BBN_TEST(single_cpu_semantics_for_cpu_on_and_affinity_info) {
  Rig r;
  r.call(HVC_0, 0xC4000003, 0);  CHECK_EQ(r.ret(), -4ll);       // ALREADY_ON
  r.call(HVC_0, 0xC4000003, 1);  CHECK_EQ(r.ret(), -2ll);       // INVALID_PARAMETERS
  r.call(HVC_0, 0xC4000004, 0);  CHECK_EQ(r.ret(), 0ll);        // ON
  r.call(HVC_0, 0xC4000004, 5);  CHECK_EQ(r.ret(), -2ll);
}

BBN_TEST(unknown_psci_functions_return_not_supported_other_ids_are_undefined) {
  Rig r;
  r.call(HVC_0, 0x840000FF); CHECK_EQ(r.ret(), -1ll);
  r.call(HVC_0, 0x1234);                                        // not a PSCI function id
  CHECK_EQ(r.m->cpu().state().esr_el1 >> 26, 0ull);             // UNDEFINED
}

BBN_TEST(hvc_is_undefined_without_a_psci_conduit) {
  Rig r(false);
  r.call(HVC_0, 0x84000000);
  CHECK_EQ(r.m->cpu().state().esr_el1 >> 26, 0ull);
}

BBN_TEST_MAIN()
