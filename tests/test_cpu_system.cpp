// Exceptions, exception levels, system registers and run-loop semantics.
#include "vector_runner.h"
#include "vectors_system.inc"

namespace {
constexpr uint64_t kCode = 0x40000000, kVbar = 0x40001000;

struct Rig {
  bbn::VirtConfig cfg;
  std::unique_ptr<bbn::VirtMachine> m;
  explicit Rig(bbn::VirtConfig c = {}) : cfg(std::move(c)) {
    cfg.ram_size = 1 << 20;
    m = std::make_unique<bbn::VirtMachine>(cfg);
  }
  void load(uint64_t addr, std::initializer_list<uint32_t> w) { std::vector<uint32_t> v(w); m->load_blob(addr, v.data(), v.size() * 4); }
  bbn::Cpu& cpu() { return m->cpu(); }
};
constexpr uint32_t NOP = 0xD503201F, HLT0 = 0xD4400000, WFI = 0xD503207F, B_SELF = 0x14000000;
}  // namespace

BBN_TEST(system_instruction_vectors) { run_all_vectors(kVectors); CHECK(kVectors.size() > 25); }

BBN_TEST(instruction_limit_is_reported) {
  Rig r; r.load(kCode, {B_SELF});
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(100) == bbn::StopReason::InsnLimit);
  CHECK_EQ(r.cpu().instructions_retired(), 100ull);
}

BBN_TEST(wfi_stops_unless_interrupt_pending) {
  Rig r; r.load(kCode, {WFI, NOP, HLT0});
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(10) == bbn::StopReason::Wfi);
  CHECK_EQ(r.cpu().state().pc, kCode + 4);       // resumes after the WFI
  CHECK(r.cpu().run(10) == bbn::StopReason::Halt);

  Rig r2; r2.load(kCode, {WFI, HLT0});
  r2.cpu().reset(kCode);
  r2.cpu().set_irq(true);                        // pending but masked (DAIF.I set at reset)
  CHECK(r2.cpu().run(10) == bbn::StopReason::Halt);  // WFI completes immediately
}

BBN_TEST(irq_is_taken_when_unmasked_with_correct_vector_and_return) {
  Rig r;
  // main: unmask IRQs, then spin. handler (EL1h IRQ vector = VBAR+0x280): record ELR, halt.
  r.load(kCode, {0xD2820009 /*movz x9,#0x1000*/, 0xF2A80009 /*movk x9,#0x4000,lsl #16*/, 0xD518C009 /*msr vbar_el1,x9*/,
                 0xD50342FF /*msr daifclr,#2*/, B_SELF});
  r.load(kVbar + 0x280, {0xD5384021 /*mrs x1,elr_el1*/, 0xD5384003 /*mrs x3,spsr_el1*/, HLT0});
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(20) == bbn::StopReason::InsnLimit);
  r.cpu().set_irq(true);
  CHECK(r.cpu().run(20) == bbn::StopReason::Halt);
  CHECK_EQ(r.cpu().state().x[1], kCode + 0x10);  // preferred return = the interrupted instruction
  CHECK_EQ(r.cpu().state().x[3] & 0x3FF, (0xDu << 6) | 5);  // SPSR: D,A,F masked, I clear; EL1h
}

BBN_TEST(fiq_has_priority_and_uses_its_own_vector) {
  Rig r;
  r.load(kCode, {0xD2820009, 0xF2A80009, 0xD518C009, 0xD50343FF /*msr daifclr,#3*/, B_SELF});
  r.load(kVbar + 0x300, {HLT0});  // FIQ vector (EL1h) = 0x200 + 0x100
  r.load(kVbar + 0x280, {0xD4400020 /*hlt #1*/});
  r.cpu().reset(kCode);
  r.cpu().run(10);
  r.cpu().set_irq(true); r.cpu().set_fiq(true);
  CHECK(r.cpu().run(10) == bbn::StopReason::Halt);
  CHECK_EQ(r.cpu().halt_imm(), 0u);              // reached the FIQ handler, not the IRQ one
}

BBN_TEST(hypercall_handler_can_service_hvc_and_smc) {
  Rig r;
  r.load(kCode, {0xD4000002 /*hvc #0*/, 0xD4000003 /*smc #0*/, 0xD2800541 /*mov x1,#42*/, HLT0});
  int calls = 0; bool saw_smc = false;
  r.cpu().set_hypercall_handler([&](bbn::Cpu& c, bool smc, uint16_t) { ++calls; saw_smc |= smc; c.state().x[0] = 0x1234; return true; });
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(10) == bbn::StopReason::Halt);
  CHECK_EQ(calls, 2); CHECK(saw_smc); CHECK_EQ(r.cpu().state().x[0], 0x1234ull); CHECK_EQ(r.cpu().state().x[1], 42ull);
}

BBN_TEST(hlt_is_undefined_when_not_configured_as_stop) {
  bbn::VirtConfig cfg; cfg.cpu.hlt_is_stop = false;
  Rig r(cfg);
  r.load(kCode, {HLT0});
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(1) == bbn::StopReason::InsnLimit);
  CHECK_EQ(r.cpu().state().esr_el1 >> 26, 0ull);
}

BBN_TEST(big_endian_request_is_reported_and_not_retained_but_mmu_enable_is) {
  Rig r;
  r.load(kCode, {0xD2A04000 /*movz x0,#0x200,lsl #16 (EE)*/, 0xD5181000 /*msr sctlr_el1,x0*/, 0xD5381001 /*mrs x1,sctlr_el1*/, HLT0});
  r.cpu().reset(kCode);
  CHECK(r.cpu().run(10) == bbn::StopReason::Unsupported);
  CHECK(r.cpu().stop_message().find("big-endian") != std::string::npos);
  CHECK_EQ(r.cpu().state().sctlr_el1 & (1ull << 25), 0ull);   // EE is not retained

  // Enabling the MMU is supported now: M is retained and execution continues (identity-mapped
  // by an empty-table fault would be fatal, so only check the register, not execution).
  Rig r2;
  r2.cpu().reset(kCode);
  r2.cpu().state().x[0] = 0x30D00801;
  r2.load(kCode, {0xD5181000 /*msr sctlr_el1,x0*/});
  r2.cpu().step();
  CHECK_EQ(r2.cpu().state().sctlr_el1 & 1, 1ull);
}

BBN_TEST(counter_source_and_frequency_are_configurable) {
  bbn::VirtConfig cfg; cfg.cpu.cntfrq = 1000000;
  Rig r(cfg);
  r.load(kCode, {0xD53BE040 /*mrs x0,cntvct_el0*/, 0xD53BE001 /*mrs x1,cntfrq_el0*/, HLT0});
  r.cpu().set_counter_source([] { return uint64_t{0xABCDEF}; });
  r.cpu().reset(kCode);
  r.cpu().run(10);
  CHECK_EQ(r.cpu().state().x[0], 0xABCDEFull); CHECK_EQ(r.cpu().state().x[1], 1000000ull);
}

BBN_TEST(el0_counter_access_gated_by_cntkctl) {
  Rig r;
  // EL0 code at 0x40000100 reads CNTVCT; handler (lower-EL sync, VBAR+0x400) records ESR.
  r.load(kCode, {0xD2820009, 0xF2A80009, 0xD518C009,
                 0xD2802001 /*mov x1,#0x100*/, 0xF2A80001 /*movk x1,#0x4000,lsl #16*/, 0xD5184021 /*msr elr_el1,x1*/,
                 0xD518401F /*msr spsr_el1,xzr*/, 0xD69F03E0 /*eret*/});
  r.load(kCode + 0x100, {0xD53BE042 /*mrs x2,cntvct_el0*/, HLT0});
  r.load(kVbar + 0x400, {0xD5385203 /*mrs x3,esr_el1*/, 0xD4400020});
  r.cpu().reset(kCode);
  r.cpu().run(50);
  CHECK_EQ(r.cpu().state().x[3] >> 26, 0ull);    // trapped: CNTKCTL_EL1.EL0VCTEN is clear

  Rig r2;
  r2.load(kCode, {0xD2820009, 0xF2A80009, 0xD518C009, 0xD2800041 /*mov x1,#2*/, 0xD518E101 /*msr cntkctl_el1,x1*/,
                  0xD2802001, 0xF2A80001, 0xD5184021, 0xD518401F, 0xD69F03E0});
  r2.load(kCode + 0x100, {0xD53BE042, HLT0});
  r2.cpu().reset(kCode);
  CHECK(r2.cpu().run(50) == bbn::StopReason::Halt);
  CHECK_EQ(r2.cpu().state().el, 0);
}

BBN_TEST(trace_hook_sees_every_instruction) {
  Rig r; r.load(kCode, {NOP, NOP, HLT0});
  std::vector<uint64_t> pcs;
  r.cpu().set_trace_hook([&](uint64_t pc, uint32_t) { pcs.push_back(pc); });
  r.cpu().reset(kCode); r.cpu().run(10);
  CHECK(pcs.size() == 3 && pcs[2] == kCode + 8);
}

BBN_TEST_MAIN()
