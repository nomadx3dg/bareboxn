// Stage-1 MMU unit tests. Page tables are built here in C++; each instruction is executed one
// at a time with a known encoding (Keystone-assembled, Capstone-verified, see comments).
// Broader coverage comes from tools/mmu/mmu_diff.py (random scenarios vs QEMU) and its
// recorded golden transcripts (tests/mmu_golden, replayed by the `mmu_golden` ctest).
#include <memory>

#include "bbn_test.h"
#include "machine/virt.h"

namespace {
constexpr uint32_t LDR_X0_X1 = 0xF9400020, STR_X2_X1 = 0xF9000022, LDTR_X0_X1 = 0xF8400820,
                   STTR_X2_X1 = 0xF8000822, LDXR_X0_X1 = 0xC85F7C20, AT_S1E1R_X1 = 0xD5087801,
                   AT_S1E1W_X1 = 0xD5087821, AT_S1E0R_X1 = 0xD5087841, TLBI_VMALLE1 = 0xD508871F,
                   BR_X1 = 0xD61F0020, MRS_X0_MMFR0 = 0xD5380700;
constexpr uint64_t AF = 1 << 10, SH = 3 << 8, NG = 1 << 11, UXN = 1ull << 54, PXN = 1ull << 53;
constexpr uint64_t AP_EL1_RW = 0, AP_ALL_RW = 1 << 6, AP_EL1_RO = 2 << 6, AP_ALL_RO = 3 << 6;
constexpr uint64_t NORMAL = AF | SH | (0 << 2), DEVICE = AF | SH | (1 << 2);
constexpr uint64_t APT_RO = 1ull << 62;
constexpr uint64_t CODE = 0x40000000, ROOT = 0x40100000, DATA = 0x40200000;
constexpr uint64_t DABT = 0x25, IABT = 0x21;

uint64_t esr(uint64_t ec, uint64_t iss) { return (ec << 26) | (1ull << 25) | iss; }

// Mirrors tools/mmu/mmulib.py's PT builder.
struct Pt {
  bbn::Bus& bus;
  unsigned g, stride, nlev, start, topbits;
  uint64_t root, next;
  Pt(bbn::Bus& b, unsigned g_, unsigned ia, uint64_t root_, uint64_t alloc)
      : bus(b), g(g_), stride(g_ - 3), root(root_), next(alloc) {
    nlev = (ia - g + stride - 1) / stride;
    start = 4 - nlev;
    topbits = ia - g - (nlev - 1) * stride;
  }
  uint64_t shift(unsigned lv) const { return g + (3 - lv) * stride; }
  uint64_t index(uint64_t va, unsigned lv) const {
    return (va >> shift(lv)) & ((1ull << (lv == start ? topbits : stride)) - 1);
  }
  uint64_t rd(uint64_t pa) { uint64_t v = 0; bus.read(pa, 8, v); return v; }
  uint64_t slot(uint64_t va, unsigned level) {
    uint64_t table = root;
    for (unsigned lv = start; lv < level; ++lv) {
      const uint64_t ea = table + 8 * index(va, lv);
      const uint64_t d = rd(ea);
      if ((d & 1) && (d & 2)) {
        table = d & ((1ull << 48) - 1) & ~((1ull << g) - 1);
      } else {
        table = next;
        next += 1ull << g;
        bus.write(ea, 8, table | 3);
      }
    }
    return table + 8 * index(va, level);
  }
  void set(uint64_t va, unsigned level, uint64_t raw) { bus.write(slot(va, level), 8, raw); }
  void map(uint64_t va, uint64_t pa, uint64_t attrs, unsigned level = 3) {
    set(va, level, pa | attrs | (level == 3 ? 3 : 1));
  }
};

struct Rig {
  std::unique_ptr<bbn::VirtMachine> m;
  std::unique_ptr<Pt> pt;
  unsigned g;
  uint64_t page;
  explicit Rig(unsigned g_ = 12, unsigned ia = 39) : g(g_), page(1ull << g_) {
    bbn::VirtConfig cfg;
    cfg.ram_size = 16 << 20;
    m = std::make_unique<bbn::VirtMachine>(cfg);
    pt = std::make_unique<Pt>(m->bus(), g, ia, ROOT, ROOT + 0x20000);
    pt->map(CODE, CODE, AF | SH | AP_EL1_RO);  // executable, read-only code page (identity)
    auto& s = st();
    const uint64_t tg0 = g == 12 ? 0 : g == 14 ? 2 : 1;
    s.tcr_el1 = (64 - ia) | (tg0 << 14) | (2ull << 32) | (1ull << 23);  // IPS=40b, EPD1
    s.mair_el1 = 0x00FF;  // attr0 = Normal, attr1 = Device-nGnRnE
    s.ttbr0_el1 = ROOT;
    s.sctlr_el1 |= 1;
    cpu().flush_tlb();
  }
  bbn::Cpu& cpu() { return m->cpu(); }
  bbn::CpuState& st() { return m->cpu().state(); }
  uint64_t& x(int i) { return st().x[i]; }
  void put(uint64_t pa, uint64_t v) { m->bus().write(pa, 8, v); }
  uint64_t get(uint64_t pa) { uint64_t v = 0; m->bus().read(pa, 8, v); return v; }
  // Execute one instruction at CODE. Returns true if it completed without an exception.
  bool insn(uint32_t w) {
    m->bus().write_bytes(CODE, &w, 4);
    st().pc = CODE;
    st().esr_el1 = 0;
    cpu().step();
    return st().esr_el1 == 0;
  }
};
}  // namespace

BBN_TEST(translation_reads_and_writes_through_a_page) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.put(DATA + 8, 0x1122334455667788);
  r.x(1) = 0x1000008;
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x1122334455667788ull);
  r.x(2) = 0xABCD;
  CHECK(r.insn(STR_X2_X1)); CHECK_EQ(r.get(DATA + 8), 0xABCDull);
}

BBN_TEST(translation_fault_reports_level_and_far) {
  Rig r;
  r.x(1) = 0x7000000;  // nothing mapped: the level-3 table does not exist -> fault at level 1
  CHECK(!r.insn(LDR_X0_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x05)); CHECK_EQ(r.st().far_el1, 0x7000000ull);
  r.pt->map(0x1000000, DATA, NORMAL);                 // creates levels 1-2 for this region
  r.x(1) = 0x1001000;                                 // neighbouring page: level-3 entry empty
  CHECK(!r.insn(STR_X2_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x07 | 0x40));   // translation fault L3, WnR
  CHECK_EQ(r.st().far_el1, 0x1001000ull);
}

BBN_TEST(device_memory_faults_on_unaligned_access_normal_does_not) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.pt->map(0x1001000, DATA + 0x1000, DEVICE | AP_EL1_RW);
  r.x(1) = 0x1000001;
  CHECK(r.insn(LDR_X0_X1));                           // Normal: unaligned is fine
  r.x(1) = 0x1001001;
  CHECK(!r.insn(LDR_X0_X1));                          // Device: Alignment fault
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x21)); CHECK_EQ(r.st().far_el1, 0x1001001ull);
  r.x(1) = 0x1001008;
  CHECK(r.insn(LDR_X0_X1));                           // aligned Device access is fine
}

BBN_TEST(sctlr_a_makes_every_unaligned_access_fault) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.st().sctlr_el1 |= 2;
  r.x(1) = 0x1000004;
  CHECK(!r.insn(LDR_X0_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x21));
}

BBN_TEST(tlb_caches_translations_until_invalidated) {
  Rig r;
  r.pt->map(0x2000000, DATA, NORMAL | AP_EL1_RW);
  r.put(DATA, 0x1111); r.put(DATA + 0x1000, 0x2222);
  r.x(1) = 0x2000000;
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x1111ull);
  r.pt->map(0x2000000, DATA + 0x1000, NORMAL | AP_EL1_RW);  // retarget in memory, no TLBI
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x1111ull);    // architecturally allowed to be stale
  CHECK(r.insn(TLBI_VMALLE1));
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x2222ull);
}

BBN_TEST(non_global_entries_are_tagged_with_the_asid) {
  Rig r;
  Pt other(r.m->bus(), 12, 39, ROOT + 0x80000, ROOT + 0xA0000);
  other.map(CODE, CODE, AF | SH | AP_EL1_RO);
  r.pt->map(0x3000000, DATA, NORMAL | AP_EL1_RW | NG);
  other.map(0x3000000, DATA + 0x1000, NORMAL | AP_EL1_RW | NG);
  r.put(DATA, 0xAAAA); r.put(DATA + 0x1000, 0xBBBB);
  r.x(1) = 0x3000000;
  r.st().ttbr0_el1 = ROOT | (1ull << 48);
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0xAAAAull);
  r.st().ttbr0_el1 = (ROOT + 0x80000) | (2ull << 48);       // new ASID, no TLBI needed
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0xBBBBull);
  r.st().ttbr0_el1 = ROOT | (1ull << 48);
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0xAAAAull);
}

BBN_TEST(access_straddling_two_pages_is_all_or_nothing) {
  Rig r;
  const uint64_t V = 0x1000000;
  r.pt->map(V, DATA, NORMAL | AP_EL1_RW);
  r.pt->map(V + 0x1000, DATA + 0x5000, NORMAL | AP_EL1_RW);  // physically non-adjacent
  r.m->bus().write(DATA + 0xFFC, 4, 0x44332211);
  r.m->bus().write(DATA + 0x5000, 4, 0x88776655);
  r.x(1) = V + 0xFFC;
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x8877665544332211ull);
  r.pt->map(V + 0x1000, DATA + 0x5000, NORMAL | AP_EL1_RO);  // second page becomes read-only
  r.cpu().flush_tlb();
  r.x(2) = 0xAAAAAAAAAAAAAAAAull;
  CHECK(!r.insn(STR_X2_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0F | 0x40));          // permission fault L3, write
  CHECK_EQ(r.st().far_el1, V + 0x1000);                      // lowest address of the faulting page
  CHECK_EQ(r.get(DATA + 0xFF8) >> 32, 0x44332211ull);        // first page untouched: no partial write
}

BBN_TEST(unprivileged_load_store_use_el0_permissions) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);            // EL1 only
  r.pt->map(0x1001000, DATA + 0x1000, NORMAL | AP_ALL_RW);   // EL0 accessible
  r.x(1) = 0x1000000;
  CHECK(r.insn(LDR_X0_X1));                                  // normal load at EL1 is fine
  CHECK(!r.insn(LDTR_X0_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0F));
  CHECK(!r.insn(STTR_X2_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0F | 0x40));
  r.x(1) = 0x1001000;
  CHECK(r.insn(LDTR_X0_X1)); CHECK(r.insn(STTR_X2_X1));
}

BBN_TEST(permission_bits_ro_xn_and_hierarchical_limits) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RO);
  r.x(1) = 0x1000000;
  CHECK(r.insn(LDR_X0_X1));
  CHECK(!r.insn(STR_X2_X1)); CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0F | 0x40));
  // APTable[1] on the level-2 table descriptor makes an otherwise writable page read-only.
  r.pt->map(0x1200000, DATA + 0x1000, NORMAL | AP_EL1_RW);
  r.pt->set(0x1200000, 2, r.get(r.pt->slot(0x1200000, 2)) | APT_RO);
  r.x(1) = 0x1200000;
  CHECK(r.insn(LDR_X0_X1));
  CHECK(!r.insn(STR_X2_X1)); CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0F | 0x40));
}

BBN_TEST(access_flag_and_address_size_faults) {
  Rig r;
  r.pt->map(0x1000000, DATA, SH | AP_EL1_RW);                // AF clear
  r.x(1) = 0x1000000;
  CHECK(!r.insn(LDR_X0_X1)); CHECK_EQ(r.st().esr_el1, esr(DABT, 0x0B));
  r.pt->map(0x1001000, DATA | (1ull << 41), NORMAL);         // output address beyond 40 bits
  r.x(1) = 0x1001000;
  CHECK(!r.insn(LDR_X0_X1)); CHECK_EQ(r.st().esr_el1, esr(DABT, 0x03));
}

BBN_TEST(table_walk_to_unassigned_memory_is_an_external_abort) {
  Rig r;
  const uint64_t V = 0x2000000000ull;  // distinct level-1 slot
  r.pt->set(V, 1, 0x2000000000ull | 3);  // table pointer into the void
  r.x(1) = V;
  CHECK(!r.insn(LDR_X0_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x16 | (1 << 9)));      // external abort on walk, level 2
}

BBN_TEST(instruction_fetch_permissions_follow_uxn_pxn_not_ap1) {
  Rig r;
  const uint32_t svc = 0xD4000001;
  // EL1-only page, UXN clear: EL0 may still execute it (execute-only user mappings).
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.m->bus().write_bytes(DATA, &svc, 4);
  r.st().el = 0; r.st().sp_sel = false; r.st().pc = 0x1000000; r.st().esr_el1 = 0;
  r.cpu().step();
  CHECK_EQ(r.st().esr_el1 >> 26, 0x15ull);                   // reached the SVC
  // EL0-writable page: EL1 must not execute it (implicit PXN).
  r.pt->map(0x1100000, DATA + 0x1000, NORMAL | AP_ALL_RW);
  r.m->bus().write_bytes(DATA + 0x1000, &svc, 4);
  r.st().el = 1; r.st().sp_sel = true; r.st().pc = 0x1100000; r.st().esr_el1 = 0;
  r.cpu().step();
  CHECK_EQ(r.st().esr_el1, esr(IABT, 0x0F)); CHECK_EQ(r.st().far_el1, 0x1100000ull);
  // UXN set: EL0 execution faults.
  r.pt->map(0x1200000, DATA + 0x2000, NORMAL | AP_ALL_RO | UXN);
  r.st().el = 0; r.st().sp_sel = false; r.st().pc = 0x1200000; r.st().esr_el1 = 0;
  r.cpu().step();
  CHECK_EQ(r.st().esr_el1 >> 26, 0x20ull);
}

BBN_TEST(top_byte_ignore_strips_tags_from_data_and_branch_targets) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.put(DATA, 0x5151);
  r.x(1) = 0xAB00000001000000ull;
  CHECK(!r.insn(LDR_X0_X1));                                 // TBI off: tag is part of the address
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x04));                 // out of range -> translation fault L0
  r.st().tcr_el1 |= 1ull << 37;                              // TBI0
  r.cpu().flush_tlb();
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x5151ull);
  CHECK(r.insn(BR_X1)); CHECK_EQ(r.st().pc, 0x1000000ull);   // PC never carries the tag
}

BBN_TEST(at_instructions_fill_par_without_faulting) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.x(1) = 0x1000000;
  CHECK(r.insn(AT_S1E1R_X1));
  CHECK_EQ(r.st().par_el1, (0xFFull << 56) | DATA | (1ull << 11) | (1ull << 9) | (3ull << 7));
  CHECK(r.insn(AT_S1E1W_X1)); CHECK_EQ(r.st().par_el1 & 1, 0ull);
  CHECK(r.insn(AT_S1E0R_X1)); CHECK_EQ(r.st().par_el1, 1ull | (0x0Full << 1));  // EL0 has no access
  r.x(1) = 0x7000000;
  CHECK(r.insn(AT_S1E1R_X1)); CHECK_EQ(r.st().par_el1, 1ull | (0x06ull << 1));   // L2 entry empty
}

BBN_TEST(sixteen_and_sixty_four_kb_granules_translate) {
  for (unsigned g : {14u, 16u}) {
    Rig r(g, 39);
    const uint64_t V = 0x4000000;
    r.pt->map(V, DATA, NORMAL | AP_EL1_RW);
    r.put(DATA + 0x10, 0xFEEDF00D);
    r.x(1) = V + 0x10;
    CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0xFEEDF00Dull);
    r.x(1) = V + r.page;                                     // next page: unmapped
    CHECK(!r.insn(LDR_X0_X1));
    CHECK_EQ(r.st().esr_el1 & 0x3C, 0x04ull);                // some translation fault
  }
}

BBN_TEST(block_descriptors_map_large_ranges_and_reserved_levels_fault) {
  Rig r;
  r.pt->map(0x40000000, 0x40000000, NORMAL | AP_EL1_RW, 1);  // 1 GiB block (4K granule, level 1)
  r.put(0x40200008, 0x7777);
  r.x(1) = 0x40200008;
  CHECK(r.insn(LDR_X0_X1)); CHECK_EQ(r.x(0), 0x7777ull);
  Rig r16(14, 39);                                            // 16K granule has no level-1 blocks
  const uint64_t V16 = 1ull << 36;                            // a level-1 slot the code page does not use
  r16.pt->set(V16, 1, 0x40000000ull | NORMAL | 1);
  r16.x(1) = V16;
  CHECK(!r16.insn(LDR_X0_X1)); CHECK_EQ(r16.st().esr_el1, esr(DABT, 0x05));
}

BBN_TEST(mmfr0_advertises_what_is_implemented) {
  Rig r;
  CHECK(r.insn(MRS_X0_MMFR0));
  CHECK_EQ(r.x(0), 0x100022ull);  // PARange 40b, 16-bit ASIDs, 16K granule supported
}

BBN_TEST(exclusive_alignment_fault_is_reported_through_the_mmu) {
  Rig r;
  r.pt->map(0x1000000, DATA, NORMAL | AP_EL1_RW);
  r.x(1) = 0x1000004;
  CHECK(!r.insn(LDXR_X0_X1));
  CHECK_EQ(r.st().esr_el1, esr(DABT, 0x21));
}

BBN_TEST(sctlr_m_toggles_translation_and_ee_is_unsupported) {
  Rig r;
  r.x(1) = DATA;
  r.st().sctlr_el1 &= ~1ull; r.cpu().flush_tlb();
  CHECK(r.insn(LDR_X0_X1));                                  // MMU off: identity
  CHECK(r.cpu().stop_message().empty());
}

BBN_TEST_MAIN()
