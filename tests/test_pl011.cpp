#include <string>

#include "bbn_test.h"
#include "devices/pl011.h"

namespace {
uint32_t rd(bbn::Pl011& u, uint64_t off) { uint64_t v = 0; CHECK(u.read(off, 4, v)); return static_cast<uint32_t>(v); }
}

BBN_TEST(identification_registers_match_pl011) {
  bbn::Pl011 u;
  CHECK_EQ(rd(u, 0xFE0), 0x11u); CHECK_EQ(rd(u, 0xFE4), 0x10u); CHECK_EQ(rd(u, 0xFE8), 0x14u); CHECK_EQ(rd(u, 0xFEC), 0x00u);
  CHECK_EQ(rd(u, 0xFF0), 0x0Du); CHECK_EQ(rd(u, 0xFF4), 0xF0u); CHECK_EQ(rd(u, 0xFF8), 0x05u); CHECK_EQ(rd(u, 0xFFC), 0xB1u);
}

BBN_TEST(transmit_goes_to_sink_and_tx_fifo_reads_empty) {
  std::string out;
  bbn::Pl011 u([&](uint8_t b) { out.push_back(char(b)); });
  CHECK_EQ(rd(u, 0x18) & 0x80u, 0x80u);  // TXFE
  CHECK(u.write(0x0, 1, 'o')); CHECK(u.write(0x0, 4, 'k')); CHECK(u.write(0x0, 4, 0x1FF41));  // upper bits ignored
  CHECK(out == "okA");
}

BBN_TEST(receive_fifo_flags_ordering_and_overrun) {
  bbn::Pl011 u;
  CHECK_EQ(rd(u, 0x18) & 0x10u, 0x10u);  // RXFE
  for (size_t i = 0; i < bbn::Pl011::kFifoDepth; ++i) CHECK(u.push_rx(uint8_t('a' + i)));
  CHECK_EQ(rd(u, 0x18) & 0x40u, 0x40u);  // RXFF
  CHECK(!u.push_rx('!'));                // overrun: byte dropped
  CHECK_EQ(rd(u, 0x3C) & (1u << 10), 1u << 10);
  CHECK_EQ(rd(u, 0x0), uint32_t('a'));
  CHECK_EQ(rd(u, 0x0), uint32_t('b'));
  CHECK_EQ(rd(u, 0x18) & 0x40u, 0u);
  for (int i = 0; i < 14; ++i) rd(u, 0x0);
  CHECK_EQ(rd(u, 0x18) & 0x10u, 0x10u);
  CHECK_EQ(rd(u, 0x0), 0u);              // empty read returns 0
}

BBN_TEST(interrupt_mask_status_clear_and_callback) {
  bbn::Pl011 u; std::vector<bool> edges;
  u.set_irq_callback([&](bool l) { edges.push_back(l); });
  u.push_rx('x');
  CHECK(!u.irq_level());                 // masked
  CHECK_EQ(rd(u, 0x3C) & 0x10u, 0x10u);  // RIS.RXRIS
  CHECK_EQ(rd(u, 0x40), 0u);             // MIS
  CHECK(u.write(0x38, 4, 0x10));         // IMSC.RXIM
  CHECK(u.irq_level()); CHECK_EQ(rd(u, 0x40), 0x10u);
  CHECK_EQ(rd(u, 0x0), uint32_t('x'));   // draining the FIFO drops the level
  CHECK(!u.irq_level());
  u.write(0x0, 4, 'z');                  // TX raw interrupt is raised by a transmit
  CHECK_EQ(rd(u, 0x3C) & 0x20u, 0x20u);
  u.write(0x38, 4, 0x20); CHECK(u.irq_level());
  u.write(0x44, 4, 0x20); CHECK(!u.irq_level());  // ICR clears
  CHECK(edges.size() == 4 && edges[0] && !edges[1] && edges[2] && !edges[3]);
}

BBN_TEST(control_registers_store_and_reset_values) {
  bbn::Pl011 u;
  CHECK_EQ(rd(u, 0x30), 0x0300u); CHECK_EQ(rd(u, 0x34), 0x12u);
  u.write(0x24, 4, 0x1A); u.write(0x28, 4, 0x3F); u.write(0x2C, 4, 0x70); u.write(0x30, 4, 0x301);
  CHECK_EQ(rd(u, 0x24), 0x1Au); CHECK_EQ(rd(u, 0x28), 0x3Fu); CHECK_EQ(rd(u, 0x2C), 0x70u); CHECK_EQ(rd(u, 0x30), 0x301u);
  u.reset(); CHECK_EQ(rd(u, 0x30), 0x0300u);
}

BBN_TEST(access_width_rules) {
  bbn::Pl011 u; uint64_t v;
  CHECK(!u.read(0x18, 8, v));            // 64-bit access rejected
  CHECK(!u.write(0x0, 8, 0));
  CHECK(!u.read(0x1000, 4, v));          // beyond region
  CHECK(u.read(0xFE1, 1, v)); CHECK_EQ(v, 0u);     // byte 1 of PeriphID0 word
  CHECK(!u.read(0xFE3, 2, v));           // straddles a register
}

BBN_TEST_MAIN()
