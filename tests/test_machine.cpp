// End-to-end: a bare-metal program prints through the PL011 on a bbn-virt machine.
#include <cstdio>
#include <fstream>
#include <string>

#include "bbn_test.h"
#include "machine/virt.h"

namespace {
}  // namespace

BBN_TEST(machine_memory_map_and_reset_state) {
  bbn::VirtConfig cfg; cfg.ram_size = 16 << 20;
  bbn::VirtMachine m(cfg);
  CHECK(m.ok());
  auto regions = m.bus().regions();
  CHECK_EQ(regions.size(), 2u);
  CHECK_EQ(regions[0].base, 0x09000000ull); CHECK(!regions[0].is_ram);
  CHECK_EQ(regions[1].base, 0x40000000ull); CHECK(regions[1].is_ram);
  m.cpu().reset(0x40000000);
  CHECK_EQ(m.cpu().state().el, 1); CHECK_EQ(m.cpu().state().daif, 0xF);
}

BBN_TEST(load_file_and_bounds) {
  bbn::VirtConfig cfg; cfg.ram_size = 1 << 20;
  bbn::VirtMachine m(cfg);
  const char* path = "bbn_test_blob.bin";
  { std::ofstream f(path, std::ios::binary); f << "abcd"; }
  std::string err;
  CHECK(m.load_file(0x40000000, path, &err));
  uint32_t w = 0; m.bus().read_bytes(0x40000000, &w, 4); CHECK_EQ(w, 0x64636261u);
  CHECK(!m.load_file(0x40000000 + (1 << 20) - 2, path, &err));   // does not fit
  CHECK(err.find("does not fit") != std::string::npos);
  CHECK(!m.load_file(0x40000000, "/nonexistent/file.bin", &err));
  std::remove(path);
}

BBN_TEST(guest_program_prints_via_pl011) {
  std::string out;
  bbn::VirtConfig cfg; cfg.ram_size = 1 << 20;
  cfg.uart_sink = [&](uint8_t b) { out.push_back(char(b)); };
  bbn::VirtMachine m(cfg);
  static const uint32_t prog[] = {
#include "hello_program.inc"
  };
  const char msg[] = "hello, bareboxn\n";
  m.load_blob(0x40000000, prog, sizeof(prog));
  m.load_blob(0x40010000, msg, sizeof(msg));
  m.cpu().reset(0x40000000);
  CHECK(m.cpu().run(10000) == bbn::StopReason::Halt);
  CHECK(out == "hello, bareboxn\n");
}

BBN_TEST(guest_can_poll_uart_flag_register_and_receive_input) {
  std::string out;
  bbn::VirtConfig cfg; cfg.ram_size = 1 << 20;
  cfg.uart_sink = [&](uint8_t b) { out.push_back(char(b)); };
  bbn::VirtMachine m(cfg);
  m.uart().push_rx('Q');
  // movz x2,#0x0900,lsl#16 ; ldr w0,[x2,#0x18] (FR) ; ldr w1,[x2] (DR) ; strb w1,[x2] (echo) ; hlt
  static const uint32_t prog[] = {
#include "echo_program.inc"
  };
  m.load_blob(0x40000000, prog, sizeof(prog));
  m.cpu().reset(0x40000000);
  CHECK(m.cpu().run(100) == bbn::StopReason::Halt);
  CHECK_EQ(m.cpu().state().x[0] & 0x10, 0ull);   // RXFE was clear when read
  CHECK_EQ(m.cpu().state().x[1], uint64_t('Q'));
  CHECK(out == "Q");
}

BBN_TEST_MAIN()
