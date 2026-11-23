#include "machine/virt.h"
#include "machine/psci.h"

#include <fstream>
#include <iterator>

namespace bbn {

VirtMachine::VirtMachine(VirtConfig cfg)
    : cfg_(std::move(cfg)), uart_(cfg_.uart_sink), cpu_(bus_, cfg_.cpu) {
  ok_ = bus_.add_ram(VirtMemMap::kRamBase, cfg_.ram_size, "ram") &&
        bus_.add_mmio(VirtMemMap::kUartBase, Pl011::kRegionSize, &uart_, "pl011");
  if (cfg_.enable_psci) cpu_.set_hypercall_handler(Psci::handle);
  cpu_.set_irq(false);
  uart_.set_irq_callback([](bool) {});  // interrupt controller arrives with the GIC
}

bool VirtMachine::load_blob(uint64_t addr, const void* data, size_t len) {
  return bus_.write_bytes(addr, data, len);
}

bool VirtMachine::load_file(uint64_t addr, const std::string& path, std::string* error) {
  std::ifstream f(path, std::ios::binary);
  if (!f) {
    if (error) *error = "cannot open " + path;
    return false;
  }
  std::vector<char> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  if (!load_blob(addr, buf.data(), buf.size())) {
    if (error) *error = path + " does not fit in guest RAM at the requested address";
    return false;
  }
  return true;
}

}  // namespace bbn
