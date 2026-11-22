// Small bit-manipulation helpers shared by the CPU core and device models.
#pragma once

#include <bit>
#include <cstdint>

namespace bbn {

static_assert(std::endian::native == std::endian::little,
              "bareboxn assumes a little-endian host (all Android ABIs are)");

// Extract instruction/register bit-field [hi:lo] (inclusive). Width must be < 32.
constexpr uint32_t bits(uint32_t v, unsigned hi, unsigned lo) {
  return (v >> lo) & ((1u << (hi - lo + 1)) - 1u);
}
constexpr bool bit(uint32_t v, unsigned i) { return (v >> i) & 1u; }

// Sign-extend the low `width` bits of v to 64 bits.
constexpr int64_t sext(uint64_t v, unsigned width) {
  return static_cast<int64_t>(v << (64 - width)) >> (64 - width);
}

constexpr uint64_t mask_n(unsigned n) { return n >= 64 ? ~0ull : ((1ull << n) - 1ull); }

constexpr uint64_t ror(uint64_t v, unsigned amt, unsigned width) {
  amt %= width;
  v &= mask_n(width);
  if (amt == 0) return v;
  return ((v >> amt) | (v << (width - amt))) & mask_n(width);
}

}  // namespace bbn
