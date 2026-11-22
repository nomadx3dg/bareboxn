// Minimal dependency-free test harness.
#pragma once
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace bbn_test {
struct Case { const char* name; std::function<void()> fn; };
inline std::vector<Case>& cases() { static std::vector<Case> c; return c; }
inline int& failures() { static int f = 0; return f; }
struct Reg { Reg(const char* n, std::function<void()> f) { cases().push_back({n, std::move(f)}); } };
inline int run_all() {
  int failed_cases = 0;
  for (auto& c : cases()) {
    int before = failures();
    c.fn();
    if (failures() != before) { ++failed_cases; std::fprintf(stderr, "FAIL  %s\n", c.name); }
  }
  std::printf("%zu test cases, %d failed\n", cases().size(), failed_cases);
  return failed_cases ? 1 : 0;
}
}  // namespace bbn_test

#define BBN_TEST(name) \
  static void name(); \
  static bbn_test::Reg reg_##name(#name, name); \
  static void name()

#define CHECK(cond) \
  do { if (!(cond)) { ++bbn_test::failures(); std::fprintf(stderr, "  %s:%d: CHECK(%s)\n", __FILE__, __LINE__, #cond); } } while (0)
#define CHECK_EQ(a, b) \
  do { auto va_ = (a); auto vb_ = (b); if (!(va_ == vb_)) { ++bbn_test::failures(); \
    std::fprintf(stderr, "  %s:%d: %s == %s  (got 0x%llx, want 0x%llx)\n", __FILE__, __LINE__, #a, #b, \
                 (unsigned long long)va_, (unsigned long long)vb_); } } while (0)

#define BBN_TEST_MAIN() int main() { return bbn_test::run_all(); }
