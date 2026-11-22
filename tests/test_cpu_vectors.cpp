// Instruction-level tests for the integer ISA subset (generated; cross-checked against Unicorn).
#include "vector_runner.h"
#include "vectors_basic.inc"

BBN_TEST(basic_instruction_vectors) { run_all_vectors(kVectors); CHECK(kVectors.size() > 100); }
BBN_TEST_MAIN()
