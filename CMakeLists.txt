cmake_minimum_required(VERSION 3.16)
project(bareboxn VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(BBN_BUILD_TESTS "Build unit and program tests" ON)
option(BBN_BUILD_TOOLS "Build command-line tools" ON)
option(BBN_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

add_library(bbn_core STATIC
  src/memory/bus.cpp
  src/devices/pl011.cpp
  src/cpu/cpu.cpp
  src/cpu/sysregs.cpp
  src/cpu/exec_branch.cpp
  src/cpu/exec_dp.cpp
  src/cpu/exec_ldst.cpp
  src/machine/virt.cpp
)
target_include_directories(bbn_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(bbn_core PRIVATE -Wall -Wextra -Wshadow -Wconversion-null)
if(BBN_WARNINGS_AS_ERRORS)
  target_compile_options(bbn_core PRIVATE -Werror)
endif()

if(BBN_BUILD_TOOLS)
  add_executable(bbn-run tools/bbn-run.cpp)
  target_link_libraries(bbn-run PRIVATE bbn_core)
  add_executable(bbn-difftest tools/difftest/bbn-difftest.cpp)
  target_link_libraries(bbn-difftest PRIVATE bbn_core)
endif()

if(BBN_BUILD_TESTS)
  enable_testing()
  foreach(t bus pl011 cpu_vectors cpu_system machine)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE bbn_core)
    target_include_directories(test_${t} PRIVATE tests)
    add_test(NAME ${t} COMMAND test_${t})
  endforeach()
endif()
