cmake_minimum_required(VERSION 3.10)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS True)
set(CMAKE_CXX_FLAGS "-march=native -maes -mrdseed -std=c++20${CMAKE_CXX_FLAGS}")
message(STATUS "CXX Flags: ${CMAKE_CXX_FLAGS}")

project(SealPIR)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
#include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-tool REQUIRED)
include_directories(${EMP-TOOL_INCLUDE_DIRS})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
add_subdirectory(src)

#enable_testing()
#add_subdirectory(test)
#add_subdirectory(test_ot)
