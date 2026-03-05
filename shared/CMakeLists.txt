cmake_minimum_required(VERSION 3.20)

add_library(shared STATIC
  src/memory/memory_reader.cpp
  src/memory/memory_map.cpp
  src/memory/mem_helpers.cpp
  src/process/process_finder.cpp
  src/scanner/pattern_scanner.cpp
)
target_compile_options(shared PRIVATE -mssse3)
target_include_directories(shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(shared PUBLIC Zydis)
