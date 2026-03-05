cmake_minimum_required(VERSION 3.20)
project(linux-mem-inspector LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG        v4.1.0
  GIT_SHALLOW    TRUE
)
set(ZYDIS_BUILD_TOOLS    OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zydis)

find_package(Threads REQUIRED)
add_compile_options(-mssse3)

add_subdirectory(shared)
add_subdirectory(inspector)
