cmake_minimum_required(VERSION 3.0)

project(ZeekPluginsf)

include(ZeekPlugin)

find_package(PkgConfig REQUIRED)
find_package(KernelHeaders REQUIRED)
find_package(LibBPF REQUIRED)

find_program(CLANG_COMPILER clang)
find_program(LLVM_COMPILER llc)

add_custom_command(OUTPUT filter.o COMMAND ${CLANG_COMPILER} -target bpf -O2 -c "${CMAKE_CURRENT_SOURCE_DIR}/src/filter.c" -o filter.o)
add_custom_target(filter ALL DEPENDS filter.o)

zeek_plugin_begin(MalakhatkoVadym sf)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/SF_Ring.cc)
zeek_plugin_cc(src/SocketFilter.cc)
zeek_plugin_bif(src/sf.bif)
zeek_plugin_dist_files(README.md CHANGES COPYING COPYING.GPL VERSION filter.o)
zeek_plugin_link_library(bpf elf)
list(APPEND _plugin_deps filter)
zeek_plugin_end()

include_directories(${KERNELHEADERS_ROOT_DIR})

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
