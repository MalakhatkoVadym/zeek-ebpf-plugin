cmake_minimum_required(VERSION 3.0)

project(ZeekPluginaf_xdp)

include(ZeekPlugin)

find_package(PkgConfig REQUIRED)
find_package(KernelHeaders REQUIRED)
find_package(LibBPF REQUIRED)
# pkg_search_module(LIBBCC REQUIRED libbcc)

find_program(CLANG_COMPILER clang)
find_program(LLVM_COMPILER llc)

zeek_plugin_begin(irtimmer af_xdp)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/AF_XDP.cc)
zeek_plugin_bif(src/af_xdp.bif)
zeek_plugin_dist_files(README.md CHANGES COPYING COPYING.GPL VERSION af_xdp_bpf.o)

zeek_plugin_link_library(bpf elf)
# list(APPEND _plugin_deps af_xdp_bpf)
zeek_plugin_end()

include_directories(${KERNELHEADERS_ROOT_DIR})

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
