# Create a library called "core" which includes the source file "dpdk.cc".
# The extension is already found. Any number of sources could be listed here.
file(GLOB_RECURSE SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.cc)
list(FILTER SRC_FILES EXCLUDE REGEX "^.*_test\\.(cc|h)$")

add_library (core STATIC ${SRC_FILES})

set_target_properties(core PROPERTIES
           VERSION ${PROJECT_VERSION}
           SOVERSION 1
           PUBLIC_HEADER dpdk.h)

find_package(nlohmann_json REQUIRED)

target_include_directories(core PUBLIC ../include)
target_include_directories(core PRIVATE .)
target_link_libraries(core PRIVATE)
target_link_libraries(core PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(core PUBLIC PkgConfig::LIBDPDK_STATIC)

# link_directories($ENV{RTE_SDK}/$ENV{RTE_TARGET}/lib/)
# find_library(DPDK_LIB NAMES libdpdk.a dpdk)
# target_link_libraries(core PRIVATE dpdk numa dl)
# target_link_libraries(core PRIVATE -Wl,--whole-archive dpdk -Wl,--no-whole-archive numa dl ${IBVERBS} ${LIBMLX4} ${LIBMLX5})

# --- vendored libbpf (EPS-backed channel) ---
# The vendored UAPI must come FIRST so <linux/bpf.h> resolves to libbpf's recent
# copy rather than the container's 5.15-era linux-libc-dev, which predates
# BPF_MAP_TYPE_USER_RINGBUF (added in 6.1). Same fix as UAPI_HEADERS in the EPS
# repo's src/Makefile.
set(LIBBPF_DIR ${PROJECT_SOURCE_DIR}/third_party/libbpf/src)
target_include_directories(core PUBLIC
    ${PROJECT_SOURCE_DIR}/third_party/libbpf/include/uapi
    ${LIBBPF_DIR}/install-dir/usr/include)
target_link_libraries(core PUBLIC ${LIBBPF_DIR}/libbpf.a elf z)