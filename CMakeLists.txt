cmake_minimum_required(VERSION 3.10)
project(plcfuzz C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(-Wall -Wextra -O2)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_library(plcfuzz_core STATIC
    plcfuzz/src/core.c
)

target_include_directories(plcfuzz_core PUBLIC
    ${CMAKE_SOURCE_DIR}/plcfuzz/include
    ${CMAKE_SOURCE_DIR}/plcfuzz/src
)

target_link_libraries(plcfuzz_core PUBLIC dl)

# ---------------------------------------------------------------------------
# Target plugins (shared libraries)
# ---------------------------------------------------------------------------

# OpenPLC in-process target plugin (reuses OpenPLC runtime helper sources)
add_library(plcfuzz_target_openplc_inproc SHARED
    plcfuzz/targets/openplc_inproc/openplc_inproc_target.c
    openplc-runtime/core/src/plc_app/utils/log.c
    openplc-runtime/core/src/plc_app/utils/utils.c
    openplc-runtime/core/src/plc_app/image_tables.c
    openplc-runtime/core/src/plc_app/plcapp_manager.c
)

target_include_directories(plcfuzz_target_openplc_inproc PRIVATE
    ${CMAKE_SOURCE_DIR}/plcfuzz/include
    ${CMAKE_SOURCE_DIR}/openplc-runtime/core/src/plc_app
    ${CMAKE_SOURCE_DIR}/openplc-runtime/core/src/plc_app/utils
)

target_link_libraries(plcfuzz_target_openplc_inproc PRIVATE dl pthread)

set_target_properties(plcfuzz_target_openplc_inproc PROPERTIES
    OUTPUT_NAME "plcfuzz_target_openplc_inproc"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/targets
)

# Modbus/TCP target plugin
add_library(plcfuzz_target_modbus_tcp SHARED
    plcfuzz/targets/modbus_tcp/modbus_tcp_target.c
)

target_include_directories(plcfuzz_target_modbus_tcp PRIVATE
    ${CMAKE_SOURCE_DIR}/plcfuzz/include
)

set_target_properties(plcfuzz_target_modbus_tcp PROPERTIES
    OUTPUT_NAME "plcfuzz_target_modbus_tcp"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/targets
)

# ---------------------------------------------------------------------------
# Frontends
# ---------------------------------------------------------------------------

add_executable(plcfuzz_afl_harness
    plcfuzz/src/afl_harness.c
)
target_link_libraries(plcfuzz_afl_harness PRIVATE plcfuzz_core)
set_target_properties(plcfuzz_afl_harness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

