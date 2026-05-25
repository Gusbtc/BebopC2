cmake_minimum_required(VERSION 3.16)
project(beacon-linux C)

set(CMAKE_C_STANDARD 11)

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffile-prefix-map=${CMAKE_SOURCE_DIR}/=")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls/CMakeLists.txt")
    add_subdirectory(deps/mbedtls)
    set(MBEDTLS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/mbedtls/include")
    set(MBEDTLS_LIBS mbedtls mbedx509 mbedcrypto)
    set(MBEDTLS_VENDORED ON)
else()
    execute_process(
        COMMAND ${CMAKE_C_COMPILER} -dumpmachine
        OUTPUT_VARIABLE BEACON_LINUX_ARCH_TRIPLET
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    set(BEACON_LINUX_INCLUDE_PATHS
        /usr/include
        /usr/local/include
        /usr/include/${BEACON_LINUX_ARCH_TRIPLET}
        /usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
    )
    set(BEACON_LINUX_LIBRARY_PATHS
        /usr/lib
        /usr/local/lib
        /usr/lib/${BEACON_LINUX_ARCH_TRIPLET}
        /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
        /lib/${BEACON_LINUX_ARCH_TRIPLET}
        /lib/${CMAKE_LIBRARY_ARCHITECTURE}
    )
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/aes.h PATHS ${BEACON_LINUX_INCLUDE_PATHS})
    find_library(MBEDTLS_LIB NAMES libmbedtls.a mbedtls PATHS ${BEACON_LINUX_LIBRARY_PATHS})
    find_library(MBEDX509_LIB NAMES libmbedx509.a mbedx509 PATHS ${BEACON_LINUX_LIBRARY_PATHS})
    find_library(MBEDCRYPTO_LIB NAMES libmbedcrypto.a mbedcrypto PATHS ${BEACON_LINUX_LIBRARY_PATHS})
    if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_LIB OR NOT MBEDX509_LIB OR NOT MBEDCRYPTO_LIB)
        message(FATAL_ERROR "mbedTLS development files not found. Install libmbedtls-dev or vendor mbedTLS at beacon-linux/deps/mbedtls.")
    endif()
    set(MBEDTLS_LIBS ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB})
    set(MBEDTLS_VENDORED OFF)
endif()

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
)
if(MBEDTLS_VENDORED)
    target_include_directories(beacon-linux PRIVATE ${MBEDTLS_INCLUDE_DIR})
else()
    target_compile_options(beacon-linux PRIVATE -idirafter ${MBEDTLS_INCLUDE_DIR})
endif()

target_link_libraries(beacon-linux PRIVATE
    ${MBEDTLS_LIBS}
    pthread
)

set_target_properties(beacon-linux PROPERTIES OUTPUT_NAME "beacon.elf")
target_compile_options(beacon-linux PRIVATE -Os -Wall -Wextra -Wno-unused-parameter)
target_link_options(beacon-linux PRIVATE -static -s)
