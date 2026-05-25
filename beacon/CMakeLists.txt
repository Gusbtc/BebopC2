cmake_minimum_required(VERSION 3.20)
project(beacon C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(beacon
    src/main.c
    src/common/mini_std.c
    src/protocol/message.c
    src/protocol/crypto.c
    src/comms/http.c
    src/comms/session.c
    src/comms/shell.c
    src/comms/socks.c
    src/exec/exec.c
    src/exec/builtin.c
    src/exec/task_dispatch.c
    src/exec/assembly.c
    src/exec/bof.c
    src/resolve/resolve.c
    src/resolve/dynapi.c
    src/transfer/transfer.c
)

target_include_directories(beacon PRIVATE include)
target_compile_options(beacon PRIVATE -O2 -Wall -Wextra -ffunction-sections -fdata-sections -fno-builtin)
target_link_options(beacon PRIVATE -s -mwindows -nostdlib -nostartfiles -Wl,-e,beacon_entry -Wl,--gc-sections)
target_link_libraries(beacon gcc ws2_32)
