cmake_minimum_required(VERSION 3.20.0)
project(of_core_fs_windows VERSION 1.0.1 DESCRIPTION "OpenFiles File Handler for Windows")

include_directories(
        ${of_core_BINARY_DIR}
        ${of_core_SOURCE_DIR}/include
        include
)

set(SRCS
        src/fs_windows.c
        )

add_library(of_core_fs_windows OBJECT ${SRCS})
set_property(TARGET of_core_fs_windows PROPERTY POSITION_INDEPENDENT_CODE ON)

