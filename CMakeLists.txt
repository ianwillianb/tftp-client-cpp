cmake_minimum_required(VERSION 3.9)

project(tftp-client VERSION 1.0.0 DESCRIPTION "Simple TFTP client" LANGUAGES CXX)
set(CMAKE_BUILD_TYPE Release)

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/build)

# Library
add_library(tftp-client SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SocketWrapper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/TFTPClient.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/TFTPUtils.cpp
)

add_library(tftp-client-static STATIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src/SocketWrapper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/TFTPClient.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/TFTPUtils.cpp
)

# Include directories
target_include_directories(tftp-client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_include_directories(tftp-client-static PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# Set library properties
set(TFTP_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/SocketWrapper.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/TFTPClient.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/TFTPDefinitions.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/TFTPUtils.h"
)

set_target_properties(tftp-client PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${TFTP_PUBLIC_HEADERS}"
)

# Generate pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/tftp-client.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tftp-client.pc"
    @ONLY
)

# Installation
include(GNUInstallDirs)
install(TARGETS tftp-client
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tftp-client.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)

