cmake_minimum_required(VERSION 3.25)
project(aember-auth VERSION 0.1.0 LANGUAGES C CXX)

# Cross builds: the aember-resources SDK's toolchain (`aember build -a <arch>`
# passes OEToolchainConfig.cmake); the unit tests also build with the x64 SDK
# (they need its TLS library) and run through its loader.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build the unit tests" OFF)

# Our C++ only: third_party/ (C) keeps its own warnings.
add_compile_options("$<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wpedantic;-Werror>")

# TLS: mbedTLS (Apache-2.0) from the aember-resources SDK (v0.1.16+). The
# wolfSSL backend (GPL-2.0-only) is gone: a GPL library can't be linked into
# a binary sold under the Aember License (aember's doc/licensing/).

include(cmake/backends.cmake)
find_package(nlohmann_json 3 REQUIRED)

add_library(aember-auth-lib STATIC src/base64.cpp src/device-key.cpp
                                   src/http.cpp src/fleet-client.cpp src/server.cpp
                                   ${AEMBER_AUTH_TLS_SOURCE})
target_include_directories(aember-auth-lib PUBLIC include)
target_link_libraries(aember-auth-lib PUBLIC aember-auth-tls monocypher
                                             nlohmann_json::nlohmann_json)

add_executable(aember-auth src/main.cpp)
target_link_libraries(aember-auth PRIVATE aember-auth-lib)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(aember-auth PRIVATE -s)
endif()

include(GNUInstallDirs)
install(TARGETS aember-auth RUNTIME DESTINATION usr/bin)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
