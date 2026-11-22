cmake_minimum_required(VERSION 3.25)
project(aember-auth VERSION 0.1.0 LANGUAGES CXX)

# Cross builds: the aember-resources SDK's toolchain (`aember build -a <arch>`
# passes OEToolchainConfig.cmake); the unit tests also build with the x64 SDK
# (they need its wolfSSL) and run through its loader.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Build the unit tests" OFF)

add_compile_options(-Wall -Wextra -Wpedantic -Werror)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WOLFSSL REQUIRED IMPORTED_TARGET wolfssl)
find_package(nlohmann_json 3 REQUIRED)

add_library(aember-auth-lib STATIC src/base64.cpp src/device-key.cpp
                                   src/http.cpp src/fleet-client.cpp src/server.cpp)
target_include_directories(aember-auth-lib PUBLIC include)
target_link_libraries(aember-auth-lib PUBLIC PkgConfig::WOLFSSL
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
