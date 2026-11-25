# libFuzzer targets for aember-auth's parsers: a host build with clang
# (ASan + UBSan), apart from the SDK build. fuzz/run.sh builds and runs them.
cmake_minimum_required(VERSION 3.25)
project(aember-auth-fuzz LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  message(FATAL_ERROR "libFuzzer needs clang (CXX=clang++-18)")
endif()

set(SANITIZE -fsanitize=address,undefined -fno-sanitize-recover=all
             -fno-omit-frame-pointer)
# clang 18 reports concepts as 201907, so libstdc++ hides <expected>; it
# does implement what <expected> needs.
add_compile_options(-D__cpp_concepts=202002L -Wno-builtin-macro-redefined)
add_compile_options(-g -O1 -Wall -Wextra ${SANITIZE} -fsanitize=fuzzer-no-link)
add_link_options(${SANITIZE})

find_package(PkgConfig REQUIRED)
pkg_check_modules(WOLFSSL REQUIRED IMPORTED_TARGET wolfssl)
find_package(nlohmann_json 3 REQUIRED)

set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/../src)
add_library(aember-auth-lib STATIC ${SRC}/base64.cpp ${SRC}/device-key.cpp
                                   ${SRC}/http.cpp ${SRC}/fleet-client.cpp
                                   ${SRC}/server.cpp)
target_include_directories(aember-auth-lib
                           PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(aember-auth-lib PUBLIC PkgConfig::WOLFSSL
                                             nlohmann_json::nlohmann_json)

foreach(target base64 url http_response auth_config state_files socket)
  add_executable(fuzz_${target} fuzz_${target}.cpp)
  target_link_libraries(fuzz_${target} PRIVATE aember-auth-lib)
  target_link_options(fuzz_${target} PRIVATE -fsanitize=fuzzer)
endforeach()
