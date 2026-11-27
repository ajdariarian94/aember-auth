# The crypto pieces aember-auth links, shared by the SDK build (CMakeLists.txt)
# and the host fuzz build (fuzz/CMakeLists.txt). Needs the C
# language enabled.
#
# - monocypher: Ed25519 for the device key (third_party/, BSD-2-Clause).
# - aember-auth-tls: mbedTLS (Apache-2.0), an INTERFACE target over
#   pkg-config (3.x) or find_library (2.28, Ubuntu 24.04's).
set(_root ${CMAKE_CURRENT_LIST_DIR}/..)

add_library(monocypher STATIC ${_root}/third_party/monocypher/monocypher.c
                              ${_root}/third_party/monocypher/monocypher-ed25519.c)
target_include_directories(monocypher SYSTEM PUBLIC ${_root}/third_party/monocypher)
set_target_properties(monocypher PROPERTIES C_STANDARD 99
                                            POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
add_library(aember-auth-tls INTERFACE)
# mbedTLS 3.x ships pkg-config files; 2.28 (Ubuntu 24.04) doesn't.
pkg_check_modules(MBEDTLS IMPORTED_TARGET mbedtls mbedx509 mbedcrypto)
if(MBEDTLS_FOUND)
  target_link_libraries(aember-auth-tls INTERFACE PkgConfig::MBEDTLS)
else()
  find_library(MBEDTLS_LIB mbedtls REQUIRED)
  find_library(MBEDX509_LIB mbedx509 REQUIRED)
  find_library(MBEDCRYPTO_LIB mbedcrypto REQUIRED)
  target_link_libraries(aember-auth-tls INTERFACE ${MBEDTLS_LIB} ${MBEDX509_LIB}
                                                  ${MBEDCRYPTO_LIB})
endif()
set(AEMBER_AUTH_TLS_SOURCE ${_root}/src/tls-mbedtls.cpp)
