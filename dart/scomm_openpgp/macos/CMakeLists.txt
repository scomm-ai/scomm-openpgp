cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

set(SCOMM_OPENPGP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(SCOMM_OPENPGP_DYLIB "${SCOMM_OPENPGP_ROOT}/target/release/libscomm_openpgp.dylib")

add_custom_command(
  OUTPUT "${SCOMM_OPENPGP_DYLIB}"
  COMMAND cargo build --release -p scomm-openpgp-ffi
  WORKING_DIRECTORY "${SCOMM_OPENPGP_ROOT}"
  COMMENT "Building libscomm_openpgp.dylib"
  VERBATIM
)
add_custom_target(scomm_openpgp_rust ALL DEPENDS "${SCOMM_OPENPGP_DYLIB}")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_DYLIB}"
  PARENT_SCOPE
)
