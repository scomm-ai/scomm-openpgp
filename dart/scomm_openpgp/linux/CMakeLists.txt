cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

set(SCOMM_OPENPGP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(SCOMM_OPENPGP_SO "${SCOMM_OPENPGP_ROOT}/target/release/libscomm_openpgp.so")

add_custom_command(
  OUTPUT "${SCOMM_OPENPGP_SO}"
  COMMAND cargo build --release -p scomm-openpgp-ffi
  WORKING_DIRECTORY "${SCOMM_OPENPGP_ROOT}"
  COMMENT "Building libscomm_openpgp.so"
  VERBATIM
)
add_custom_target(scomm_openpgp_rust ALL DEPENDS "${SCOMM_OPENPGP_SO}")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_SO}"
  PARENT_SCOPE
)
