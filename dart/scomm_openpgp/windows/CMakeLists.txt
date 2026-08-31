# This file is used by Flutter to bundle the Sequoia-backed cdylib.
cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

set(SCOMM_OPENPGP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../..")
set(SCOMM_OPENPGP_DLL "${SCOMM_OPENPGP_ROOT}/target/release/scomm_openpgp.dll")

add_custom_command(
  OUTPUT "${SCOMM_OPENPGP_DLL}"
  COMMAND cargo build --release -p scomm-openpgp-ffi
  WORKING_DIRECTORY "${SCOMM_OPENPGP_ROOT}"
  COMMENT "Building scomm_openpgp.dll"
  VERBATIM
)
add_custom_target(scomm_openpgp_rust ALL DEPENDS "${SCOMM_OPENPGP_DLL}")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_DLL}"
  PARENT_SCOPE
)
