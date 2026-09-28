cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

# Flutter points CMAKE_CURRENT_SOURCE_DIR at .plugin_symlinks; resolve before the repo root.
get_filename_component(_SCOMM_OPENPGP_LINUX_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_OPENPGP_ROOT "${_SCOMM_OPENPGP_LINUX_DIR}/../../.." ABSOLUTE)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
  set(SCOMM_OPENPGP_TRIPLE "aarch64-unknown-linux-gnu")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i686|i386)$")
  set(SCOMM_OPENPGP_TRIPLE "i686-unknown-linux-gnu")
else()
  set(SCOMM_OPENPGP_TRIPLE "x86_64-unknown-linux-gnu")
endif()
set(SCOMM_OPENPGP_LIB_FILENAME "libscomm_openpgp.so")
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/prebuilt_library.cmake")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_PREBUILT}"
  PARENT_SCOPE
)
