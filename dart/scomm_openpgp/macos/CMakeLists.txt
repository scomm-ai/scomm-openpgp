cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

# Flutter points CMAKE_CURRENT_SOURCE_DIR at .plugin_symlinks; resolve before the repo root.
get_filename_component(_SCOMM_OPENPGP_MACOS_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_OPENPGP_ROOT "${_SCOMM_OPENPGP_MACOS_DIR}/../../.." ABSOLUTE)

if(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
  set(SCOMM_OPENPGP_TRIPLE "x86_64-apple-darwin")
elseif(CMAKE_OSX_ARCHITECTURES MATCHES "arm64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
  set(SCOMM_OPENPGP_TRIPLE "aarch64-apple-darwin")
else()
  set(SCOMM_OPENPGP_TRIPLE "x86_64-apple-darwin")
endif()
set(SCOMM_OPENPGP_LIB_FILENAME "libscomm_openpgp.dylib")
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/prebuilt_library.cmake")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_PREBUILT}"
  PARENT_SCOPE
)
