# This file is used by Flutter to bundle the Sequoia-backed cdylib.
cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "scomm_openpgp")
project(${PROJECT_NAME} LANGUAGES CXX)

# Flutter points CMAKE_CURRENT_SOURCE_DIR at windows/flutter/ephemeral/.plugin_symlinks
# (not the pub-cache git checkout). Resolve that symlink before walking to the repo root.
get_filename_component(_SCOMM_OPENPGP_WINDOWS_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(SCOMM_OPENPGP_ROOT "${_SCOMM_OPENPGP_WINDOWS_DIR}/../../.." ABSOLUTE)

# Generator platform wins. Windows-on-ARM still builds the x64 runner.
if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
  set(SCOMM_OPENPGP_TRIPLE "i686-pc-windows-msvc")
elseif(CMAKE_GENERATOR_PLATFORM MATCHES "ARM64|arm64")
  set(SCOMM_OPENPGP_TRIPLE "aarch64-pc-windows-msvc")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
  set(SCOMM_OPENPGP_TRIPLE "aarch64-pc-windows-msvc")
else()
  set(SCOMM_OPENPGP_TRIPLE "x86_64-pc-windows-msvc")
endif()
set(SCOMM_OPENPGP_LIB_FILENAME "scomm_openpgp.dll")
include("${CMAKE_CURRENT_LIST_DIR}/../cmake/prebuilt_library.cmake")

set(scomm_openpgp_bundled_libraries
  "${SCOMM_OPENPGP_PREBUILT}"
  PARENT_SCOPE
)
