# Resolve the cdylib for this machine from prebuilt/<rust-triple>/.
# CI commits those files. A checkout that does not contain the triple yet
# downloads it from main so app builds do not compile OpenSSL.

set(_scomm_prebuilt_dir "${SCOMM_OPENPGP_ROOT}/prebuilt/${SCOMM_OPENPGP_TRIPLE}")
set(_scomm_prebuilt_file "${_scomm_prebuilt_dir}/${SCOMM_OPENPGP_LIB_FILENAME}")
if(NOT EXISTS "${_scomm_prebuilt_file}")
  file(MAKE_DIRECTORY "${_scomm_prebuilt_dir}")
  set(_scomm_prebuilt_url
    "https://github.com/scomm-ai/scomm-openpgp/raw/main/prebuilt/${SCOMM_OPENPGP_TRIPLE}/${SCOMM_OPENPGP_LIB_FILENAME}")
  message(STATUS "scomm_openpgp: downloading ${_scomm_prebuilt_url}")
  file(DOWNLOAD "${_scomm_prebuilt_url}" "${_scomm_prebuilt_file}"
    STATUS _scomm_prebuilt_dl
    TIMEOUT 180)
  list(GET _scomm_prebuilt_dl 0 _scomm_prebuilt_code)
  list(GET _scomm_prebuilt_dl 1 _scomm_prebuilt_msg)
  if(NOT _scomm_prebuilt_code EQUAL 0)
    file(REMOVE "${_scomm_prebuilt_file}")
    message(FATAL_ERROR
      "scomm_openpgp: no prebuilt library for ${SCOMM_OPENPGP_TRIPLE} "
      "(${_scomm_prebuilt_msg}).")
  endif()
endif()
# include() shares the caller's scope. PARENT_SCOPE would hide this path
# from the plugin CMakeLists that builds bundled_libraries.
set(SCOMM_OPENPGP_PREBUILT "${_scomm_prebuilt_file}")
