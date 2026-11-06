# Resolve the cdylib for this machine from prebuilt/<rust-triple>/.
# CI commits those files, and the git ref an app pins includes them. There is no
# download fallback: fetching from a moving branch would link a binary the pin
# never named.

set(SCOMM_OPENPGP_PREBUILT
  "${SCOMM_OPENPGP_ROOT}/prebuilt/${SCOMM_OPENPGP_TRIPLE}/${SCOMM_OPENPGP_LIB_FILENAME}")
if(NOT EXISTS "${SCOMM_OPENPGP_PREBUILT}")
  message(FATAL_ERROR
    "scomm_openpgp: no prebuilt library for ${SCOMM_OPENPGP_TRIPLE}. "
    "Pin a scomm-openpgp revision that CI has published.")
endif()
