#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OQS::oqs" for configuration "Release"
set_property(TARGET OQS::oqs APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OQS::oqs PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/liboqs.so.0.14.1-dev"
  IMPORTED_SONAME_RELEASE "liboqs.so.8"
  )

list(APPEND _cmake_import_check_targets OQS::oqs )
list(APPEND _cmake_import_check_files_for_OQS::oqs "${_IMPORT_PREFIX}/lib/liboqs.so.0.14.1-dev" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
