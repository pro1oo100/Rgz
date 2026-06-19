add_library(vernam SHARED library.cpp)
target_include_directories(vernam PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
include(GenerateExportHeader)
generate_export_header(vernam)