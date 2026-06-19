add_library(xtea SHARED xtea.cpp)
target_include_directories(xtea PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
include(GenerateExportHeader)
generate_export_header(xtea)
