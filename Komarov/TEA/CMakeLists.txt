add_library(TEA SHARED TEA.cpp)
target_include_directories(playfair PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
include(GenerateExportHeader)
generate_export_header(TEA)