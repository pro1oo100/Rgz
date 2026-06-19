add_library(chacha20 SHARED chacha20.cpp)
target_include_directories(chacha20 PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
include(GenerateExportHeader)
generate_export_header(chacha20)
