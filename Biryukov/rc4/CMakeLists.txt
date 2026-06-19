add_library(rc4 SHARED rc4.cpp)
target_include_directories(rc4 PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
