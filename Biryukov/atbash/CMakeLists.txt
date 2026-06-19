add_library(atbash SHARED atbash.cpp)
target_include_directories(atbash PUBLIC . ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})
