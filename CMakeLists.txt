cmake_minimum_required(VERSION 4.0)
project(RGZ)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(Dobrinov/playfair)
add_subdirectory(Dobrinov/vernam)

add_executable(app main.cpp)
target_include_directories(app PRIVATE ${CMAKE_SOURCE_DIR})

target_link_libraries(app ${CMAKE_DL_LIBS})

add_dependencies(app playfair vernam)

set_target_properties(playfair vernam PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Libraries"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/Libraries")