cmake_minimum_required(VERSION 3.10)
project(cryptum CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror)

include_directories(src)

add_library(atbash SHARED libs/atbash/atbash.cpp)
add_library(rc4    SHARED libs/rc4/rc4.cpp)

add_executable(cryptum src/main.cpp)
target_link_libraries(cryptum dl)

add_executable(test_ciphers tests/test_ciphers.cpp)
target_link_libraries(test_ciphers dl)

add_custom_target(run_tests
    COMMAND ${CMAKE_COMMAND} -E env
        LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}
        ${CMAKE_BINARY_DIR}/test_ciphers
    DEPENDS test_ciphers atbash rc4
    COMMENT "Running cipher tests"
)

install(TARGETS cryptum DESTINATION bin)
install(TARGETS atbash rc4 DESTINATION lib)
