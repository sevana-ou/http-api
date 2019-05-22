project(http-api-test)

cmake_minimum_required(VERSION 3.1)


set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED 11)
set (SRC dashboard.cpp main.cpp ../src/http_api.cpp)
set (HDR dashboard.h ../src/http_api.h)
include_directories(/usr/local/include ../src)

add_executable(http_api_test ${SRC})
link_directories(/usr/local/lib)
find_library(LIBEVENT libevent.a)
target_link_libraries(http_api_test pthread ${LIBEVENT})
