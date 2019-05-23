project(http-client-test)

cmake_minimum_required(VERSION 3.1)

if (CMAKE_SYSTEM MATCHES "Linux*")
    set (TARGET_LINUX ON)
endif()

if (CMAKE_SYSTEM MATCHES "Darwin*")
    set (TARGET_OSX ON)
endif()

if (CMAKE_SYSTEM MATCHES "Windows*")
    set (TARGET_WIN ON)
endif()


set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED 11)
set (SRC main.cpp ../../src/http_api.cpp)
set (HDR ../../src/http_api.h)
include_directories(/usr/local/include ../../src)

add_executable(http_client_test ${SRC} ${HDR})
link_directories(/usr/local/lib)
find_library(LIBEVENT libevent.a)
find_library(LIBEVENT_PTHREADS libevent_pthreads.a)
target_link_libraries(http_client_test pthread ${LIBEVENT} ${LIBEVENT_PTHREADS})

if (TARGET_LINUX)
    target_compile_definitions(http_client_test PRIVATE -DTARGET_LINUX)
endif()

if (TARGET_OSX)
    target_compile_definitions(http_client_test PRIVATE -DTARGET_OSX)
endif()

if (TARGET_WIN)
    target_compile_definitions(http_client_test PRIVATE -DTARGET_WIN)
endif()
