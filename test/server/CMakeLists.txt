project(http-api-test)

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
set (SRC dashboard.cpp main.cpp ../../src/http_api.cpp )
set (HDR dashboard.h ../../src/http_api.h ../../src/multipart_parser.h ../../src/multipart_reader.h)
include_directories(/usr/local/include ../../src ../../lib/evhtp/include)

add_executable(http_api_test ${SRC})
link_directories(/usr/local/lib)
find_library(LIBEVENT libevent.a)
find_library(LIBEVENT_PTHREADS libevent_pthreads.a)
find_library(LIBEVENT_HTTP evhtp PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/evhtp/lib/macos NO_DEFAULT_PATH)

target_link_libraries(http_api_test pthread ${LIBEVENT} ${LIBEVENT_PTHREADS} ${LIBEVENT_HTTP})

if (TARGET_LINUX)
    target_compile_definitions(http_api_test PRIVATE -DTARGET_LINUX)
endif()

if (TARGET_OSX)
    target_compile_definitions(http_api_test PRIVATE -DTARGET_OSX -DENABLE_MULTI_THREAD_SERVER)
endif()

if (TARGET_WIN)
    target_compile_definitions(http_api_test PRIVATE -DTARGET_WIN)
endif()
