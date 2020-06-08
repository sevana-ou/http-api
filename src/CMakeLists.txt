project(http-lib)

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
set (SRC http_api.cpp)
set (HDR http_api.h multipart_reader.h multipart_parser.h)
add_library(http_lib STATIC ${SRC} ${HDR})

target_include_directories(http_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../lib/evhtp/include)

#find_library(LIBEVENT libevent.a)
#find_library(LIBEVENT_PTHREADS libevent_pthreads.a)
#target_link_libraries(http_client_test pthread ${LIBEVENT} ${LIBEVENT_PTHREADS})

if (TARGET_LINUX)
    target_compile_definitions(http_lib PRIVATE -DTARGET_LINUX)
    set (EVHTP_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../lib/evhtp/lib/linux/x64/libevhtp.a PARENT_SCOPE)
endif()

if (TARGET_OSX)
    target_compile_definitions(http_lib PRIVATE -DTARGET_OSX)
    set (EVHTP_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../lib/evhtp/lib/macos/libevhtp.a PARENT_SCOPE)
endif()

if (TARGET_WIN)
    target_compile_definitions(http_lib PRIVATE -DTARGET_WIN)
endif()

