# HTTP API Library

A C++ minimalistic HTTP client and server library built on top of libevent and evhtp, designed for cross-platform development.

## Overview

This library provides both HTTP client and server functionality with the following key features:

- **HTTP Client**: Asynchronous HTTP client with connection pooling and timeout support
- **HTTP Server**: Multi-threaded HTTP server with support for various content types
- **Request Handling**: Support for GET/POST requests with URL parameters and multipart form data
- **File Uploads**: Built-in multipart/form-data parser for file uploads
- **Timer Support**: Event-based timer functionality
- **Cross-Platform**: Supports Linux, macOS, and Windows

## Architecture

### Core Components

- `http_client`: Asynchronous HTTP client class with connection management
- `http_server`: Multi-threaded HTTP server (when ENABLE_MULTI_THREAD_SERVER is defined)
- `request_params`: Parameter handling class with type-safe getters
- `timer`: Event-based timer implementation
- `multipart_parser`: Parser for handling multipart form data

### Key Features

- **Content Type Support**: HTML, JSON, JavaScript, PNG, CSS, and binary files
- **CORS Support**: Built-in Cross-Origin Resource Sharing headers
- **Chunked Transfer**: Support for chunked HTTP responses
- **Connection Management**: Keep-alive and connection pooling
- **Thread Safety**: Multi-threaded server implementation with proper locking

## Build Requirements

- CMake 3.20 or higher
- C++23 compatible compiler
- libevent library (included as static library)
- evhtp library (included as static library)


## Building

The library is designed to be integrated into existing CMake projects. Add the source files to your project:

```cmake
# Include the HTTP API library
add_subdirectory(http_api/src)
target_link_libraries(your_target http_lib)
```

Platform-specific configurations are handled automatically based on the target system.

Or you can just copy files to your project.

## Usage Examples

### HTTP Client

```cpp
#include "http_api.h"

http_client client;
client.get("http://example.com", http_client::connection_close, 
    [](http_client& client, http_client::ctx ctx, http_client::response_info& info) {
        if (info.mChunk.size() == 0) {
            std::cout << "Response: " << info.mAllData << std::endl;
        }
    });
```

### HTTP Server

```cpp
#include "http_api.h"

http_server server;
server.set_port(8080);
server.set_handler([](http_server& server, http_server::ctx ctx, 
                     const request_info& ri, http_server::http_request_ownership& ownership) {
    server.send_json(ctx, R"({"status": "ok"})");
});
server.start();
```

## Testing

The project includes test applications:

- **Client Test**: `test/client/main.cpp` - Demonstrates HTTP client usage
- **Server Test**: `test/server/main.cpp` - Runs a test HTTP server with dashboard

Build and run tests using the provided CMake configuration.

## Dependencies

- **libevent**: Event-driven network library
- **evhtp**: High-performance HTTP server library

All dependencies are included as static libraries for the supported platforms.

## License

MPL license - you are free to use it but we will be happy to see fixes + proposed changes.

