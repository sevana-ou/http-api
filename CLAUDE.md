# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

C++ minimalistic HTTP client and server library built on libevent and evhtp. Licensed under MPL. Supports Linux, macOS, and Windows.

## Build Commands

### Library (as part of a larger CMake project)
```cmake
add_subdirectory(http_api/src)
target_link_libraries(your_target http_lib)
```

### Test Server
```bash
cd test/server
mkdir -p build && cd build
cmake .. && make
./http_api_test    # starts server on port 8080
```

### Test Client
```bash
cd test/client
mkdir -p build && cd build
cmake .. && make
./http_client_test <url>
```

### Manual Testing (with server running)
```bash
bash test/scripts/load_page.sh        # GET HTML
bash test/scripts/load_json.sh        # GET JSON
bash test/scripts/load_json_chunked.sh # GET chunked JSON
bash test/scripts/upload_file.sh      # POST multipart file upload
bash test/scripts/quit_server.sh      # shutdown server
```

There is no automated test framework — testing is manual via curl scripts.

## Build Requirements

- CMake 3.20+
- C++20 compiler (the library CMakeLists uses C++20; test CMakeLists use C++11)
- libevent (libevent.a, libevent_pthreads.a) — must be installed on the system
- evhtp — bundled as pre-built static libraries in `lib/evhtp/`

## Architecture

### Source Layout
- `src/http_api.h` + `src/http_api.cpp` — entire library implementation (~1400 lines)
- `src/multipart_parser.h` — header-only state-machine multipart/form-data parser
- `src/multipart_reader.h` — header-only higher-level multipart reader with callbacks
- `lib/evhtp/` — bundled evhtp static libraries (Linux glibc/musl, macOS) and headers
- `test/server/` — example HTTP server with dashboard endpoints
- `test/client/` — example HTTP client

### Core Classes (all in `http_api.h`)

- **`http_client`** — async HTTP client with connection pooling. Runs its own event loop in a worker thread. Key method: `get(url, connection_kind, response_handler)`.
- **`http_server`** — multi-threaded HTTP server (only available when `ENABLE_MULTI_THREAD_SERVER` is defined). Uses evhtp for concurrent request handling. Supports `send_*()` methods for responding from internal threads and `queue_*()` methods for responding from external threads.
- **`request_params`** — extends `std::multimap<string,string>` with type-safe getters (`get_bool`, `get_int`, `get_string`, etc.).
- **`timer`** — libevent-based timer with single-shot, interval, and interval-with-immediate modes.

### Key Compile Definitions
- `TARGET_LINUX` / `TARGET_OSX` / `TARGET_WIN` — platform detection (set automatically by CMake)
- `ENABLE_MULTI_THREAD_SERVER` — must be defined to compile `http_server` (it pulls in evhtp headers)

### Threading Model
Both client and server run dedicated worker threads with libevent's `event_base_dispatch()`. The server additionally supports evhtp's built-in I/O thread pool via `set_threads(n)`. Cross-thread response delivery uses a queue mechanism (`queue_json`, `queue_html`, `queue_error`) that is safe to call from any thread, unlike the `send_*` methods which must be called from internal threads only.

### Content Types
The server supports: HTML, JSON, JavaScript, PNG, CSS, and binary. CORS headers are available via `set_cors()`.
