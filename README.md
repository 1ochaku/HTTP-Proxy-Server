# HTTP Proxy Server

## Overview

This project implements an HTTP Proxy Server using the Boost.Asio library in C++. The server handles HTTP GET requests, manages cookies, and provides extensive logging for debugging and performance monitoring.

## Features

- **Asynchronous Handling**: Utilizes Boost.Asio's asynchronous features (`async_read` and `async_write`) to handle multiple concurrent connections without blocking operations.
- **Cookie Management**: Implements an efficient cookie management system using `std::unordered_map` for fast access and updates.
- **Detailed Logging**: Comprehensive logging to track server operations, monitor connections, manage cookies, and log responses.

## Requirements

- C++11 or later
- Boost 1.76.0 or higher

## Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/1ochaku/HTTP-Proxy-Server.git
   cd HTTP-Proxy-Server
   ```

2. **Install Boost**:
   Download and install the Boost library from the Boost website.

3. **Build the project**:
   The project includes two main files for different functionalities.

### Compiling and Running the Proxy Server

#### Part 1: Basic Request Handling

- **File**: `proxy_server.cpp`
- **Functionality**: Manages the basic transfer and reception of HTTP requests.

1. Open a terminal and compile the code:

   ```bash
   g++ proxy_server.cpp -o proxy_server -I "D:\Downloads\boost_1_86_0\" -I "D:\Downloads\boost_1_86_0\stage\vs64\lib" -L "D:\Downloads\boost_1_86_0\stage\vs64\lib\boost_system-vc142-mt-gd-x64-1.86.lib" -lws2_32 -lmswsock
   ```

2. Run the server:

   ```bash
   .\proxy_server.exe
   ```

3. In another terminal, initiate a request:

   ```powershell
   Invoke-WebRequest -Proxy http://127.0.0.1:8080 -Uri http://google.com
   ```

   _(On Linux, you can use `curl` instead of `Invoke-WebRequest`)_

#### Part 2: Cookie Processing with Analytics

- **File**: `proxy_server_with_cookies_analytics.cpp`
- **Functionality**: Adds cookie processing and analytics.

1. Open a terminal and compile the code:

   ```bash
   g++ proxy_server_with_cookies_analytics.cpp -o proxy_server_with_cookies_analytics -I "D:\Downloads\boost_1_86_0\" -I "D:\Downloads\boost_1_86_0\stage\vs64\lib" -L "D:\Downloads\boost_1_86_0\stage\vs64\lib\boost_system-vc142-mt-gd-x64-1.86.lib" -lws2_32 -lmswsock
   ```

2. Run the server:

   ```bash
   .\proxy_server_with_cookies_analytics.exe
   ```

3. In another terminal, make a request:

   ```powershell
   Invoke-WebRequest -Proxy http://127.0.0.1:8080 -Uri http://example.com
   ```

## Cookie Management

Cookies are stored using a nested `std::unordered_map` structure:

```cpp
std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, std::string>>> clientCookies;
```

- **Identifier**: Combines the client's IP address and port number.
- **Domain Name**: Domain for which cookies are set.
- **Cookie Name/Value**: Actual cookies managed by the server.

## Logging

The server logs:

- Server connections
- Cookie management details
- Cookies added to request headers
- Received responses
- Stored cookies
