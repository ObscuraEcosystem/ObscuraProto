# Building and Testing ObscuraProto

This document outlines the steps to build the ObscuraProto project and run its associated tests.

## Prerequisites

Ensure you have the following installed on your system:
*   `cmake` (version 3.11 or newer)
*   A C++ compiler (e.g., g++ for Linux, Clang, MSVC)
*   `build-essential` (for Debian/Ubuntu-based systems)
*   Internet connection (for CMake's `FetchContent` to download dependencies automatically)

## Building the Project

Follow these steps to build the ObscuraProto project:

1.  **Create a build directory:**
    It is recommended to perform an out-of-source build, which keeps your source directory clean.

    ```bash
    mkdir build
    cd build
    ```

2.  **Configure CMake:**
    Run CMake to configure the project. This command generates the build system files (e.g., Makefiles or Visual Studio project files). We will enable building of tests and examples.

    ```bash
    cmake .. -D OBSCURAPROTO_BUILD_TESTS=ON -D OBSCURAPROTO_BUILD_EXAMPLES=ON
    ```

    If you are in the project root, and want to create the build directory and configure in one step:

    ```bash
    cmake -B build -S . -D OBSCURAPROTO_BUILD_TESTS=ON -D OBSCURAPROTO_BUILD_EXAMPLES=ON
    ```

3.  **Build the project:**
    Compile the project using the generated build system.

    ```bash
    cmake --build .
    ```

    If you configured from the project root into a `build` directory:

    ```bash
    cmake --build build
    ```

## Running Tests

After successfully building the project, you can run the tests:

1.  **Navigate to the build directory:**

    ```bash
    cd build
    ```

2.  **Execute tests using CTest:**
    `ctest` is the CMake test driver program. The `--output-on-failure` flag ensures that the test output is shown only for failing tests, which is useful for quick debugging.

    ```bash
    ctest --output-on-failure
    ```
