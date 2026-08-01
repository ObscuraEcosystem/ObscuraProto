cmake_minimum_required(VERSION 3.11)

# Project name and version
project(ObscuraProto VERSION 1.1.1 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use shared (dynamic) MSVC runtime for all targets including FetchContent'd deps
if(MSVC)
    if(POLICY CMP0091)
        cmake_policy(SET CMP0091 NEW)
    endif()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# Set a minimum policy version to allow older CMake scripts from dependencies to run.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# ##############################################################################
# # Cryptography Library
# ##############################################################################
include(FetchContent)

# Declare asio dependency (for websocketpp)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0 # Using a stable tag
)
FetchContent_MakeAvailable(asio)

# Declare websocketpp dependency
# Force C++11 mode to avoid Boost dependency on MSVC
add_compile_definitions(
    _WEBSOCKETPP_CPP11_TYPE_TRAITS_
    _WEBSOCKETPP_CPP11_MEMORY_
    _WEBSOCKETPP_CPP11_THREAD_
    _WEBSOCKETPP_CPP11_FUNCTIONAL_
    _WEBSOCKETPP_CPP11_SYSTEM_ERROR_
    _WEBSOCKETPP_CPP11_RANDOM_DEVICE_
    _WEBSOCKETPP_CPP11_CHRONO_
)
FetchContent_Declare(
    websocketpp
    GIT_REPOSITORY https://github.com/zaphoyd/websocketpp.git
    GIT_TAG 0.8.2 # Using a stable tag
)
FetchContent_MakeAvailable(websocketpp)

# Declare sodium dependency (via libsodium-cmake wrapper)
FetchContent_Declare(Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c
)
set(SODIUM_DISABLE_TESTS ON)
FetchContent_MakeAvailable(Sodium)

# Fix sodium target's include directories for proper export support.
# libsodium-cmake uses unprefixed relative paths which CMake rejects when exporting.
set_target_properties(sodium PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
        "$<BUILD_INTERFACE:${sodium_SOURCE_DIR}/libsodium/src/libsodium/include>;$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)



# ##############################################################################
# # Library Target
# ##############################################################################

# Add the library target
add_library(obscuraproto)

# Add source files to the library
target_sources(obscuraproto
    PRIVATE
        src/packet.cpp
        src/crypto.cpp
        src/session.cpp
        src/version.cpp
        src/handshake_messages.cpp
        src/stream.cpp
        src/config.cpp
        src/rate_limiter.cpp
        src/ws_client.cpp
        src/ws_server.cpp
)

# Public include directories
target_include_directories(obscuraproto
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
        $<BUILD_INTERFACE:${websocketpp_SOURCE_DIR}>
)


# Add compile definitions
target_compile_definitions(obscuraproto
    PUBLIC
        ASIO_STANDALONE
)

# Link external libraries
find_package(Threads REQUIRED)

if(WIN32)
    target_link_libraries(obscuraproto PUBLIC ws2_32)
endif()

target_link_libraries(obscuraproto
    PUBLIC
        Threads::Threads
        sodium
)


# ##############################################################################
# # Tests (optional, using GoogleTest)
# ##############################################################################

option(BUILD_TESTING "Build the tests" ON)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()


# ##############################################################################
# # Examples (optional)
# ##############################################################################

# Add examples subdirectory
add_subdirectory(examples)

# ##############################################################################
# # Installation
# ##############################################################################

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Set the destination for the public headers
set(INSTALL_INCLUDE_DIR ${CMAKE_INSTALL_INCLUDEDIR})

# Install the public headers
install(DIRECTORY include/
    DESTINATION ${INSTALL_INCLUDE_DIR}
)

# Generate and install the package configuration file
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ObscuraProtoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

# Create an export set for the library target and its dependencies
install(TARGETS obscuraproto sodium
    EXPORT ObscuraProtoTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${INSTALL_INCLUDE_DIR}
)

# Export dependencies
# This ensures that consumers of this package will also find and link against
# the dependencies like asio, websocketpp, and sodium.
export(EXPORT ObscuraProtoTargets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/ObscuraProtoTargets.cmake"
    NAMESPACE ObscuraProto::
)

# Configure the main package file
configure_package_config_file(
    "cmake/ObscuraProtoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ObscuraProtoConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ObscuraProto"
    PATH_VARS INSTALL_INCLUDE_DIR
)

# Install the generated CMake files
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/ObscuraProtoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/ObscuraProtoConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ObscuraProto"
)

install(EXPORT ObscuraProtoTargets
    FILE ObscuraProtoTargets.cmake
    NAMESPACE ObscuraProto::
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/ObscuraProto"
)
