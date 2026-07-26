# tests/CMakeLists.txt

# Google Test
set(gtest_force_shared_crt ON CACHE BOOL "Use shared (DLL) run-time lib" FORCE)
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
FetchContent_MakeAvailable(googletest)

# Enable testing
enable_testing()

# Create the test executable
add_executable(obscuraproto_tests
    main.cpp
    crypto_test.cpp
    packet_test.cpp
    handshake_messages_test.cpp
    version_negotiation_test.cpp
    client_auth_test.cpp
    integration_test.cpp
    rate_limiter_test.cpp
    config_test.cpp
    ws_lifecycle_test.cpp
)

# Link the test executable against the main library and Google Test
target_link_libraries(obscuraproto_tests
    PRIVATE
    obscuraproto
    GTest::gtest_main
)

# Add the test to CTest
include(GoogleTest)
gtest_discover_tests(obscuraproto_tests)
