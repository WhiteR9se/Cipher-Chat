cmake_minimum_required(VERSION 3.16)
project(CipherChat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(OpenSSL REQUIRED)

add_library(cipherchat_common
    src/common/crypto.cpp
    src/common/protocol.cpp
    src/common/utils.cpp
)

target_include_directories(cipherchat_common
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(cipherchat_common
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
)

add_executable(server
    src/server/main.cpp
    src/server/server.cpp
)

target_link_libraries(server
    PRIVATE
        cipherchat_common
        pthread
)

add_executable(client
    src/client/main.cpp
    src/client/client.cpp
)

target_link_libraries(client
    PRIVATE
        cipherchat_common
        pthread
)

install(TARGETS server client
        RUNTIME DESTINATION bin)

