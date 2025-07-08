cmake_minimum_required(VERSION 3.15)
project(NEye VERSION 0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(libpcap REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(CURL REQUIRED)

add_library(neye_lib SHARED src/neye_lib.cpp src/logger.cpp)
target_include_directories(neye_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(neye_lib PRIVATE libpcap::libpcap nlohmann_json::nlohmann_json CURL::libcurl)

add_executable(NEye src/main.cpp)
target_include_directories(NEye PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(NEye PRIVATE libpcap::libpcap nlohmann_json::nlohmann_json neye_lib CURL::libcurl)

set(CMAKE_INSTALL_RPATH "${CMAKE_CURRENT_BINARY_DIR}")
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)