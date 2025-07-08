message(STATUS "Conan: Using CMakeDeps conandeps_legacy.cmake aggregator via include()")
message(STATUS "Conan: It is recommended to use explicit find_package() per dependency instead")

find_package(libpcap)
find_package(nlohmann_json)
find_package(CURL)

set(CONANDEPS_LEGACY  libpcap::libpcap  nlohmann_json::nlohmann_json  CURL::libcurl )