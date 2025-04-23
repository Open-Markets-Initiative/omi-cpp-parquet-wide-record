cmake_minimum_required(VERSION 3.28)

project(omi_parqet)

set(CMAKE_CXX_STANDARD 20)

find_package(PCAP REQUIRED)
find_package(Arrow REQUIRED)
find_package(Parquet REQUIRED)

add_subdirectory(jnx)
add_subdirectory(nasdaq)