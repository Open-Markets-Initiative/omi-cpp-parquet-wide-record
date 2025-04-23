cmake_minimum_required(VERSION 3.28)
project(jnx_equities_pts_itch_v1_6)

set(CMAKE_CXX_STANDARD 20)

find_package(PCAP REQUIRED)
find_package(Arrow REQUIRED)
find_package(Parquet REQUIRED)

add_executable(parquet jnx_equities_pts_itch_v1_6.cpp)
target_link_libraries(parquet PRIVATE ${PCAP_LIBRARY} Arrow::arrow_shared Parquet::parquet_shared)