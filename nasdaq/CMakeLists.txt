cmake_minimum_required(VERSION 3.28)
project(nasdaq_equities_totalview_itch_v5_0)

set(CMAKE_CXX_STANDARD 20)

find_package(PCAP REQUIRED)
find_package(Arrow REQUIRED)
find_package(Parquet REQUIRED)

add_executable(parquet nasdaq_equities_totalview_itch_v5_0.cpp)
target_link_libraries(parquet PRIVATE ${PCAP_LIBRARY} Arrow::arrow_shared Parquet::parquet_shared)