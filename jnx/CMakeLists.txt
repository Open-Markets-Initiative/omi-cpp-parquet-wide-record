add_executable(jnx_equities_pts_itch_v1_6 jnx_equities_pts_itch_v1_6.cpp)
target_link_libraries(jnx_equities_pts_itch_v1_6
 PRIVATE ${PCAP_LIBRARY}
 Arrow::arrow_shared
 Parquet::parquet_shared)