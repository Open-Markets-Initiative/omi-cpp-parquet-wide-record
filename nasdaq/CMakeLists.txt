add_executable(nasdaq_equities_totalview_itch_v5_0 nasdaq_equities_totalview_itch_v5_0.cpp)
target_link_libraries(nasdaq_equities_totalview_itch_v5_0
 PRIVATE ${PCAP_LIBRARY} 
 Arrow::arrow_shared 
 Parquet::parquet_shared)