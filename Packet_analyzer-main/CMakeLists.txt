cmake_minimum_required(VERSION 3.16)

project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(SOURCES
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/rule_manager.cpp
    src/connection_tracker.cpp
)

add_executable(dpi_engine ${SOURCES})

if(APPLE)
    target_link_libraries(dpi_engine PRIVATE pthread)
endif()
