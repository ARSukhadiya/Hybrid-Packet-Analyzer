cmake_minimum_required(VERSION 3.10)
project(HybridPacketAnalyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
if(WIN32)
    # Windows-specific libpcap handling
    find_path(PCAP_INCLUDE_DIR pcap.h
        PATHS
        "C:/WpdPack/Include"
        "C:/Program Files/WpdPack/Include"
        "C:/Program Files (x86)/WpdPack/Include"
        "C:/Npcap/Include"
        "C:/Program Files/Npcap/Include"
        "C:/Program Files (x86)/Npcap/Include"
    )
    
    find_library(PCAP_LIBRARY
        NAMES wpcap
        PATHS
        "C:/WpdPack/Lib/x64"
        "C:/WpdPack/Lib"
        "C:/Program Files/WpdPack/Lib/x64"
        "C:/Program Files/WpdPack/Lib"
        "C:/Program Files (x86)/WpdPack/Lib/x64"
        "C:/Program Files (x86)/WpdPack/Lib"
        "C:/Npcap/Lib/x64"
        "C:/Npcap/Lib"
        "C:/Program Files/Npcap/Lib/x64"
        "C:/Program Files/Npcap/Lib"
        "C:/Program Files (x86)/Npcap/Lib/x64"
        "C:/Program Files (x86)/Npcap/Lib"
    )
    
    if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        set(PCAP_FOUND TRUE)
        set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
        set(PCAP_LIBRARIES ${PCAP_LIBRARY})
        message(STATUS "Found libpcap: ${PCAP_LIBRARY}")
    else()
        message(WARNING "libpcap not found. Install Npcap or WinPcap.")
        set(PCAP_FOUND FALSE)
    endif()
else()
    # Linux/macOS - use pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
endif()

# Include directories
if(PCAP_FOUND)
    include_directories(${PCAP_INCLUDE_DIRS})

    # Add executable
    add_executable(packet_capture src/cpp/packet_capture.cpp)

    # Link libraries
    target_link_libraries(packet_capture ${PCAP_LIBRARIES})

    # Set compiler flags
    if(PCAP_CFLAGS_OTHER)
        target_compile_options(packet_capture PRIVATE ${PCAP_CFLAGS_OTHER})
    endif()

    # Create shared library for Python integration
    add_library(packet_capture_lib SHARED src/cpp/packet_capture_lib.cpp)
    target_link_libraries(packet_capture_lib ${PCAP_LIBRARIES})
    if(PCAP_CFLAGS_OTHER)
        target_compile_options(packet_capture_lib PRIVATE ${PCAP_CFLAGS_OTHER})
    endif()
else()
    message(WARNING "libpcap not found - building simple simulation library")
    
    # Create simple simulation library without libpcap
    add_library(packet_capture_lib SHARED src/cpp/simple_packet_lib.cpp)
    message(STATUS "Built simple packet capture simulation library")
endif()

