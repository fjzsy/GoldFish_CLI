cmake_minimum_required(VERSION 3.19)
project(GoldFish_CLI LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Network)

qt_standard_project_setup()

qt_add_executable(GoldFish_CLI
    main.cpp
    flowaggregator.cpp
    flowaggregator.h
    packet_analyzer_engine.cpp
    packet_analyzer_engine.h
    packet_info_extended.h
    pcapfilereader.cpp
    pcapfilereader.h
    statisticsheader.h
    psnchartheader.h
    protocol_parser_factory.h
    protocol_layers.h
    otherpacketstats.h
    protocol_parsers.cpp
    reportdata.cpp reportdata.h
    reportdata.cpp reportdata.h
    pcapanalyzerapp.cpp pcapanalyzerapp.h

    commconfig.h commconfig.cpp
    analytics.cpp analytics.h

)

# qt_add_translations(
#     TARGETS GoldFish_CLI
#     TS_FILES GoldFish_CLI_en_AS.ts
# )

target_link_libraries(GoldFish_CLI
    PRIVATE
        Qt::Core
        Qt::Gui
        Qt::Network
)

# ==================== 平台相关 ====================
if(WIN32)
    # Windows 平台：Npcap SDK 自动查找
    add_compile_definitions(WIN32 WPCAP)

    # 自动查找 Npcap SDK 路径（支持 C/D 盘，支持自定义路径）
    find_path(NPCAP_INCLUDE_DIR
        NAMES pcap.h
        PATHS
        "C:/npcap-sdk-1.16/Include"
        "D:/npcap-sdk-1.16/Include"
        "$ENV{NPCAP_DIR}/Include"
    )

    find_library(WPCAP_LIB
        NAMES wpcap
        PATHS
        "C:/npcap-sdk-1.16/Lib/x64"
        "D:/npcap-sdk-1.16/Lib/x64"
        "$ENV{NPCAP_DIR}/Lib/x64"
    )

    find_library(PACKET_LIB
        NAMES Packet
        PATHS
        "C:/npcap-sdk-1.16/Lib/x64"
        "D:/npcap-sdk-1.16/Lib/x64"
        "$ENV{NPCAP_DIR}/Lib/x64"
    )

    # 检查是否找到
    if(NOT NPCAP_INCLUDE_DIR OR NOT WPCAP_LIB OR NOT PACKET_LIB)
        message(FATAL_ERROR "
        找不到 Npcap SDK！
        请下载 npcap-sdk-1.16，并放到 C:/ 或 D:/
        或者设置环境变量 NPCAP_DIR 指向 SDK 路径
        ")
    endif()

    # 加入头文件 & 库
    target_include_directories(GoldFish_CLI PRIVATE ${NPCAP_INCLUDE_DIR})
    target_link_libraries(GoldFish_CLI PRIVATE ${WPCAP_LIB} ${PACKET_LIB} ws2_32)

    set(INSTALL_DESTINATION "bin")

elseif(UNIX AND NOT APPLE)
    # WSL / Linux: libpcap
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)

    if(NOT PCAP_FOUND)
        message(FATAL_ERROR "请安装：sudo apt install libpcap-dev")
    endif()

    target_include_directories(GoldFish_CLI PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(GoldFish_CLI PRIVATE ${PCAP_LIBRARIES})
    set(INSTALL_DESTINATION "/opt/${PROJECT_NAME}/bin")
endif()


include(GNUInstallDirs)

install(TARGETS GoldFish_CLI
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
