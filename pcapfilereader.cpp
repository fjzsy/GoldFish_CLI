#include "pcapfilereader.h"
#include <iostream>
#include <ostream>
#include <QDebug>

PcapFileReader::PcapFileReader(QObject *parent)
    : m_pcapHandle(nullptr),analyzer(nullptr)
{
   stats_.reset();
}

PcapFileReader::~PcapFileReader()
{
    close();
}

bool PcapFileReader::open(const std::string& filename)
{

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename.c_str(), errbuf);
    if (!pcap) {
        qDebug() << "Unable to open PCAP file: " << errbuf;
        return false;
    }

    //qDebug() << "成功打开PCAP文件: " << filename;
    m_pcapHandle = pcap;

    // 获取pcap文件信息
    int linkType = pcap_datalink(pcap);
    //qDebug() << "链路类型: ";
    // switch (linkType) {
    // case DLT_EN10MB: qDebug() << "以太网"; break;
    // case DLT_RAW: qDebug() << "原始IP"; break;
    // case DLT_LINUX_SLL: qDebug() << "Linux Cooked"; break;
    // default: qDebug()<< "未知 (" << linkType << ")"; break;
    // }

    return true;
}

void PcapFileReader::close()
{
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = nullptr;
    }
    stats_.reset();
}


QString PcapFileReader::getFileInfo() const
{
    if (!m_pcapHandle) {
        return "PCAP file not opened";
    }

    QString ss;

    // 获取pcap统计信息
    pcap_stat stats;
    if (pcap_stats(m_pcapHandle, &stats) == 0) {
        ss = "PCAP Statistics:\n";
        ss = ss + "  Packets received: " + QString("%1").arg(stats.ps_recv) + "\n";
        ss = ss + "  Packets dropped: " + QString("%1").arg(stats.ps_drop) + "\n";
        ss = ss + "  Interface dropped: " + QString("%1").arg(stats.ps_ifdrop) + "\n";
        qDebug() << ss;
    }

    return ss;
}

//统计全量,分析采样
bool PcapFileReader::readAllPackets()
{
    //std::vector<PacketInfo> packets;

    analyses.clear();

    if (!m_pcapHandle) {
        std::cerr << "PCAP file not opened" << std::endl;
        return false;
    }

    if(SAMPLE_RATE<=0) SAMPLE_RATE=1000;

    // 预分配空间，最大不超过100000，避免内存浪费
    uint32_t reserveSize = 100000 / SAMPLE_RATE;
    reserveSize = (reserveSize > 100000) ? 100000 : reserveSize;
    analyses.reserve(100000 / SAMPLE_RATE);  // 采样包预分配

    // 读取所有包
    struct pcap_pkthdr* header;
    const u_char* packetData;
    uint64_t packetNumber = 0;

    int perTime = 1;
    int count = 0;

    while (pcap_next_ex(m_pcapHandle, &header, &packetData) == 1) {

        ++packetNumber;

        // ============ 第1层：基础统计（PcapStatistics） ============
        stats_.totalPackets++;
        stats_.totalBytes += header->len; //流量统计、计费、性能评估

        // 基础长度检查
        if (header->caplen < 14) {
            stats_.errors.tooShort++;
            continue;
        }

        uint16_t ethType = (packetData[12] << 8) | packetData[13];
        int vlanOffset = 0;
        // 检测VLAN标签（EtherType=0x8100），带VLAN则偏移4字节
        if (ethType == 0x8100) {
            vlanOffset = 4;
            // 重新获取真实的EtherType（偏移后）
            ethType = (packetData[12 + vlanOffset] << 8) | packetData[13 + vlanOffset];
        }

        // ============ 第2层：IP层统计（IpStatistics） ============
        if (ethType == 0x0800) {  // IPv4
            if (header->caplen < 14 + vlanOffset + 20) {
                stats_.errors.ipHeaderTruncated++;
                continue;
            }

            uint8_t protocol = packetData[23 + vlanOffset];
            stats_.ipPackets++;
            stats_.ipBytes += header->len;

            // ============ 第3层：UDP层统计（UdpStatistics） ============
            if (protocol == 17) {  // UDP
                if (header->caplen < 42 + vlanOffset) {
                    stats_.errors.udpHeaderTruncated++;
                    continue;
                }

                uint16_t srcPort = (packetData[34 + vlanOffset] << 8) | packetData[35 + vlanOffset];
                uint16_t dstPort = (packetData[36 + vlanOffset] << 8) | packetData[37 + vlanOffset];
                // stats_.udpPackets++;
                // stats_.udpBytes += header->len;
                stats_.portStats[dstPort]++;

                // ============ 第4层：RoCE统计（RoceStatistics） ============
                if ((srcPort == 4791 || srcPort == 4790) || (dstPort == 4791 || dstPort == 4790)) {
                    stats_.rocev2Packets++;
                    stats_.rocev2Bytes += header->len;
                    PacketAnalysis analysis;

                    analysis.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 +
                                         header->ts.tv_usec;

                    analysis.isRoCEv2 = true;

                    // 只有RoCEv2包才深度解析，且按采样率
                    if (packetNumber % SAMPLE_RATE == 0) {
                        analysis.packetNumber = packetNumber;
                        // analysis.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 +
                        //                      header->ts.tv_usec;
                        analysis.capturedSize = header->caplen;
                        analysis.originalSize = header->len;
                        analysis.packetSize = analysis.originalSize;
                        analysis.rawData = packetData;
                        analysis.rawDataLen = header->caplen;

                        // 深度解析（会填充更详细的统计）
                        if (analyzer != nullptr) { // 新增空指针校验{
                            analyzer->analyzePacket(packetData, header->caplen, analysis, stats_, vlanOffset);
                            analyses.push_back(analysis);
                        }else{
                            stats_.errors.analyzerNotSet++; // 新增统计项，便于排查
                        }
                    }
                    else{
                        parseBasicFields(packetData, header->caplen, analysis, stats_, vlanOffset);
                    }

                    // 2. aggregator调用处（RoCEv2分支）
                    if (aggregator != nullptr) { // 空指针校验
                        aggregator->process_packet(analysis);
                    } else {
                        stats_.errors.aggregatorNotSet++; // 统计项，便于排查
                    }

                } else {
                    stats_.udpOtherPackets++;
                    stats_.udpOtherBytes += header->len;
                }
            }
            // ============ TCP统计 ============
            else if (protocol == 6) {
                stats_.tcpPackets++;
                stats_.tcpBytes += header->len;
            }
            // ============ ICMP统计 ============
            else if (protocol == 1) {
                stats_.icmpPackets++;
                stats_.icmpBytes += header->len;
            } else {
                stats_.errors.unknownIpProtocol++;
            }
        }
        // ============ ARP统计 ============
        else if (ethType == 0x0806) {
            stats_.arpPackets++;
            stats_.arpBytes += header->len;
        }
        // ============ PFC统计 ============
        else if (ethType == 0x8808) {
            stats_.pfcPackets++;
            stats_.pfcBytes += header->len;

            // ==============================
            // 1. 自动计算 VLAN 偏移（兼容所有VLAN场景，永不硬编码）
            // ==============================
            const uint8_t* ethBasePtr = packetData;
            uint32_t vlanTotalOffset = 14;  // 以太网固定头 14字节起始

            // 循环识别 VLAN 标签(0x8100)、双层QinQ(0x88A8)，自动累加偏移
            uint16_t nextEthType = ntohs(*reinterpret_cast<const uint16_t*>(ethBasePtr + 12));
            while (nextEthType == 0x8100 || nextEthType == 0x88A8)
            {
                vlanTotalOffset += 4;
                nextEthType = ntohs(*reinterpret_cast<const uint16_t*>(ethBasePtr + 12 + vlanTotalOffset - 4));
            }

            // 定位到流控帧纯载荷区域（跳过所有以太网头+所有VLAN标签）
            const uint8_t* pausePayload = ethBasePtr + vlanTotalOffset;
            uint32_t payloadRemainLen = header->caplen - vlanTotalOffset;

            // ==============================
            // 2. 载荷最小长度防越界校验（标准802.1Qbb最小载荷8字节）
            // ==============================
            if (payloadRemainLen < 2)
            {
                stats_.errors.pfcHeaderTruncated++;
                continue;
            }

            // ==============================
            // 3. 解析帧类型 Opcode（网络大端，统一 ntohs 转换）
            // ==============================
            uint16_t frameOpcode = ntohs(*reinterpret_cast<const uint16_t*>(pausePayload));

            // ==============================
            // 按帧类型做长度检查（真正的工业级标准）
            // ==============================
            bool validLength = false;
            if (frameOpcode == PAUSE_OPCODE) {
                validLength = (payloadRemainLen >= 4);  // 全局 PAUSE = 4字节
            } else if (frameOpcode == PFC_OPCODE) {
                validLength = (payloadRemainLen >= 8);  // PFC 帧 = 8字节
            }

            if (!validLength) {
                stats_.errors.pfcHeaderTruncated++;
                continue;
            }

            // ==============================
            // 4. 初始化 PFC/PAUSE 分析结构 时间戳 标准微秒转换（C++ static_cast 安全强转，1000000 微秒基准）
            // ==============================
            PacketAnalysis pfcAnalysis{};
            pfcAnalysis.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 + header->ts.tv_usec;

            // 默认初始化标记
            pfcAnalysis.isPause = false;
            pfcAnalysis.isPFC = false;
            pfcAnalysis.pfcClassEnableMask = 0;
            pfcAnalysis.pfcPauseTime = 0;
            pfcAnalysis.pfc_priority = 0xFF;

            // ==============================
            // 5. 分支解析：普通全局 PAUSE 帧
            // ==============================
            if (frameOpcode == PAUSE_OPCODE)
            {
                pfcAnalysis.isPause = true;
                pfcAnalysis.isPFC = false;

                pfcAnalysis.pfc_priority = 0xFF;

            }
            // ==============================
            // 6. 分支解析：802.1Qbb PFC 优先级流控帧
            // 格式：Opcode(2) + Reserved(1) + EnableMask(1) + PauseTime[8个优先级](各2字节)
            // ==============================
            else if (frameOpcode == PFC_OPCODE)
            {
                pfcAnalysis.isPause = true;
                pfcAnalysis.isPFC = true;

                // 第4字节：优先级使能掩码
                // 解析优先级掩码
                uint8_t enable_vector = pausePayload[3];
                pfcAnalysis.pfcClassEnableMask = enable_vector;

                // 偏移+4 取16位暂停时间，网络字节序安全转换 ntohs
                pfcAnalysis.pfcPauseTime = ntohs(*reinterpret_cast<const uint16_t*>(pausePayload + 4));

                // 解析第一个被暂停的优先级（0~7）
                pfcAnalysis.pfc_priority = 0xFF;   // 默认无效
                for (int prio = 0; prio < 8; ++prio)
                {
                    if (enable_vector & (1 << prio))
                    {
                        pfcAnalysis.pfc_priority = prio;
                        break;
                    }
                }
            }

            //7. 关联到聚合器，用于后续时序图联动
            if (aggregator != nullptr) { // 空指针校验
                aggregator->process_packet(pfcAnalysis);
            } else {
                stats_.errors.aggregatorNotSet++;
            }
        }
        else {
            stats_.errors.unknownEtherType++;
        }

        // 进度条控制
        count++;
        if(count > 10000 && perTime < 10){
            emit sigPkParseProc(perTime * 10);
            perTime++;
            count = 0;
        }
    }

    emit sigPkParseProc(100);//进度条显示100%

    //std::cout << "读取完成: 总包数=" << stats_.totalPackets
    //          << " (采样率 1:" << SAMPLE_RATE << ")" << std::endl;
    return true;
}

void PcapFileReader::parseBasicFields(const uint8_t *data, uint32_t length,
                                      PacketInfo &analy,
                                      AnalysisStatistics& stats,
                                      int vlanOffset)
{
     // 1. 长度检查（防御性编程）
    if (length < 54  + vlanOffset) {  // 以太网14 + IP20 + UDP8 + BTH12 = 54
        stats.roceErrors.packetTooShort++;
        return;  // 太小的包已经被过滤，这里只是二次确认
    }


    // 2. 取 IP 头长度（固定偏移 14）
    uint32_t ipOffset = 14 + vlanOffset;
    analy.ip.headerLen = (data[ipOffset] & 0x0F) * 4;
    analy.ip.srcIp = EthernetParser::getU32(data, ipOffset  + 12);
    analy.ip.dstIp = EthernetParser::getU32(data, ipOffset  + 16);

    // 3. UDP 头
    uint32_t udpOffset = ipOffset + analy.ip.headerLen;
    analy.udp.srcPort = EthernetParser::getU16(data, udpOffset);
    analy.udp.dstPort = EthernetParser::getU16(data, udpOffset + 2);

    // 4. BTH 头位置
    uint32_t bthOffset = udpOffset + 8;

    // 5. 边界检查（确保 BTH 完整）
    if (bthOffset + 11 >= length) {
        stats.roceErrors.bthHeaderTruncated++;
        return;
    }

    // 5. 取操作码
    analy.bth.opcode = data[bthOffset];

    // 6. 取 QP Num (24位)
    analy.bth.qpNum = EthernetParser::getU24(data, bthOffset + 5);

    // 7. 取 PSN (24位)
    analy.bth.psn = EthernetParser::getU24(data, bthOffset + 9);

    // 8.全量统计
    stats.qpOpcodeStats[analy.bth.qpNum][analy.bth.opcode]++;
    stats.qpStats[analy.bth.qpNum]++;
    stats.psnStats[analy.bth.psn / 1000]++;
}

void PcapFileReader::readPackets(std::function<void (const PacketInfo &)> callback)
{
    if (!m_pcapHandle) {
        std::cerr << "PCAP文件未打开" << std::endl;
        return;
    }

    // 使用回调函数处理每个包
    struct CallbackData {
        uint64_t packetNumber;
        std::function<void(const PacketInfo&)> callback;
        PcapStatistics* stats;
    };

    CallbackData cbData{0, callback, &stats_};

    // 读取并处理包
    struct pcap_pkthdr* header;
    const u_char* packetData;

    while (pcap_next_ex(m_pcapHandle, &header, &packetData) == 1) {
        PacketInfo pkt;
        pkt.packetNumber = ++cbData.packetNumber;
        pkt.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 +
                        header->ts.tv_usec;
        pkt.capturedSize = header->caplen;
        pkt.originalSize = header->len;
       // pkt.data.assign(packetData, packetData + header->caplen);

        // 调用回调函数
        callback(pkt);

        // 更新统计
        stats_.totalPackets++;
        stats_.totalBytes += header->caplen;
    }
}

std::vector<PacketInfo> PcapFileReader::readRoCEv2Packets()
{
    std::vector<PacketInfo> rocev2Packets;

    if (!m_pcapHandle) {
        return rocev2Packets;
    }

    struct pcap_pkthdr* header;
    const u_char* packetData;
    uint64_t packetNumber = 0;

    while (pcap_next_ex(m_pcapHandle, &header, &packetData) == 1) {
        packetNumber++;

        // 只处理RoCEv2包
        if (isRoCEv2Packet(packetData, header->caplen)) {
            PacketInfo pkt;
            pkt.packetNumber = packetNumber;
            pkt.timestamp = static_cast<uint64_t>(header->ts.tv_sec) * 1000000 +
                            header->ts.tv_usec;
            pkt.capturedSize = header->caplen;
            pkt.originalSize = header->len;
            //pkt.data.assign(packetData, packetData + header->caplen);

            rocev2Packets.push_back(pkt);
            stats_.rocev2Packets++;
        }
    }

    std::cout << "Found  " << rocev2Packets.size() << " RoCEv2 packets" << std::endl;
    return rocev2Packets;
}

void PcapFileReader::setAnalyzer(PacketAnalyzerEngine *newAnalyzer)
{
    analyzer = newAnalyzer;
}

void PcapFileReader::setAggregator(FlowAggregator *newAggregator)
{
    aggregator = newAggregator;
}

void PcapFileReader::setSAMPLE_RATE(uint32_t newSAMPLE_RATE)
{
    SAMPLE_RATE = (newSAMPLE_RATE > 0) ? newSAMPLE_RATE : 1000;
}

bool PcapFileReader::isRoCEv2Packet(const uint8_t *data, uint32_t length) const
{
    if (length < 42) {  // 以太网头(14) + IP头(20) + UDP头(8) = 42字节
        return false;
    }

    // 检查以太网类型是否为IPv4 (0x0800)
    if (data[12] != 0x08 || data[13] != 0x00) {
        return false;
    }

    uint16_t ethType = (data[12] << 8) | data[13];
    int vlanOffset = 0;
    // 检测VLAN标签（EtherType=0x8100），带VLAN则偏移4字节
    if (ethType == 0x8100) {
        vlanOffset = 4;
        // 重新获取真实的EtherType（偏移后）
        ethType = (data[12 + vlanOffset] << 8) | data[13 + vlanOffset];
        // 带VLAN时，最小长度需增加4字节
        if (length < 42 + vlanOffset) {
            return false;
        }
    }

    // 检查以太网类型是否为IPv4 (0x0800)
    if (ethType != 0x0800) {
        return false;
    }

    // 检查IP协议是否为UDP (0x11)
    if (data[23 + vlanOffset] != 0x11) {
        return false;
    }

    // 检查UDP端口（RoCEv2端口 4791/4790），UDP头偏移 = 14 + vlanOffset + 20（IP头最小长度）
    uint32_t udpOffset = 14 + vlanOffset + 20;
    uint16_t srcPort = (data[udpOffset] << 8) | data[udpOffset + 1];
    uint16_t dstPort = (data[udpOffset + 2] << 8) | data[udpOffset + 3];

    // 补充源端口判断，覆盖双向报文（如CNP反向发送）
    return (srcPort == 4791 || srcPort == 4790 || dstPort == 4791 || dstPort == 4790);
}
