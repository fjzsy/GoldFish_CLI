#ifndef STATISTICSHEADER_H
#define STATISTICSHEADER_H

#include <cstdint>
#include <cstring>
#include <map>

//*************************代码结构说明**************************/
// PcapStatistics
//     ├─ totalPackets, totalBytes, errors (基础)
//     ↓
//     IpStatistics
//     ├─ ipPackets, udpPackets, tcpPackets, icmpPackets (IP层)
//     ↓
//     UdpStatistics
//     ├─ rocev2Packets, udpOtherPackets, portStats (UDP细分)
//     ↓
//     RoceStatistics
//     ├─ opcodeStats, qpStats, psnStats, roceErrors (RDMA层)
//     ├─ totalRetrans, totalLost, totalOutOfOrder (流控指标)
//     ↓
//     AnalysisStatistics
//     ├─ avgPacketSize, lossRate, retransRate (综合指标)

#pragma pack(push,1)
struct PcapStatistics {
    // 基础统计（所有包）
    uint64_t totalPackets;
    uint64_t totalBytes;

    // 异常分类（所有包都可能）
    struct {
        uint32_t tooShort;            // 包太短 (<14)
        uint32_t ipHeaderTruncated;   // IP头不完整
        uint32_t udpHeaderTruncated;  // UDP头不完整
        uint32_t unknownEtherType;    // 未知以太网类型
        uint32_t unknownIpProtocol;   // 未知IP协议
        uint32_t pfcHeaderTruncated;  // PFC核心字段
        uint32_t malformed;           // 格式错误
        uint32_t analyzerNotSet;      // 分析空指针校验
        uint32_t aggregatorNotSet;    // 聚合统计空指针
    } errors;

    PcapStatistics() { reset(); }

    void reset() {
        totalPackets = 0;
        totalBytes = 0;
        memset(&errors, 0, sizeof(errors));
    }
};

struct IpStatistics : public PcapStatistics {
    // IP层基础
    uint64_t ipPackets;      // 所有IP包总数
    uint64_t ipBytes;        // 所有IP包字节数

    // IP协议分布
    uint64_t arpPackets;
    uint64_t arpBytes;

    uint64_t tcpPackets;
    uint64_t tcpBytes;

    uint64_t icmpPackets;
    uint64_t icmpBytes;

    // 预留流控字段（IP层）
    uint32_t ipFragments;    // IP分片包数
    uint32_t ipOptions;       // 带选项的IP包数

    //PFC 是链路层帧, 优先级流控(Priority Flow Control)
    uint32_t pfcPackets;
    uint32_t pfcBytes;

    struct {
        uint32_t ipHeaderTruncated;
        uint32_t unknownIpProtocol;
    } ipErrors;

    void reset() {
        PcapStatistics::reset();
        memset(&ipErrors, 0, sizeof(ipErrors));
        ipPackets = 0;
        ipBytes = 0;
        arpPackets = 0;
        arpBytes = 0;
        tcpPackets = 0;
        tcpBytes = 0;
        icmpPackets = 0;
        icmpBytes = 0;
        ipFragments = 0;
        ipOptions = 0;
        pfcPackets = 0;
        pfcBytes = 0;
    }
};

struct UdpStatistics : public IpStatistics {
    // UDP细分
    uint64_t rocev2Packets;    // RoCEv2 包数
    uint64_t rocev2Bytes;      // RoCEv2 字节数

    uint64_t udpOtherPackets;  // 非RoCE UDP
    uint64_t udpOtherBytes;

    // 按端口统计（流控用）
    std::map<uint16_t, uint64_t> portStats;  // 目的端口分布

    // UDP层错误（由上层解析器填充）
    uint32_t udpHeaderTruncated;  // UDP头不完整（覆盖基类同名错误）

    // 需要总UDP包数时，动态计算
    uint64_t getUdpPackets() const {
        return rocev2Packets + udpOtherPackets;
    }

    uint64_t getUdpBytes() const {
        return rocev2Bytes + udpOtherBytes;
    }

    void reset() {
        IpStatistics::reset();
        rocev2Packets = 0;
        rocev2Bytes = 0;
        udpOtherPackets = 0;
        udpOtherBytes = 0;
        portStats.clear();
        udpHeaderTruncated = 0;
    }
};

struct RoceStatistics : public UdpStatistics {
    // 按操作码统计
    std::map<uint32_t, std::map<uint8_t, uint64_t>> qpOpcodeStats;

    // 按QP统计
    std::map<uint32_t, uint64_t> qpStats;

    // 按PSN范围统计
    std::map<uint32_t, uint64_t> psnStats;  // 按PSN/1000分组

    // BTH层错误
    struct {
        uint32_t bthHeaderTruncated; // BTH头不完整
        uint32_t rethTruncated;      // RETH被截断
        uint32_t rethMalformed;      // RETH格式错误
        uint32_t immTruncated;       // 立即数被截断
        uint32_t atomicTruncated;    // 原子操作被截断
        uint32_t atomicAckTruncated; // 原子操作Ack被截断
        uint32_t dethTruncated;      // DETH被截断
        uint32_t iethTruncated;      // IETH被截断
        uint32_t malformed;          // 格式错误
        uint32_t packetTooShort;     // 数据包太短
    } roceErrors;

    // 流控相关（RDMA特有）
    uint64_t totalRetrans;        // 总重传次数
    uint64_t totalLost;           // 总丢包数
    uint64_t totalOutOfOrder;     // 总乱序包数

    // 多网口相关
    uint32_t icmpFromUnexpectedIf;  // ICMP从非预期网口来

    RoceStatistics() { reset(); }

    void reset() {
        UdpStatistics::reset();
        qpOpcodeStats.clear();
        qpStats.clear();
        psnStats.clear();
        memset(&roceErrors, 0, sizeof(roceErrors));
        totalRetrans = 0;
        totalLost = 0;
        totalOutOfOrder = 0;
        icmpFromUnexpectedIf = 0;
    }
};

struct AnalysisStatistics : public RoceStatistics {
    // 这里可以加一些综合指标
    double avgPacketSize;       // 平均包大小
    double avgRocePacketSize;   // 平均RoCE包大小
    double lossRate;            // 整体丢包率
    double retransRate;         // 整体重传率

    // 按时间段的统计（流控用）
    std::map<uint64_t, uint64_t> timeSeriesStats;  // 时间戳分组

    void reset() {
        RoceStatistics::reset();
        avgPacketSize = 0;
        avgRocePacketSize = 0;
        lossRate = 0;
        retransRate = 0;
        timeSeriesStats.clear();
    }

    // 计算派生指标
    void calculateDerived() {
        if (totalPackets > 0) {
            avgPacketSize = (double)totalBytes / totalPackets;
        }
        if (rocev2Packets > 0) {
            avgRocePacketSize = (double)rocev2Bytes / rocev2Packets;
        }
        // 丢包率、重传率由流聚合器计算
    }
};
#pragma pack(pop)
#endif // STATISTICSHEADER_H
