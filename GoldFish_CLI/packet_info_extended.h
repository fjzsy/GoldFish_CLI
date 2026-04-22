#ifndef PACKET_INFO_EXTENDED_H
#define PACKET_INFO_EXTENDED_H

// packet_info_extended.h
#pragma once

#include <cstring>
#include <string>
#include <cstdint>

#pragma pack(push, 1)

// 先加宏定义
#define ETHERTYPE_FLOW_CONTROL 0x8808
#define PFC_OPCODE 0x0101
#define PAUSE_OPCODE 0x0001


// 前向声明
class OpcodeClassifier;

enum PacketType {
    TYPE_ROCEV2,
    TYPE_UDP,
    TYPE_TCP,
    TYPE_ICMP,
    TYPE_ARP,
    TYPE_PFC,  // Pause Frame，用于流控
    TYPE_OTHER
};

struct PacketInfo {
    // 基础信息
    uint32_t packetNumber;   // 包的序号
    uint64_t timestamp;      // 时间戳
    uint32_t packetSize;     // 包大小 兼容旧代码或特殊需求
    uint32_t capturedSize;   // 捕获大小 边界检查、解析安全
    uint32_t originalSize;   // 原始大小 流量统计、计费、性能评估
    const uint8_t* rawData;  // 原始数据
    uint32_t rawDataLen;     // 原始数据长度

    // 各层头部信息
    struct EthernetInfo {
        uint64_t  srcMac;
        uint64_t  dstMac;
        uint16_t etherType;
    } ethernet;

    struct IpInfo {
        uint32_t  srcIp;
        uint32_t  dstIp;
        uint8_t protocol;
        uint8_t version;
        uint8_t headerLen;
        uint16_t totalLength;
        uint8_t ttl;
        uint8_t tos;
        uint16_t checksum;
    } ip;

    struct UdpInfo {
        uint16_t srcPort;
        uint16_t dstPort;
        uint16_t length;
        uint16_t checksum;
    } udp;

    // RoCEv2 基础信息
    struct BthInfo {
        uint8_t opcode;
        uint8_t baseOpcode;

        // 所有标志位（用位域）放在一个16位单元
        uint16_t solicited : 1;
        uint16_t migReq    : 1;
        uint16_t fecn      : 1;
        uint16_t becn      : 1;
        uint16_t dqpn      : 1;
        uint16_t ackReq    : 1;
        uint16_t reserved  : 10;  // 剩余10位填充
        uint8_t padCount;  //填充字节数，其目的是确保数据部分从 4字节边界 开始，以满足内存对齐
        uint8_t version;
        uint16_t pkey;
        uint32_t qpNum;
        uint32_t psn;
        uint8_t retryCnt;  //重发次数
    } bth;

    // 标记当前用了哪个成员
    enum { EXT_NONE, EXT_RETH, EXT_ATOMIC, EXT_IMM, EXT_ATOMIC_ACK, EXT_DETH, EXT_IETH } extType;

    // RDMA扩展头部信息（根据操作码不同）
    union RdmaExtendedHeaders {
        // RDMA操作（Write/Read）
        struct RethInfo {
            uint64_t virtualAddress;
            uint32_t rkey;
            uint32_t dmaLength;
        } reth;

        // 原子操作（CMP_SWP / FETCH_ADD）
        struct AtomicInfo {
            uint64_t virtualAddress;
            uint32_t rkey;
            uint64_t swapData;
            uint64_t compareData;
        } atomic;

        // 原子操作确认
        struct AtomicAckInfo {
            uint64_t originalData;
        } atomicAck;

        uint32_t immediateData;// 立即数（SEND_LAST_IMM / SEND_ONLY_IMM 等）

        // ⭐ DETH - Datagram Extended Transport Header（用于UD服务）
        struct DethInfo {
            uint32_t qkey; // 队列对密钥（类似于PKey，但用于UD）
            uint32_t sourceQpn; // 源QP号（UD模式需要知道来源）
        } deth;

        // ⭐ IETH - Invalidate Extended Transport Header（用于远程失效）
        struct IethInfo {
            uint32_t rkey;  // 要失效的RKey
        } ieth;

        // 为了对齐到最大成员（通常是AtomicInfo，32字节）
        uint8_t padding[32];

    } rdmaExt;

    // ==========================
    // 🔥 时序分析信息（直接内嵌）
    // ==========================
    struct TimelineMetrics
    {
        int64_t interval_us;     // 与上一包间隔
        int64_t delay_us;        // 单向时延
        int64_t rtt_us;          // 往返时延
        int64_t jitter_us;       // 抖动

        bool    is_abnormal;     // 是否异常
        char    abnormal_type[32];// 异常类型（不用string，避免跨平台/内存问题）
        char    abnormal_desc[128];// 异常描述
        uint8_t reserved[2];     // 对齐

        uint64_t flow_hash;      // 流哈希key（代替string，高性能）
        uint32_t packet_index;   // 包索引（跳转详情）
    } timeline;

    // 负载数据
    struct PayloadInfo {
        const uint8_t* data;      // 指向负载
        uint32_t length;          // 负载长度
        uint32_t offset;          // 在完整消息中的偏移
        bool isFirst;             // 是否是第一个分段
        bool isMiddle;            // 是否是中间分段
        bool isLast;              // 是否是最后分段
        bool hasPayload;          // 是否有负载数据
    } payload;


    // 元数据
    bool isRoCEv2;
    bool isValid;
    std::string errorMessage;

    // 辅助方法
    std::string getOpcodeString() const;
    uint32_t getTotalHeaderSize() const;
    bool hasImmediateData() const;

    PacketInfo() {
        reset();
    }

    void reset() {
        packetNumber = 0;
        timestamp = 0;
        packetSize = 0;
        capturedSize = 0;
        originalSize = 0;
        rawData = nullptr;
        rawDataLen = 0;

        isRoCEv2 = false;
        isValid = false;
        errorMessage.clear();

        // 初始化-清零各层
        memset(&ethernet, 0, sizeof(ethernet));
        memset(&ip, 0, sizeof(ip));
        memset(&udp, 0, sizeof(udp));
        memset(&bth, 0, sizeof(bth));
        memset(&rdmaExt, 0, sizeof(rdmaExt));
        memset(&timeline, 0, sizeof(timeline));

        // 初始化负载信息
        payload.data = nullptr;
        payload.length = 0;
        payload.offset = 0;
        payload.isFirst = false;
        payload.isMiddle = false;
        payload.isLast = false;
        payload.hasPayload = false;
    }
};

#pragma pack(pop)

#endif // PACKET_INFO_EXTENDED_H
