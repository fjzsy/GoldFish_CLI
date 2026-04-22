#ifndef OTHERPACKETSTATS_H
#define OTHERPACKETSTATS_H

#include <QObject>

class OtherPacketStats
{
public:
    OtherPacketStats();

    // 计数
    uint64_t udpCount;      // 非RoCE UDP
    uint64_t tcpCount;
    uint64_t icmpCount;
    uint64_t arpCount;
    uint64_t otherCount;

    // 示例包（环形缓冲区，只存前N个）
    static const int MAX_SAMPLES = 10;
    struct Sample {
        uint32_t packetNumber;
        uint64_t timestamp;
        uint8_t protocol;      // IP协议号
        uint32_t srcIp;
        uint32_t dstIp;
        uint16_t srcPort;
        uint16_t dstPort;
        uint16_t etherType;
    } samples[MAX_SAMPLES];
    int sampleCount;

    // 处理一个非RoCEv2包
    void process(const uint8_t* data, uint32_t len, uint32_t packetNum, uint64_t ts);

private:
    void add_sample(uint32_t packetNum, uint64_t ts, uint8_t proto, const uint8_t* data);
};

#endif // OTHERPACKETSTATS_H
