#ifndef PSNCHARTHEADER_H
#define PSNCHARTHEADER_H
#include <QColor>
#include <QPointF>
#include <QVector>
#include <QHostAddress>


#define WAVE_MARGIN_LEFT		10	// 绘图时坐标轴距离最外边缘的边距
#define WAVE_MARGIN_RIGHT		10	// 绘图时坐标轴距离最外边缘的边距
#define WAVE_MARGIN_TOP			10	// 绘图时坐标轴距离最外边缘的边距
#define WAVE_MARGIN_BOTTOM		10	// 绘图时坐标轴距离最外边缘的边距

const int margin = 40;
const double MAX_REASONABLE_TIME = 1000.0;  //1000 毫秒

struct FlowKey {
    uint32_t srcIp = 0;          // 源IP（网络字节序）
    uint32_t dstIp = 0;          // 目的IP（网络字节序）
    uint16_t srcPort = 0;         // 源端口
    uint16_t dstPort = 0;         // 目的端口（SMBDirect固定4791）
    uint32_t qpNum = 0;           // Queue Pair号
    uint32_t expectedIfIndex = 0;  // 预期接口索引（用于多路径）

    // 操作码 - 区分同一QP内的消息类型
    // 0x00: SEND_FIRST (数据开始)
    // 0x02: SEND_LAST (数据结束)
    // 0x04: SEND_ONLY (控制消息)
    // 0x11: RDMA_READ_RESP_FIRST (数据响应)
    uint8_t opcode = 0;

    // 消息方向 - 区分发送/接收
    enum Direction {
        DIRECTION_UNKNOWN,
        DIRECTION_SEND,    // 本端发送
        DIRECTION_RECV     // 本端接收
    } direction = DIRECTION_UNKNOWN;

    // 便捷构造函数
    FlowKey() = default;

    FlowKey(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
            uint32_t qp, uint8_t op, Direction dir)
        : srcIp(src), dstIp(dst), srcPort(sport), dstPort(dport),
        qpNum(qp), opcode(op), direction(dir), expectedIfIndex(0) {}

    bool operator==(const FlowKey& other) const {
        return srcIp == other.srcIp &&
               dstIp == other.dstIp &&
               srcPort == other.srcPort &&
               dstPort == other.dstPort &&
               qpNum == other.qpNum &&
               opcode == other.opcode &&
               direction == other.direction &&
               expectedIfIndex == other.expectedIfIndex;
    }

    // 生成用于报表的键值字符串
    QString toKeyString() const {
        return QString("%1:%2-%3:%4-QP%5-op%6-%7")
        .arg(QHostAddress(srcIp).toString()).arg(srcPort)
            .arg(QHostAddress(dstIp).toString()).arg(dstPort)
            .arg(qpNum)
            .arg(opcode, 2, 16, QChar('0'))
            .arg(direction == DIRECTION_SEND ? "SEND" :
                     direction == DIRECTION_RECV ? "RECV" : "UNK");
    }
};


// 为FlowKey提供qHash函数，以便用作QMap/QHash的键
// inline uint qHash(const FlowKey &key, uint seed) {
//     // 组合所有字段的哈希值
//     QtPrivate::QHashCombine hash;
//     seed = hash(seed, key.srcIp);
//     seed = hash(seed, key.dstIp);
//     seed = hash(seed, key.srcPort);
//     seed = hash(seed, key.dstPort);
//     seed = hash(seed, key.qpNum);
//     seed = hash(seed, key.opcode);        // ✅ 包含opcode
//     seed = hash(seed, key.direction);      // ✅ 包含direction
//     return seed;
// }

namespace std {
template<> struct hash<FlowKey> {
    size_t operator()(const FlowKey& k) const {
        size_t seed = 0;

        auto hash_uint32 = std::hash<uint32_t>{};
        auto hash_uint16 = std::hash<uint16_t>{};

        seed ^= hash_uint32(k.srcIp) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint32(k.dstIp) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint16(k.srcPort) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint16(k.dstPort) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint32(k.qpNum) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint32(k.opcode) + 0x9e3779b9 + (seed<<6) + (seed>>2);
        seed ^= hash_uint32(k.direction) + 0x9e3779b9 + (seed<<6) + (seed>>2);

        return seed;
    }
};
}


struct QpCurve {
    FlowKey qpNum;
    QVector<QPointF> points;
    QColor color;

    double minTime;
    double maxTime;
    uint32_t minPsn;
    uint32_t maxPsn;

    QpCurve()
        : qpNum()
        , minTime(1e9)
        , maxTime(-1e9)
        , minPsn(0xFFFFFFFF)
        , maxPsn(0) {}

    void addPoint(double relTime, uint32_t relPsn) {
        points.push_back({relTime, static_cast<qreal>(relPsn)});

        // 同时更新范围
        if (relTime < minTime) minTime = relTime;
        if (relTime > maxTime) maxTime = relTime;
        if (relPsn < minPsn) minPsn = relPsn;
        if (relPsn > maxPsn) maxPsn = relPsn;
    }
};

struct QpState {
    uint64_t firstTime;      // 该 QP 第一个包的时间戳
    uint32_t firstPsn;       // 该 QP 第一个包的 PSN
    QpCurve curve;  // 直接用 QpCurve 存数据
};

struct LineInfo {
    QString name;
    QColor color;
    int packetCount;
};

// 内联函数：Opcode转字符串
inline QString opcodeToString(uint8_t opcode) {
    switch(opcode) {
    // Send 操作 (0x00-0x05)
    case 0x00: return "SEND_FIRST";
    case 0x01: return "SEND_MIDDLE";
    case 0x02: return "SEND_LAST";
    case 0x03: return "SEND_LAST_IMM";
    case 0x04: return "SEND_ONLY";
    case 0x05: return "SEND_ONLY_IMM";

    // RDMA Write 操作 (0x06-0x0B)
    case 0x06: return "RDMA_WRITE_FIRST";
    case 0x07: return "RDMA_WRITE_MIDDLE";
    case 0x08: return "RDMA_WRITE_LAST";
    case 0x09: return "RDMA_WRITE_LAST_IMM";
    case 0x0A: return "RDMA_WRITE_ONLY";
    case 0x0B: return "RDMA_WRITE_ONLY_IMM";

    // RDMA Read 操作 (0x10-0x14)
    case 0x10: return "RDMA_READ_REQ";
    case 0x11: return "RDMA_READ_RESP_FIRST";
    case 0x12: return "RDMA_READ_RESP_MIDDLE";
    case 0x13: return "RDMA_READ_RESP_LAST";
    case 0x14: return "RDMA_READ_RESP_ONLY";

    // ACK 操作 (0x60-0x61)
    case 0x60: return "ACK";
    case 0x61: return "ATOMIC_ACK";

    // CNP 操作 (0x81)
    case 0x81: return "CNP";

    // Atomic 操作 (0x90-0x91)
    case 0x90: return "ATOMIC_CMP_SWP";
    case 0x91: return "ATOMIC_FETCH_ADD";

    default: return QString("UNKNOWN (0x%1)").arg(opcode, 2, 16, QChar('0'));
    }
}
#endif // PSNCHARTHEADER_H
