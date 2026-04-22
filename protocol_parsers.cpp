// protocol_parsers.cpp
#include "protocol_parser_factory.h"
#include "qobject.h"
#include <sstream>
#include <iomanip>
#include <pcap.h>

// === EthernetParser 实现 ===
bool EthernetParser::parse(const uint8_t* data, uint32_t length,
                           PacketAnalysis& analysis, uint32_t offset) {
    if (length - offset < 14) {
        return false;
    }

    ProtocolLayer layer;
    layer.name = "Ethernet";
    layer.startOffset = offset;
    layer.length = 14;
    layer.description = "以太网帧头";

    // 目的MAC地址
    // uint64_t srcMac = getMac(data, offset);
    // layer.addField("Destination MAC", dstMac, offset, 6, "目的MAC地址");

    // // 源MAC地址
    // std::string srcMac = extractMacAddress(data, offset + 6);
    // layer.addField("Source MAC", srcMac, offset + 6, 6, "源MAC地址");

    // 以太网类型
    uint16_t etherType = extractUint16(data, offset + 12);
    std::string etherTypeStr;
    switch (etherType) {
    case 0x0800: etherTypeStr = "IPv4 (0x0800)"; break;
    case 0x0806: etherTypeStr = "ARP (0x0806)"; break;
    case 0x86DD: etherTypeStr = "IPv6 (0x86DD)"; break;
    case 0x8915: etherTypeStr = "RoCEv2 (0x8915)"; break; // 实际上RoCEv2在UDP中
    default:
        etherTypeStr = "Unknown (0x" +
                       std::to_string(etherType) + ")";
        break;
    }
    layer.addField("EtherType", etherTypeStr, offset + 12, 2,
                   "上层协议类型");

    // 生成十六进制转储
    //layer.hexDump = generateHexDump(data + offset, 14);

    analysis.layers.push_back(layer);
    return true;
}


// === IPv4Parser 实现 ===
bool IPv4Parser::parse(const uint8_t* data, uint32_t length,
                       PacketAnalysis& analysis, uint32_t offset)
{
    QString tt="";

    if (length - offset < 20) {
        return false;
    }

    ProtocolLayer layer;
    layer.name = "IPv4";
    layer.startOffset = offset;

    // 版本和头部长度
    uint8_t versionAndIhl = data[offset];
    uint8_t version = versionAndIhl >> 4;
    uint8_t ihl = (versionAndIhl & 0x0F) * 4;
    layer.length = ihl;

    if (version != 4) {
        return false;
    }

    layer.description = "IPv4 数据包头";

    // 版本和头部长度
    layer.addField("Version", std::to_string(version), offset, 0.5, "IP版本");
    layer.addField("IHL", std::to_string(ihl) + " bytes", offset, 0.5, "头部长度");

    // DSCP和ECN
    uint8_t dscpEcn = data[offset + 1];
    uint8_t dscp = dscpEcn >> 2;
    uint8_t ecn = dscpEcn & 0x03;
    layer.addField("DSCP", std::to_string(dscp), offset + 1, 1, "差分服务代码点");
    layer.addField("ECN", std::to_string(ecn), offset + 1, 1, "显式拥塞通知");

    // 总长度
    uint16_t totalLength = extractUint16(data, offset + 2);
    layer.addField("Total Length", std::to_string(totalLength) + " bytes",
                   offset + 2, 2, "总长度");

    // 标识符
    uint16_t identification = extractUint16(data, offset + 4);
    tt = QString::asprintf("%d", identification);
    layer.addField("Identification", "0x" + tt.toStdString(),
                   offset + 4, 2, "标识符");

    // 标志和片偏移
    uint16_t flagsAndOffset = extractUint16(data, offset + 6);
    bool df = (flagsAndOffset & 0x4000) != 0;  // Don't Fragment
    bool mf = (flagsAndOffset & 0x2000) != 0;  // More Fragments
    uint16_t fragmentOffset = flagsAndOffset & 0x1FFF;

    QString flagsStr = df ? "DF " : "";
    tt = mf ? "MF" : "";
    flagsStr.append(tt);
    layer.addField("Flags", flagsStr.toStdString(), offset + 6, 2, "标志位");
    layer.addField("Fragment Offset", std::to_string(fragmentOffset),
                   offset + 6, 2, "片偏移");

    // TTL
    uint8_t ttl = data[offset + 8];
    layer.addField("TTL", std::to_string(ttl), offset + 8, 1, "生存时间");

    // 协议
    uint8_t protocol = data[offset + 9];
    std::string protocolStr;
    switch (protocol) {
    case 1: protocolStr = "ICMP (1)"; break;
    case 6: protocolStr = "TCP (6)"; break;
    case 17: protocolStr = "UDP (17)"; break;
    case 132: protocolStr = "SCTP (132)"; break;
    default: protocolStr = "Unknown (" + std::to_string(protocol) + ")"; break;
    }
    layer.addField("Protocol", protocolStr, offset + 9, 1, "上层协议");

    // 头部校验和
    uint16_t checksum = extractUint16(data, offset + 10);
    tt = QString::asprintf("%0x", checksum);
    layer.addField("Header Checksum", "0x" + tt.toStdString(),
                   offset + 10, 2, "头部校验和");

    // 源IP地址
    std::string srcIp = extractIpAddress(data, offset + 12);
    layer.addField("Source IP", srcIp, offset + 12, 4, "源IP地址");

    // 目的IP地址
    std::string dstIp = extractIpAddress(data, offset + 16);
    layer.addField("Destination IP", dstIp, offset + 16, 4, "目的IP地址");

    // 生成十六进制转储
    //layer.hexDump = generateHexDump(data + offset, ihl);

    analysis.layers.push_back(layer);
    return true;
}

bool UDPParser::parse(const uint8_t* data, uint32_t length,
                      PacketAnalysis& analysis, uint32_t offset) {
    if (length - offset < 8) {
        return false;
    }

    ProtocolLayer layer;
    layer.name = "UDP";
    layer.startOffset = offset;
    layer.length = 8;
    layer.description = "User Datagram Protocol Header";

    // 源端口
    uint16_t srcPort = extractUint16(data, offset);
    layer.addField("Source Port", std::to_string(srcPort), offset, 2, "源端口");

    // 目的端口
    uint16_t dstPort = extractUint16(data, offset + 2);
    std::string dstPortStr = std::to_string(dstPort);
    layer.addField("Dest Port", dstPortStr, offset + 2, 2, "目的端口");

    // 长度
    uint16_t udpLength = extractUint16(data, offset + 4);
    layer.addField("Length", std::to_string(udpLength) + " bytes",
                   offset + 4, 2, "UDP数据报长度");

    // 校验和
    uint16_t checksum = extractUint16(data, offset + 6);
    //layer.addField("Checksum", "0x" + HexUtils::toHex(checksum, 4),
    //               offset + 6, 2, "校验和");

    // 检查是否为RoCEv2端口
    if (dstPort == 4791 || dstPort == 4790) {
        layer.addField("RoCEv2", "Yes", offset + 2, 2, "RoCEv2协议端口");
    }

    // 使用正确的函数名 generateHexDump
    //layer.hexDump = generateHexDump(data + offset, 8);
    analysis.layers.push_back(layer);
    return true;
}

// === BTHParser 实现 ===
bool BTHParser::parse(const uint8_t* data, uint32_t length,
                      PacketAnalysis& analysis, uint32_t offset)
{
    if (length - offset < 12) {
        return false;
    }

    ProtocolLayer layer;
    layer.name = "BTH";
    layer.startOffset = offset;
    layer.length = 12;
    layer.description = "Base Transport Header";

    // 操作码
    uint8_t opcode = data[offset];
    uint8_t baseOpcode = opcode & 0x1F;
    uint8_t opcodeClass = (opcode >> 5) & 0x07;

    std::string opcodeName = getOpcodeName(opcode);
    QString tt = QString::asprintf("%0x", opcode);
    layer.addField("Opcode", opcodeName + " (0x" + tt.toStdString() + ")",
                   offset, 1, getOpcodeDescription(opcode));

    // S、M、PadCount、Version
    uint8_t flags = data[offset + 1];
    bool solicited = (flags & 0x80) != 0;
    bool migReq = (flags & 0x40) != 0;
    uint8_t padCount = (flags >> 4) & 0x03;
    uint8_t version = flags & 0x0F;

    layer.addField("S (Solicited)", solicited ? "Yes" : "No",
                   offset + 1, 1, "请求标志");
    layer.addField("M (MigReq)", migReq ? "Yes" : "No",
                   offset + 1, 1, "迁移请求");
    layer.addField("Pad Count", std::to_string(padCount),
                   offset + 1, 1, "填充字节数");
    layer.addField("Version", std::to_string(version),
                   offset + 1, 1, "BTH版本");

    // Partition Key
    uint16_t pkey = extractUint16(data, offset + 2);
    tt = QString::asprintf("%0x", pkey);
    layer.addField("Partition Key", "0x" + tt.toStdString(),
                   offset + 2, 2, "分区密钥");

    // FECN、BECN、Resv6、DQPN
    uint8_t fecnBecn = data[offset + 4];
    bool fecn = (fecnBecn & 0x80) != 0;
    bool becn = (fecnBecn & 0x40) != 0;
    bool dqpn = (fecnBecn & 0x08) != 0;

    layer.addField("FECN", fecn ? "Yes" : "No",
                   offset + 4, 1, "前向显式拥塞通知");
    layer.addField("BECN", becn ? "Yes" : "No",
                   offset + 4, 1, "后向显式拥塞通知");
    layer.addField("DQPN", dqpn ? "Yes" : "No",
                   offset + 4, 1, "目的地QP号有效");

    // QP Number (24位)
    uint32_t qpNum = extractUint24(data, offset + 5);
    layer.addField("QP Number", std::to_string(qpNum),
                   offset + 5, 3, "队列对编号");

    // A位
    bool ackReq = (data[offset + 8] & 0x80) != 0;
    layer.addField("A (AckReq)", ackReq ? "Yes" : "No",
                   offset + 8, 1, "确认请求");

    // PSN (24位)
    uint32_t psn = extractUint24(data, offset + 9);
    layer.addField("PSN", std::to_string(psn),
                   offset + 9, 3, "包序列号");

    // 标记为RoCEv2包
    analysis.isRoCEv2 = true;

    //layer.hexDump = generateHexDump(data + offset, 12);
    analysis.layers.push_back(layer);

    return true;
}

bool RETHParser::parse(const uint8_t* data, uint32_t length,
                       PacketAnalysis& analysis, uint32_t offset) {
    if (length - offset < 16) {
        return false;
    }

    ProtocolLayer layer;
    layer.name = "RETH";
    layer.startOffset = offset;
    layer.length = 16;
    layer.description = "RDMA Extended Transport Header";

    // 虚拟地址（64位）
    uint32_t vaHigh = extractUint32(data, offset);
    uint32_t vaLow = extractUint32(data, offset + 4);
    uint64_t virtualAddr = (static_cast<uint64_t>(vaHigh) << 32) | vaLow;

    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(16) << std::setfill('0')
       << std::uppercase << virtualAddr;
    layer.addField("Virtual Address", ss.str(), offset, 8, "远程虚拟地址");

    // RKey
    uint32_t rkey = extractUint32(data, offset + 8);
    ss.str("");
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << rkey;
    layer.addField("RKey", ss.str(), offset + 8, 4, "远程键");

    // DMA长度
    uint32_t dmaLength = extractUint32(data, offset + 12);
    layer.addField("DMA Length", std::to_string(dmaLength) + " bytes",
                   offset + 12, 4, "DMA传输长度");

    // 使用正确的函数名 generateHexDump
    //layer.hexDump = generateHexDump(data + offset, 16);
    analysis.layers.push_back(layer);

    return true;
}



std::string BTHParser::getOpcodeName(uint8_t opcode) const {
    uint8_t base = opcode & 0x1F;

    switch (base) {
    case 0x00: return "SEND_FIRST";
    case 0x01: return "SEND_MIDDLE";
    case 0x02: return "SEND_LAST";
    case 0x03: return "SEND_LAST_IMM";
    case 0x04: return "SEND_ONLY";
    case 0x05: return "SEND_ONLY_IMM";
    case 0x06: return "RDMA_WRITE_FIRST";
    case 0x07: return "RDMA_WRITE_MIDDLE";
    case 0x08: return "RDMA_WRITE_LAST";
    case 0x09: return "RDMA_WRITE_LAST_IMM";
    case 0x0A: return "RDMA_WRITE_ONLY";
    case 0x0B: return "RDMA_WRITE_ONLY_IMM";
    case 0x10: return "RDMA_READ_REQUEST";
    case 0x11: return "RDMA_READ_RESP_FIRST";
    case 0x12: return "RDMA_READ_RESP_MIDDLE";
    case 0x13: return "RDMA_READ_RESP_LAST";
    case 0x14: return "RDMA_READ_RESP_ONLY";
    case 0x60: return "ACKNOWLEDGE";
    case 0x61: return "ATOMIC_ACK";
    case 0x81: return "CNP";
    case 0x90: return "ATOMIC_CMP_AND_SWP";
    case 0x91: return "ATOMIC_FETCH_AND_ADD";
    case 0xC0: return "RESYNC";
    default: return "UNKNOWN";
    }
}

std::string BTHParser::getOpcodeDescription(uint8_t opcode) const
{
    return "";
}
