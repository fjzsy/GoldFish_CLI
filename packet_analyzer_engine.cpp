#include "packet_analyzer_engine.h"


#include <sstream>
#include <iomanip>


PacketAnalyzerEngine ::PacketAnalyzerEngine (QObject *parent)
    : QObject{parent}
{
    // 注册所有解析器
    stats_.reset();
}

void PacketAnalyzerEngine::analyzePacket(const uint8_t *data, uint32_t length,
                                         PacketAnalysis& analy,
                                         AnalysisStatistics& stats, int vlanOffset)
{
    // 检查是否满足最小长度（基础统计已在PcapFileReader中完成）
    if (length < 54 + vlanOffset) {  // 以太网14 + IP20 + UDP8 + BTH12 = 54
        return;  // 太小的包已经被过滤，这里只是二次确认
    }

    uint32_t offset = vlanOffset;

    // ============ 以太网层（只解析，不统计） ============
    analy.ethernet.dstMac = parser.getMac(data, offset);
    analy.ethernet.srcMac = parser.getMac(data, offset + 6);
    offset += 14;

    // ============ IP层（只解析，不统计） ============
    analy.ip.srcIp = parser.getU32(data, offset + 12);
    analy.ip.dstIp = parser.getU32(data, offset + 16);
    analy.ip.protocol = data[offset + 9];
    analy.ip.version = data[offset] >> 4;
    analy.ip.headerLen = (data[offset] & 0x0F) * 4;
    analy.ip.totalLength = parser.getU16(data, offset + 2);
    analy.ip.ttl = data[offset + 8];
    offset += analy.ip.headerLen;

    // ============ UDP层（只解析，不统计） ============
    analy.udp.srcPort = parser.getU16(data, offset);
    analy.udp.dstPort = parser.getU16(data, offset + 2);
    analy.udp.length = parser.getU16(data, offset + 4);
    offset += 8;

    // ============ BTH层解析（RoCE专属统计） ============
    if (offset + 12 > length) {
        stats.roceErrors.bthHeaderTruncated++;  // BTH头不完整
        return;
    }
    analy.bth.opcode = data[offset];
    analy.bth.baseOpcode = analy.bth.opcode & 0x1F;

    uint8_t flags = data[offset + 1];
    analy.bth.solicited = (flags & 0x80) != 0;
    analy.bth.migReq = (flags & 0x40) != 0;
    analy.bth.padCount = (flags >> 4) & 0x03;
    analy.bth.version = flags & 0x0F;

    analy.bth.pkey = parser.getU16(data, offset + 2);

    uint8_t fecnBecn = data[offset + 4];
    analy.bth.fecn = (fecnBecn & 0x80) != 0;
    analy.bth.becn = (fecnBecn & 0x40) != 0;
    analy.bth.dqpn = (fecnBecn & 0x08) != 0;

    analy.bth.qpNum = parser.getU24(data, offset + 5);
    analy.bth.ackReq = (data[offset + 8] & 0x80) != 0;
    analy.bth.psn = parser.getU24(data, offset + 9);

    // ============ RoCE专属统计（在RoceStatistics层） ============
    stats.qpOpcodeStats[analy.bth.qpNum][analy.bth.opcode]++;
    stats.qpStats[analy.bth.qpNum]++;
    stats.psnStats[analy.bth.psn / 1000]++;

    offset += 12;

    // ============ 扩展头部解析（错误统计） ============
    uint8_t baseOpcode = analy.bth.baseOpcode;

    if (baseOpcode >= 0x06 && baseOpcode <= 0x0B) {
        if (offset + 16 > length) {
            stats.roceErrors.rethTruncated++;
            return;
        }

        // 格式检查
        if (data[offset] == 0 && data[offset+1] == 0) {
            stats.roceErrors.rethMalformed++;
        }

        memcpy(&analy.rdmaExt.reth, data + offset, sizeof(analy.rdmaExt.reth));
        analy.extType = PacketInfo::EXT_RETH;
        offset += sizeof(analy.rdmaExt.reth);

    } else if (baseOpcode == 0x03 || baseOpcode == 0x05 ||
               baseOpcode == 0x09 || baseOpcode == 0x0B) {
        if (offset + 4 > length) {
            stats.roceErrors.immTruncated++;
            return;
        }
        analy.rdmaExt.immediateData = parser.getU32(data, offset);
        analy.extType = PacketInfo::EXT_IMM;
        offset += 4;

    } else if (baseOpcode == 0x90 || baseOpcode == 0x91) {
        if (offset + 32 > length) {
            stats.roceErrors.atomicTruncated++;
            return;
        }
        memcpy(&analy.rdmaExt.atomic, data + offset, sizeof(analy.rdmaExt.atomic));
        analy.extType = PacketInfo::EXT_ATOMIC;
        offset += sizeof(analy.rdmaExt.atomic);

    } else if (baseOpcode == 0x61) {
        if (offset + 8 > length) {
            // atomicAck 错误统计
            stats.roceErrors.atomicAckTruncated++; // 错误统计项
            return;
        }
        analy.rdmaExt.atomicAck.originalData = parser.getU64(data, offset);
        analy.extType = PacketInfo::EXT_ATOMIC_ACK;
        offset += 8;

    } else if (baseOpcode >= 0x0C && baseOpcode <= 0x0F) {
        if (offset + 8 > length) {
            stats.roceErrors.dethTruncated++;
            return;
        }
        analy.rdmaExt.deth.qkey = parser.getU32(data, offset);
        analy.rdmaExt.deth.sourceQpn = parser.getU32(data, offset + 4);
        analy.extType = PacketInfo::EXT_DETH;
        offset += 8;

    } else if (baseOpcode == 0x1C || baseOpcode == 0x1D) {
        if (offset + 4 > length) {
            stats.roceErrors.iethTruncated++;
            return;
        }
        analy.rdmaExt.ieth.rkey = parser.getU32(data, offset);
        analy.extType = PacketInfo::EXT_IETH;
        offset += 4;
    }
    return;
}

void PacketAnalyzerEngine::reset()
{
    stats_.reset();
}
