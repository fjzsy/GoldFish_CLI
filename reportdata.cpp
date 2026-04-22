#include "reportdata.h"
#include <QLocale>
#include <QDebug>
#include "psnchartheader.h"
#ifdef _WIN32
// Windows 平台
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
// Linux / Unix / macOS
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

void ReportData::genReportData( const uint32_t& analyTimeMs,
                                const AnalysisStatistics &anlyStats,
                                int topN) //QP号TOP数，默认10
{
    sourceData.clear();
    QTextStream out(&sourceData);  // QTextStream 直接写 QString

    out << "===================================================\n";
    out << tr("              RoCEv2 PCAP Analysis Report") << "\n\n";
    out << tr(" Pcap file：") << pcapFileName << "\n";
    out << "===================================================\n\n";

    // 总体统计
    out << tr("📊 Summary Statistics") << "\n"
        << "--------------------------------------------------\n"
        << tr("  ├─ Total Packets: %1").arg(anlyStats.totalPackets) << "\n"
        << tr("  ├─ Total Traffic (Bytes): %1 bytes").arg(anlyStats.totalBytes) << "\n"
        << tr("  └─ Analysis Time (ms): %1 ms").arg(analyTimeMs) << "\n\n";

    out << tr("📦 Protocol Distribution") << "\n"
        << "--------------------------------------------------\n"
        << tr("  ├─ RoCEv2 packets: %1").arg(anlyStats.rocev2Packets) << "\n"
        << tr("  ├─ Other UDP packets: %1").arg(anlyStats.udpOtherPackets) << "\n"
        << tr("  ├─ TCP packets: %1").arg(anlyStats.tcpPackets) << "\n"
        << tr("  ├─ ICMP packets: %1").arg(anlyStats.icmpPackets) << "\n"
        << tr("  ├─ ARP packets: %1").arg(anlyStats.arpPackets) << "\n"
        << tr("  ├─ PFC packets: %1").arg(anlyStats.pfcPackets) << "\n"
        << tr("  ├─ IP fragments: %1").arg(anlyStats.ipFragments) << "\n"
        << tr("  └─ IP packets with options: %1").arg(anlyStats.ipOptions) << "\n\n";


    out << "🎯 RoCEv2 OpCode Distribution\n"
        << "--------------------------------------------------\n";
    for (const auto& [qpNum, opcodeMap] : anlyStats.qpOpcodeStats) {
        out << QString("QP %1:\n").arg(qpNum);

        // 格式化数字带千位分隔符
        //QLocale locale(QLocale::English);
        //QString countStr = locale.toString(static_cast<qlonglong>(count));

        int count = 0;
        for (const auto& [opcode, packets] : opcodeMap) {
            QString prefix = (++count == opcodeMap.size()) ? "  └─ " : "  ├─ ";
            //out << prefix << opcodeToString(opcode) << ": " << packets << "\n";
            out << QString("  %1 %2 (0x%3): %4\n")
                       .arg(prefix)
                       .arg(opcodeToString(opcode))
                       .arg(opcode, 2, 16, QLatin1Char('0'))
                       .arg(packets);
        }
    }

    // QP statistic
    printFlowStats(out);

    printTimeAnaly(out);

    printErrorStats(out, anlyStats);
    out.flush();
}

void ReportData::saveToFile(QString fileName)
{
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        qDebug() << "Open the file fail:" << fileName;
        return;
    }

    QTextStream out(&file);
    out << sourceData;  //report data

    out << "\n📦 Sampled Packet Details (RoCEv2)\n"
        << "--------------------------------------------------\n";

    for (const auto& analysis : analyses) {
        if (analysis.isRoCEv2) {
            out << "Packet #" << analysis.packetNumber << "\n"
                << "---------------------------\n"
                << "timestamp: " << analysis.timestamp << "\n"
                << "Packet size: " << analysis.originalSize << " bytes\n";
            printBthHeader(out, analysis);
        }
    }

    file.close();
    return;
}

QString ReportData::getSourceData() const
{
    return sourceData;
}

void ReportData::setPcapFileName(const QString &newPcapFileName)
{
    pcapFileName = newPcapFileName;
}

void ReportData::printBthHeader(QTextStream &out, const PacketAnalysis &pkt)
{
    out << tr("\n[BTH header]\n");

    //opertation code
    out << QString("  Opcode: %1 (0x%2)\n")
               .arg(opcodeToString(pkt.bth.opcode))
               .arg(pkt.bth.opcode, 2, 16, QLatin1Char('0'));

    // flag
    out << QString("  S (Solicited): %1\n").arg(pkt.bth.solicited ? "Yes" : "No")
        << QString("  M (MigReq): %1\n").arg(pkt.bth.migReq ? "Yes" : "No")
        << QString("  Pad Count: %1\n").arg(pkt.bth.padCount)
        << QString("  Version: %1\n").arg(pkt.bth.version);

    // Partition Key
    out << QString("  Partition Key: 0x%1\n")
               .arg(pkt.bth.pkey, 4, 16, QLatin1Char('0'));

    // congestion flag
    out << QString("  FECN: %1\n").arg(pkt.bth.fecn ? "Yes" : "No")
        << QString("  BECN: %1\n").arg(pkt.bth.becn ? "Yes" : "No")
        << QString("  DQPN: %1\n").arg(pkt.bth.dqpn ? "Yes" : "No");

    // QP Number
    out << QString("  QP Number: %1\n").arg(pkt.bth.qpNum);

    // A位
    out << QString("  A (AckReq): %1\n").arg(pkt.bth.ackReq ? "Yes" : "No");

    // PSN
    out << QString("  PSN: %1\n").arg(pkt.bth.psn);

    // ============ 扩展头部 ============
    switch (pkt.extType) {
    case PacketInfo::EXT_RETH:
        out << tr("\n[RETH header]\n");
        out << QString("  Virtual Address: 0x%1\n")
                   .arg(pkt.rdmaExt.reth.virtualAddress, 16, 16, QLatin1Char('0'));
        out << QString("  RKey: 0x%1\n")
                   .arg(pkt.rdmaExt.reth.rkey, 8, 16, QLatin1Char('0'));
        out << QString("  DMA Length: %1 bytes\n")
                   .arg(pkt.rdmaExt.reth.dmaLength);
        break;

    case PacketInfo::EXT_ATOMIC:
        out << tr("\n[Atomic header]\n");
        out << QString("  Virtual Address: 0x%1\n")
                   .arg(pkt.rdmaExt.atomic.virtualAddress, 16, 16, QLatin1Char('0'));
        out << QString("  RKey: 0x%1\n")
                   .arg(pkt.rdmaExt.atomic.rkey, 8, 16, QLatin1Char('0'));
        out << QString("  Swap Data: 0x%1\n")
                   .arg(pkt.rdmaExt.atomic.swapData, 16, 16, QLatin1Char('0'));
        out << QString("  Compare Data: 0x%1\n")
                   .arg(pkt.rdmaExt.atomic.compareData, 16, 16, QLatin1Char('0'));
        break;

    case PacketInfo::EXT_IMM:
        out << "\n[Immediate Data]\n";
        out << QString("  Immediate Data: 0x%1\n")
                   .arg(pkt.rdmaExt.immediateData, 8, 16, QLatin1Char('0'));
        break;

    case PacketInfo::EXT_ATOMIC_ACK:
        out << "\n[Atomic ACK]\n";
        out << QString("  Original Data: 0x%1\n")
                   .arg(pkt.rdmaExt.atomicAck.originalData, 16, 16, QLatin1Char('0'));
        break;

    case PacketInfo::EXT_DETH:
        out << tr("\n[DETH header]\n");
        out << QString("  QKey: 0x%1\n")
                   .arg(pkt.rdmaExt.deth.qkey, 8, 16, QLatin1Char('0'));
        out << QString("  Source QPN: %1\n").arg(pkt.rdmaExt.deth.sourceQpn);
        break;

    case PacketInfo::EXT_IETH:
        out << tr("\n[IETH header]\n");
        out << QString("  RKey (to invalidate): 0x%1\n")
                   .arg(pkt.rdmaExt.ieth.rkey, 8, 16, QLatin1Char('0'));
        break;

    default:
        break;
    }

    out << "\n";
}

void ReportData::printErrorStats(QTextStream &out, const AnalysisStatistics &stats)
{
    out << "\n" << tr("⚠️ Anomaly Statistics") << "\n"
        << "----------------------------------------" << "\n";

    bool hasError = false;

    // （from PcapStatistics）
    if (stats.errors.tooShort > 0) {
        out << tr("   Packet too short (<14 bytes): %1").arg(stats.errors.tooShort) << "\n";
        hasError = true;
    }

    if (stats.errors.ipHeaderTruncated > 0) {
        out << tr("   Incomplete IP header: %1").arg(stats.errors.ipHeaderTruncated) << "\n";
        hasError = true;
    }

    if (stats.errors.udpHeaderTruncated > 0) {
        out << tr("   Incomplete UDP header: %1").arg(stats.errors.udpHeaderTruncated) << "\n";
        hasError = true;
    }

    if (stats.errors.unknownEtherType > 0) {
        out << tr("   UnknownEtherType: %1").arg(stats.errors.unknownEtherType) << "\n";
        hasError = true;
    }

    if (stats.errors.unknownIpProtocol > 0) {
        out << tr("   UnknownIpProtocol: %1").arg(stats.errors.unknownIpProtocol) << "\n";
        hasError = true;
    }

    if (stats.errors.malformed > 0) {
        out << tr("   Format error: %1").arg(stats.errors.malformed) << "\n";
        hasError = true;
    }
    if (stats.errors.pfcHeaderTruncated > 0) {
        out << tr("   PFC protocol error: %1").arg(stats.errors.pfcHeaderTruncated) << "\n";
        hasError = true;
    }
    if (stats.errors.analyzerNotSet > 0) {
        out << tr("   analyzerNotSet: %1").arg(stats.errors.analyzerNotSet) << "\n";
        hasError = true;
    }
    if (stats.errors.aggregatorNotSet > 0) {
        out << tr("   aggregatorNotSet: %1").arg(stats.errors.aggregatorNotSet) << "\n";
        hasError = true;
    }

    // RoCE 层异常（来自 RoceStatistics）
    if (stats.roceErrors.bthHeaderTruncated > 0) {
        out << tr("   Incomplete BTH header: %1").arg(stats.roceErrors.bthHeaderTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.rethTruncated > 0) {
        out << tr("   RETH truncated: %1").arg(stats.roceErrors.rethTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.rethMalformed > 0) {
        out << tr("   Invalid RETH format: %1").arg(stats.roceErrors.rethMalformed) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.immTruncated > 0) {
        out << tr("   Immediate data truncated: %1").arg(stats.roceErrors.immTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.atomicTruncated > 0) {
        out << tr("   Atomic operation truncated: %1").arg(stats.roceErrors.atomicTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.atomicAckTruncated > 0) {
        out << tr("   Atomic operation ACK truncated: %1").arg(stats.roceErrors.atomicAckTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.dethTruncated > 0) {
        out << tr("   DETH truncated: %1").arg(stats.roceErrors.dethTruncated) << "\n";
        hasError = true;
    }

    if (stats.roceErrors.iethTruncated > 0) {
        out << tr("   IETH truncated: %1").arg(stats.roceErrors.iethTruncated) << "\n";
        hasError = true;
    }
    if (stats.roceErrors.packetTooShort > 0) {
        out << tr("   RoCE header truncated: %1").arg(stats.roceErrors.packetTooShort) << "\n";
        hasError = true;
    }

    // multi-interface
    if (stats.icmpFromUnexpectedIf > 0) {
        out << tr("   ICMP returned from unexpected interface: %1").arg(stats.icmpFromUnexpectedIf) << "\n";
        hasError = true;
    }

    // not error
    if (!hasError) {
        out << tr("   No anomalies detected") << "\n";
    }
}

void ReportData::printFlowStats(QTextStream &out, int topN)
{
    out << "\n📊 Flow Statistics (By 5-Tuple) \n";
    out << "----------------------------------------------------------------------------------------------------\n";
    out << "Source IP\tSource Port\tDest IP\tDest Port\tQP\tOpCode\tPackets\tPSN Range\tLoss Rate\n";
    out << "----------------------------------------------------------------------------------------------------\n";

    // convert into vector to sort
    std::vector<std::pair<FlowKey, FlowStats>> sortedFlows;
    for (const auto& [key, flow] : flows) {
        sortedFlows.push_back({key, flow});
    }

    // desc by packet number
    std::sort(sortedFlows.begin(), sortedFlows.end(),
              [](const auto& a, const auto& b) {
                  return a.second.packets > b.second.packets;
              });

    int count = 0;
    for (const auto& [key, flow] : sortedFlows) {
        if (topN > 0 && count++ >= topN) break;

        // IP addr change
        char srcIpStr[16], dstIpStr[16];

        struct in_addr addr;

        addr.s_addr = ntohl(key.srcIp);
        inet_ntop(AF_INET, &addr, srcIpStr, sizeof(srcIpStr));

        addr.s_addr = ntohl(key.dstIp);
        inet_ntop(AF_INET, &addr, dstIpStr, sizeof(dstIpStr));

        // PSN range
        QString psnRange = QString("%1 → %2")
                               .arg(flow.first_psn)
                               .arg(flow.last_psn);

        out << QString("%1\t%2\t%3\t%4\t%5\t0x%6\t%7\t%8\t%9%\n")
                   .arg(srcIpStr)
                   .arg(key.srcPort)
                   .arg(dstIpStr)
                   .arg(key.dstPort)
                   .arg(key.qpNum)
                   .arg(key.opcode, 0, 16)
                   .arg(flow.packets)
                   .arg(psnRange)
                   .arg(flow.loss_rate * 100, 0, 'f', 2);
    }

    if (topN > 0 && flows.size() > (size_t)topN) {
        out << "... and " << (flows.size() - topN) << " more flows not shown\n";
    }
}

void ReportData::printTimeAnaly(QTextStream &out, int topN)
{
    out << "\n📊 Flow Time Analysis (By 5-Tuple) \n";
    out << "-------------------------------------------------------------------------------------------------------------\n";
    out << "Source IP\tSrcPort\tDest IP\tDestPort\tQP\tOpCode\tPFC Pause\tavg_delay\tmax_delay\tavg_jitter\tmax_jitter\tretrans\tlost\n";
    out << "------------------------------------------------------------------------------------------------------------\n";

    // 转成 vector 便于排序
    std::vector<std::pair<FlowKey, QPFlowAnalytics>> sortedFlows;
    for (const auto& [key, flow] : flows) {
        sortedFlows.push_back({key, flow});
    }

    // 按包数降序排序
    std::sort(sortedFlows.begin(), sortedFlows.end(),
              [](const auto& a, const auto& b) {
                  return a.second.packets > b.second.packets;
              });
    int count = 0;
    for (const auto& [key, flow] : sortedFlows) {
        if (topN > 0 && count++ >= topN) break;

        // IP地址转换
        char srcIpStr[16], dstIpStr[16];

        struct in_addr addr;

        addr.s_addr = ntohl(key.srcIp);
        inet_ntop(AF_INET, &addr, srcIpStr, sizeof(srcIpStr));

        addr.s_addr = ntohl(key.dstIp);
        inet_ntop(AF_INET, &addr, dstIpStr, sizeof(dstIpStr));

        // PSN范围
        QString psnRange = QString("%1 → %2")
                               .arg(flow.first_psn)
                               .arg(flow.last_psn);

        out << QString("%1\t%2\t%3\t%4\t%5\t0x%6\t%7\t%8\t%9\t%10\t%11\t%12\t%13\n")
                   .arg(srcIpStr)
                   .arg(key.srcPort)
                   .arg(dstIpStr)
                   .arg(key.dstPort)
                   .arg(key.qpNum)
                   .arg(key.opcode, 0, 16)
                   .arg(flow.pfc_pause_count)
                   .arg(flow.avg_delay)
                   .arg(flow.max_delay)
                   .arg(flow.avg_jitter)
                   .arg(flow.max_jitter)
                   .arg(flow.retrans_count)
                   .arg(flow.real_lost_packets);
    }

}
