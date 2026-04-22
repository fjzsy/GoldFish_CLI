#ifndef PACKET_ANALYZER_ENGINE_H
#define PACKET_ANALYZER_ENGINE_H

#include <QObject>

#include "protocol_parser_factory.h"
#include <memory>
#include <vector>
#include "packet_info_extended.h"
#include "statisticsheader.h"

class PacketAnalyzerEngine  : public QObject
{
    Q_OBJECT
public:
    explicit PacketAnalyzerEngine (QObject *parent = nullptr);

    // 分析单个包
    void analyzePacket(const uint8_t* data, uint32_t length,
                       PacketAnalysis& analy, AnalysisStatistics& stats,int vlanOffset);

    const AnalysisStatistics& getStatistics() const { return stats_; }
    void reset();

signals:

private:

    EthernetParser parser;
    AnalysisStatistics stats_;

};

#endif // PACKET_ANALYZER_ENGINE_H
