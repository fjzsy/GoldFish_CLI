#ifndef REPORTDATA_H
#define REPORTDATA_H

#include "flowaggregator.h"
#include "protocol_layers.h"
#include "psnchartheader.h"
#include "statisticsheader.h"
#include <QObject>
#include <QTextStream>
#include <QFile>

class ReportData : public QObject
{
public:
    ReportData(QObject* parent = nullptr) {}

    std::vector<PacketAnalysis> analyses;

    std::unordered_map<FlowKey, QPFlowAnalytics> flows;

    void genReportData(const uint32_t& analyTimeMs,
                        const AnalysisStatistics &anlyStats,
                        int topN = 10); //QP TOP，default 10

    void saveToFile(QString fileName = "analysis_report.txt");

    QString getSourceData() const;

    void setPcapFileName(const QString &newPcapFileName);

private:
    QString sourceData;
    QString pcapFileName;

    void printBthHeader(QTextStream& out, const PacketAnalysis& pkt);
    void printErrorStats(QTextStream& out, const AnalysisStatistics& stats);
    void printFlowStats(QTextStream& out, int topN = 10);
    void printTimeAnaly(QTextStream& out, int topN = 10);

    //QString opcodeToString(uint8_t opcode);
};

#endif // REPORTDATA_H
