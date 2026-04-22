#include "pcapanalyzerapp.h"
#include <iostream>
#include <fstream>
#include <QDebug>

PcapAnalyzerApp::PcapAnalyzerApp(QObject *parent)
    : QObject(parent)
{

}

PcapAnalyzerApp::~PcapAnalyzerApp()
{

}

void PcapAnalyzerApp::analyzePcapFile(const std::string&  filename, ReportData *report)
{
    auto startTime = std::chrono::high_resolution_clock::now();

    // 1. 打开PCAP文件
    if (!pcapReader->open(filename)) {
        qDebug() << "❌ Unable to open PCAP file";
        return;
    }

    // 2. 创建分析引擎
    PacketAnalyzerEngine analyzer;

    pcapReader->setAnalyzer(&analyzer);

    // 3. 读取所有包
    bool result = pcapReader->readAllPackets();

    if (!result) {
        qDebug() << "PCAP file is empty or read failed";
        return;
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    uint32_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();

    // 4. 获取样本分析包队列
    report->analyses = std::move(pcapReader->analyses);

    // 5. 获流队列
    report->flows = aggregator->anlyFlowMap_;

    // 6. 生成统计信息
    auto pcapStats = pcapReader->getStatistics();
    report->genReportData(duration, pcapStats);
}

void PcapAnalyzerApp::setPcapReader(PcapFileReader *newPcapReader)
{
    pcapReader = newPcapReader;
}

void PcapAnalyzerApp::setAggregator(FlowAggregator *newAggregator)
{
    aggregator = newAggregator;
}
