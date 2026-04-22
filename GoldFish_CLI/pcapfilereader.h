#ifndef PCAPFILEREADER_H
#define PCAPFILEREADER_H

#include "qobject.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <functional>
#include "packet_info_extended.h"
#include "packet_analyzer_engine.h"
#include "otherpacketstats.h"
#include "protocol_parser_factory.h"
#include "flowaggregator.h"


class PcapFileReader : public QObject
{
     Q_OBJECT
public:
    PcapFileReader(QObject* parent = nullptr);
    ~PcapFileReader();

    bool open(const std::string& filePath) ;
    void close();

    // 检查是否打开成功
    bool isOpen() const { return m_pcapHandle != nullptr; }

    // 获取文件信息
    QString getFileInfo() const;

    PacketType identify_packet(const uint8_t* data, uint32_t len, OtherPacketStats* info);


    // 读取所有包
    bool readAllPackets();

    // 解析出 QP、PSN（每个包都做）
    static inline void parseBasicFields(const uint8_t* data, uint32_t length,
                                        PacketInfo& analy,
                                        AnalysisStatistics& stats,
                                        int vlanOffset); // 新增VLAN偏移参数

    // 分析每个包
    std::vector<PacketAnalysis> analyses;

    // 流式读取（回调方式）
    void readPackets(std::function<void(const PacketInfo&)> callback);

    // 过滤读取（只读RoCEv2包）
    std::vector<PacketInfo> readRoCEv2Packets();

    const AnalysisStatistics& getStatistics() const { return stats_; }

    void setAnalyzer(PacketAnalyzerEngine *newAnalyzer);

    void setAggregator(FlowAggregator *newAggregator);

    void setSAMPLE_RATE(uint32_t newSAMPLE_RATE);

signals:
    void sigPkParseProc(const int value);

private:

    pcap_t* m_pcapHandle;
    AnalysisStatistics stats_;

    uint32_t SAMPLE_RATE=1000; //采样率

    // 3. 创建分析引擎
    PacketAnalyzerEngine* analyzer;

    FlowAggregator* aggregator;

    // 检查是否为RoCEv2包
    bool isRoCEv2Packet(const uint8_t* data, uint32_t length) const;
};

#endif // PCAPFILEREADER_H
