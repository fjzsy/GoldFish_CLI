#ifndef PCAPANALYZERAPP_H
#define PCAPANALYZERAPP_H

#include <QObject>
#include "pcapfilereader.h"
#include "packet_info_extended.h"
#include "reportdata.h"
#include "statisticsheader.h"
#include "flowaggregator.h"

class PcapAnalyzerApp: public QObject
{
     Q_OBJECT
public:
    PcapAnalyzerApp(QObject* parent = nullptr);
    ~PcapAnalyzerApp();

    void analyzePcapFile(const std::string&  filename, ReportData* report);

    QList<QString> getList() const;

    void setPcapReader(PcapFileReader *newPcapReader);

    void setAggregator(FlowAggregator *newAggregator);

signals:
    void sigPkParseProc(const int value);

private:

    PcapFileReader* pcapReader;
    FlowAggregator* aggregator;
};

#endif // PCAPANALYZERAPP_H
