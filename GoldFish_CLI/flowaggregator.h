#ifndef FLOWAGGREGATOR_H
#define FLOWAGGREGATOR_H

#include <QObject>

#include <unordered_map>
#include <vector>
#include "packet_info_extended.h"
#include "psnchartheader.h"
#include "analytics.h"



class FlowAggregator : public QObject
{
    Q_OBJECT
public:
    explicit FlowAggregator(QObject *parent = nullptr);

    void process_packet(const PacketInfo& pkt);

    // 获取所有流统计（已计算好最终指标）
    std::vector<QPFlowAnalytics> get_all_flows();

    std::unordered_map<FlowKey, QPFlowAnalytics > anlyFlowMap_;

    // 获取Top N有问题的流（按丢包率排序）
    std::vector<QPFlowAnalytics> get_problem_flows(int top_n = 10);

    std::vector<QpCurve> getCurves();  // 返回曲线数据

signals:

private:
    //std::unordered_map<FlowKey, FlowStats> flows_;

    std::unordered_map<FlowKey, QpState> qpStates;

    std::vector<QColor> generateColors(int count);

};

#endif // FLOWAGGREGATOR_H
