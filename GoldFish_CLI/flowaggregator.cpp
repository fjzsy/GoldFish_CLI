#include "analytics.h"
#include <QDebug>
#include "flowaggregator.h"

FlowAggregator::FlowAggregator(QObject *parent)
    : QObject{parent}
{
    anlyFlowMap_.reserve(1000);  // 假设最多1000个流
}

void FlowAggregator::process_packet(const PacketInfo &pkt)
{
    if (!pkt.isRoCEv2) return;

    // 流标识：可以用 (srcIp << 32) | qpn 作为key
    FlowKey flow_key;
    flow_key.srcIp = pkt.ip.srcIp;
    flow_key.dstIp = pkt.ip.dstIp;
    flow_key.srcPort = pkt.udp.srcPort;
    flow_key.dstPort = pkt.udp.dstPort;
    flow_key.qpNum = pkt.bth.qpNum;
    flow_key.opcode = pkt.bth.opcode;

    // 3. 构造时序包
    TimelineItem item;
    item.psn          = pkt.bth.psn & 0x00FFFFFF;
    item.timestamp_us = pkt.timestamp;
    item.opcode       = pkt.bth.opcode;
    item.len          = pkt.originalSize;

    auto it = anlyFlowMap_.find(flow_key);
    if (it == anlyFlowMap_.end()) {
        // 新流
        QPFlowAnalytics anlyFlow;
        anlyFlow.first_psn = pkt.bth.psn & 0x00FFFFFF;
        anlyFlow.last_psn = anlyFlow.first_psn;
        anlyFlow.key.qpNum = pkt.bth.qpNum;
        anlyFlow.key.srcIp = pkt.ip.srcIp;
        anlyFlow.key.dstIp = pkt.ip.dstIp;
        anlyFlow.first_seen = pkt.timestamp;
        anlyFlow.last_seen = pkt.timestamp;
        anlyFlow.bytes += pkt.originalSize;
        anlyFlow.last_ts = pkt.timestamp;

        anlyFlow.add_timeline_point(item);

        anlyFlowMap_[flow_key] = anlyFlow;
        auto& state = qpStates[flow_key];
        state.firstTime = pkt.timestamp;
        state.firstPsn = anlyFlow.first_psn;
        state.curve.qpNum = flow_key;
    } else {
        // 已有流，更新统计
        QPFlowAnalytics& flow = it->second;

        // 更新最后一个PSN
        flow.last_psn = pkt.bth.psn & 0x00FFFFFF;

        // 间隔计算（可选）
        uint64_t interval = pkt.timestamp - flow.last_ts;
        flow.total_interval += interval;

        // 更新统计
        flow.packets++;
        flow.bytes += pkt.originalSize;
        flow.last_seen = pkt.timestamp;
        flow.last_ts = pkt.timestamp;

        flow.add_timeline_point(item);

        auto& state = qpStates[flow_key];
        // 计算相对时间（以该QP自己的第一个包为基准）

        double relTime = (pkt.timestamp - state.firstTime) / 1000.0; // 毫秒

        // // 计算差值时考虑回绕
        int32_t diff = (pkt.bth.psn - state.firstPsn + 0x01000000) % 0x01000000;
        uint32_t relPsn = diff & 0x00FFFFFF;

        // addPoint，它会自动更新范围
        state.curve.addPoint(relTime, relPsn);
        // if(pkt.bth.qpNum==88)
        //     qDebug() << "scrIp" << pkt.ip.srcIp
        //              << "srcPort" << pkt.udp.srcPort
        //              << "dstIp" << pkt.ip.dstIp
        //              << "dstPort" << pkt.udp.dstPort
        //              << "QP:" << pkt.bth.qpNum
        //              << "abs PSN:" << pkt.bth.psn
        //              << "first PSN:" << state.firstPsn
        //              << "timestamp:" << pkt.timestamp
        //              << "relTime:" << relTime;
    }
}

std::vector<QPFlowAnalytics> FlowAggregator::get_all_flows()
{
    std::vector<QPFlowAnalytics> result;
    for (auto& [key, flow] : anlyFlowMap_) {
        flow.finalize();  // 确保指标已算好
        result.push_back(flow);
    }
    return result;
}

std::vector<QPFlowAnalytics> FlowAggregator::get_problem_flows(int top_n)
{
    std::vector<QPFlowAnalytics> result;
    for (auto& [key, flow] : anlyFlowMap_) {
        flow.finalize();
        result.push_back(flow);
    }

    // 按丢包率排序
    std::sort(result.begin(), result.end(),
              [](const QPFlowAnalytics& a, const QPFlowAnalytics& b) {
                  return a.loss_rate > b.loss_rate;
              });

    if (result.size() > top_n) {
        result.resize(top_n);
    }
    return result;
}

std::vector<QpCurve> FlowAggregator::getCurves()
{
    std::vector<QpCurve> result;
    for (auto& [qp, state] : qpStates) {
        result.push_back(std::move(state.curve));  // 直接转移
    }
    return result;  // RVO 优化
}

std::vector<QColor> FlowAggregator::generateColors(int count)
{
    std::vector<QColor> colors;
    colors.reserve(count);

    for (int i = 0; i < count; i++) {
        // 色相从 0 到 359 均匀分布，饱和度 200，亮度 150
        int hue = (i * 360 / count) % 360;
        colors.push_back(QColor::fromHsl(hue, 200, 150));
    }

    return colors;
}
