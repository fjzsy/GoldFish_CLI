#ifndef ANALYTICS_H
#define ANALYTICS_H

#include "psnchartheader.h"
#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>

// 1. 用于判断：32位PSN回绕/QP重置
const uint32_t PSN_WRAP_THRESHOLD  = 0x00800000;   // 判断回绕 / QP重置

// 2. 用于判断：异常大跳跃 = 严重丢包（网络异常）
const uint32_t PSN_LARGE_JUMP      = 0x00100000;   // 判断大跨度丢包

const uint32_t PSN_MASK            = 0x00FFFFFF;   // 24bit 掩码

// ==============================================
// 两个枚举全部放在这里（pack 外面，绝对安全）
// ==============================================
enum class AbnormalType : uint8_t
{
    NONE = 0,
    LATENCY_SPIKE,
    JITTER_HIGH,
    PFC_PRI_PAUSE,
    GLOBAL_PAUSE
};

enum class AlertLevel : uint8_t
{
    rigorous = 0,
    STANDARD,
    LOOSE
};


// ==============================================
// 字节对齐从这里开始
// ==============================================
#pragma pack(push,1)
struct FlowStats
{
    FlowKey key;

    uint64_t packets;
    uint64_t bytes;
    uint64_t first_seen;
    uint64_t last_seen;

    uint64_t first_psn;
    uint64_t last_psn;
    uint64_t max_psn;       // 最大PSN（只增不减）
    uint64_t expected_psn;
    uint16_t opcode;
    uint64_t last_ts;
    uint64_t lost_packets;
    uint64_t retrans_count;
    uint64_t real_lost_packets;    // 最终真实丢包
    uint64_t total_interval;

    float loss_rate;
    float retrans_rate;
    float avg_interval;

    FlowStats();
    void finalize();
};

struct TimelineItem
{
    uint64_t timestamp_us=0;
    uint64_t qpn=0;
    uint64_t psn=0;
    uint32_t len = 0;
    uint8_t  opcode=0;

    int64_t  interval_us=0;
    int64_t  delay_us=0;
    int64_t  rtt_us=0;
    int64_t  jitter_us=0;

    bool     is_pause=false;
    bool     is_pfc=false;
    uint8_t  pfc_priority=0;

    // PSN 全量状态标记
    bool     is_retrans=false;       // 是否重传包
    bool     is_lost_recovery=false;// 是否丢包恢复后的首包
    bool     is_psn_jump=false;     // 是否PSN大幅跳变(QP重建/重置)
    bool     is_large_jump=false;   // 判断大跨度丢包
    bool     is_psn_wrap=false;     // 32位回绕
    bool     is_qp_reset=false;     //qp重置
    bool     is_fake_delay=false;   // 伪延时（重传/丢包/跳变导致，不计入真实时延统计）

    AbnormalType abnormal_type = AbnormalType::NONE;
};

struct QPFlowAnalytics : public FlowStats
{
    std::string flow_key;


    // 单向时延指标
    int64_t max_delay;
    int64_t min_delay;
    int64_t avg_delay;

    // RTT往返指标
    int64_t max_rtt;
    int64_t avg_rtt;

    // 抖动指标
    int64_t max_jitter;
    int64_t avg_jitter;

    // 异常包统计
    int32_t abnormal_count = 0;

    // PSN 异常统计
    uint32_t large_jump_count = 0;   // 大跳变次数
    uint32_t qp_reset_count = 0;     // QP 重置次数
    uint32_t psn_wrap_count = 0;     // PSN 回绕次数
    uint32_t pfc_pause_count = 0;        // pfc_pause 次数
    uint64_t total_valid_expected = 0; // 累计有效的期望包数（排除大跳变跳过的不连续区间）
    uint64_t total_lost = 0;           // 累计真实丢包数（已被多次修正）

    // 动态可配置告警阈值（不再硬编码，支持运行时修改）
    int64_t latency_spike_threshold_us;
    int64_t jitter_high_threshold_us;

    //PSN跳变判定阈值（默认行业标准：0x00100000）
    uint32_t psn_jump_threshold;

    // ===================== 全自动自适应PSN步长核心 =====================
    uint32_t auto_learned_psn_step;   // 程序自动学习到的该QP固有正常步长
    bool     step_learned_flag;

    QPFlowAnalytics();

    // 核心主接口：新增一包，全链路自动计算所有指标
    void add_timeline_point(const TimelineItem& item);

    // 异常检测：间隔/抖动/PFC/PAUSE
    void detect_abnormal(TimelineItem& item);

    // PSN完整解析：重传、丢包、跳变、32位回绕、伪延时判定
    void check_psn_status(TimelineItem& item);

    bool is_request_opcode(uint32_t opcode);
    bool is_ack_opcode(uint32_t opcode);

    // 外部获取接口
    uint64_t get_packets() const { return packets; }
    uint64_t get_retrans_count() const { return retrans_count; }
    uint64_t get_real_lost_packets() const;
    uint32_t get_last_psn() const { return last_psn; }
    double get_retrans_rate() const; // 重传率
    double get_lost_rate() const;


    // 全量指标最终懒计算汇总（抓包结束统一调用）
    void finalize_all();

     // 阈值手动自定义设置
    void set_threshold(int64_t latency_thresh, int64_t jitter_thresh);

    // 一键切换告警灵敏度档位
    void set_alert_level(AlertLevel level);

    // 设置PSN跳变阈值接口
    void set_psn_jump_threshold(uint32_t threshold);

private:
    // RTT 请求-ACK 哈希匹配 O(1)高性能查找
    std::unordered_map<uint32_t, uint64_t> request_map;

    std::vector<TimelineItem> timeline;

    void reset(uint32_t curr_psn);

    // 时序容器预分配容量，避免动态扩容拷贝
    static constexpr size_t RESERVE_CAPACITY = 1024 * 16;

    // PSN跳变判定阈值（行业标准）
    static constexpr uint32_t PSN_JUMP_THRESHOLD = 0x00100000;

    // Opcode类型判断工具
    bool is_request_opcode(uint8_t op);
    bool is_ack_opcode(uint8_t op);
};

#pragma pack(pop)

// 异常枚举转字符串（仅UI展示，不参与解析主线程）
inline std::string abnormal_to_string(AbnormalType type)
{
    switch(type)
    {
    case AbnormalType::LATENCY_SPIKE: return "LATENCY_SPIKE";
    case AbnormalType::JITTER_HIGH:  return "JITTER_HIGH";
    case AbnormalType::PFC_PRI_PAUSE: return "PFC_PRI_PAUSE";
    case AbnormalType::GLOBAL_PAUSE: return "GLOBAL_PAUSE";
    default: return "NONE";
    }
}

#endif // ANALYTICS_H
