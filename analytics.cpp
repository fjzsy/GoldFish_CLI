#include "analytics.h"
#include <cstring>


// ==============================================
// FlowStats
// ==============================================
FlowStats::FlowStats()
    : packets(0), bytes(0), first_seen(0), last_seen(0),
    first_psn(0), last_psn(0), max_psn(0), expected_psn(0),
    last_ts(0), lost_packets(0), retrans_count(0),
    real_lost_packets(0), total_interval(0),
    loss_rate(0.0f), retrans_rate(0.0f), avg_interval(0.0f)
{
}

void FlowStats::finalize()
{
    if (packets == 0) return;

    // 丢包率 = 丢包总数 / (有效总包 + 丢包)
    loss_rate = static_cast<float>(lost_packets) / static_cast<float>(packets + lost_packets);

    // 重传率 = 重传包数 / 有效总包数
    retrans_rate = static_cast<float>(retrans_count) / static_cast<float>(packets);

    // 平均包间隔
    if (packets > 1)
    {
        avg_interval = static_cast<float>(total_interval) / static_cast<float>(packets - 1);
    }
}

// ======================================================
// 子类构造函数：初始化所有默认阈值（全部行业标准默认值）
// ======================================================
QPFlowAnalytics::QPFlowAnalytics()
{
    max_delay = 0;
    min_delay = INT64_MAX;
    avg_delay = 0;

    max_rtt = 0;
    avg_rtt = 0;

    max_jitter = 0;
    avg_jitter = 0;

    abnormal_count = 0;

    // 提前预分配大容量，全程不再扩容、不再拷贝内存
    timeline.reserve(RESERVE_CAPACITY);

    // ===================== 默认：STANDARD 标准档位（交付信而泰/中移首选） =====================
    // 间隔毛刺：10ms = 10000us （行业通用标准）
    latency_spike_threshold_us = 10000;
    // 高抖动：2ms = 2000us （RoCEv2通用黄金阈值）
    jitter_high_threshold_us = 2000;

    // ========== 全自动自适应步长初始化 ==========
    auto_learned_psn_step = 1;      // 默认保底步长+1
    step_learned_flag = false;       // 未完成学习

    large_jump_count = 0;
    qp_reset_count = 0;
    psn_wrap_count = 0;
    total_valid_expected = 0;
    total_lost = 0;
}

// ==============================================
// 核心主入口：单包全量解析处理
// 包间隔、时延极值、抖动、RTT配对、PSN全量分析、异常检测一站式完成
// 全程仅做轻量更新，均值全部懒计算到finalize_all，极致高性能
// ==============================================
void QPFlowAnalytics::add_timeline_point(const TimelineItem& item)
{
    // 加入时序序列
    timeline.push_back(item);
    TimelineItem& curr = timeline.back();

    packets++;

    if (packets == 1)
    {
        first_seen = curr.timestamp_us;
        last_ts = curr.timestamp_us;
        min_delay = 0;
    }

    last_seen = curr.timestamp_us;

    // 1. 计算当前包与上一包的时间间隔 interval
    int64_t interval = 0;
    if (last_ts > 0) {
        if (item.timestamp_us >= last_ts) {
            interval = static_cast<int64_t>(item.timestamp_us - last_ts);
        } else {
            // 时间戳乱序（可能来自多核抓包），记录日志或使用绝对值
            interval = -static_cast<int64_t>(last_ts - item.timestamp_us);
            // 或者标记为异常
            curr.is_fake_delay = true;
        }
    }

    curr.interval_us = interval;
    total_interval += interval;
    last_ts = item.timestamp_us;

    // 2. 时延极值更新
    if (item.delay_us > 0)
    {
        if (item.delay_us > max_delay)
            max_delay = item.delay_us;
        if (item.delay_us < min_delay)
            min_delay = item.delay_us;
    }

    //3. 抖动计算
    if (timeline.size() >= 2)
    {
        const auto& prev = timeline[timeline.size() - 2];
        int64_t jitter = std::abs(interval - prev.interval_us);
        curr.jitter_us = jitter;

        if (jitter > max_jitter)
            max_jitter = jitter;
    }

    // 4. RTT 哈希自动配对
    if (is_request_opcode(item.opcode))
    {
        request_map[curr.psn] = curr.timestamp_us;
    }
    else if (is_ack_opcode(curr.opcode))
    {
        auto it = request_map.find(curr.psn);
        if (it != request_map.end())
        {
            int64_t rtt = static_cast<int64_t>(curr.timestamp_us) - static_cast<int64_t>(it->second);
            curr.rtt_us = rtt;

            if (rtt > max_rtt)
                max_rtt = rtt;

            request_map.erase(it);
        }
    }

    // 5. PSN全套分析：重传/丢包/跳变/32位回绕/伪延时标记
    check_psn_status(curr);

    // 6. 网络异常检测（间隔、抖动、PFC、PAUSE）
    detect_abnormal(curr);
}

// ==============================================
// 异常检测引擎：基于动态阈值告警，纯枚举标记无运行时字符串开销
// ==============================================
void QPFlowAnalytics::detect_abnormal(TimelineItem& item)
{
    item.abnormal_type = AbnormalType::NONE;

    // 1. 长时间间隔 = 传输卡顿、链路阻塞
    if (item.interval_us > latency_spike_threshold_us) {
        item.abnormal_type = AbnormalType::LATENCY_SPIKE;
        abnormal_count++;
    }
    // 2. 抖动超限，网络不稳定
    else if (item.jitter_us > jitter_high_threshold_us) {
        item.abnormal_type = AbnormalType::JITTER_HIGH;
        abnormal_count++;
    }
    // 3. PFC优先级流控触发（数据中心最核心故障点）
    else if (item.is_pfc && item.pfc_priority != 0xFF) {
        item.abnormal_type = AbnormalType::PFC_PRI_PAUSE;
        abnormal_count++;
    }
    // 4. 老式全局PAUSE帧（全端口阻塞）
    else if (item.is_pause && !item.is_pfc){
        item.abnormal_type = AbnormalType::GLOBAL_PAUSE;
        abnormal_count++;
    }
}

// ======================================================
// PSN全自动智能自适应算法（无任何人工配置）
// 逻辑优先级（严格不可乱）：
// 1. PSN大幅跳变(QP重建) > 2. 32位自然回绕 > 3. 重传(PSN重复)
// 4. 自动学习该QP固有正常步长(+1/+2/+4/+8)
// 5. 按自身步长判断合法递增，超出步长才判定真实丢包
// 6. 伪延时完整过滤
// ======================================================
void QPFlowAnalytics::check_psn_status(TimelineItem &item)
{
    const uint32_t curr_psn = item.psn & PSN_MASK;

    // 初始化所有标记位
    item.is_retrans       = false;
    item.is_lost_recovery = false;
    item.is_psn_jump      = false;
    item.is_fake_delay    = false;
    item.is_psn_wrap      = false;
    item.is_large_jump    = false;  // 异常大跳变（严重丢包）
    item.is_qp_reset      = false;  // QP重置

    // 首个数据包初始化PSN基线
    if (packets == 1)
    {
        // first_psn             = curr_psn;
        // last_psn              = curr_psn;
        // max_psn               = curr_psn;
        // expected_psn          = curr_psn;
        // step_learned_flag     = false;
        // auto_learned_psn_step = 1;

        // total_valid_expected  = 0;
        reset(curr_psn);
        return;
    }

    const uint32_t prev_psn = last_psn;
    const uint32_t delta_forward = (curr_psn >= prev_psn) ? (curr_psn - prev_psn) : 0;
    const uint32_t delta_backward = (prev_psn > curr_psn) ? (prev_psn - curr_psn) : 0;


    // ==============================================================
    // 【第一层】PSN 变小：只处理 回绕 / QP重置 / 重传 / 迟到包
    // ==============================================================
    if (curr_psn < prev_psn)
    {
        // --------------------------
        // 1. QP 重置（巨大回退，超过 PSN_WRAP_THRESHOLD）
        // --------------------------
        if (delta_backward  > PSN_WRAP_THRESHOLD)
        {
            // ----------------------
            // QP 重置 / 会话重建
            // ----------------------
            item.is_qp_reset   = true;
            item.is_psn_jump   = true;
            item.is_fake_delay = true;

            retrans_count      = 0;
            lost_packets       = 0;
            total_valid_expected = 0;

            // 全部重置，开启新流
            reset(curr_psn);
            // first_psn = curr_psn;
            // last_psn  = curr_psn;
            // max_psn   = curr_psn;
            // expected_psn = curr_psn;
            // step_learned_flag = false;
            // auto_learned_psn_step = 1;
            return;
        }
        // ----------------------
        // 2. 正常 32位 PSN 回绕（从最大值回到 0 附近）
        // ----------------------
        else if (delta_backward  <= PSN_WRAP_THRESHOLD)
        {
            item.is_psn_wrap   = true;
            item.is_fake_delay = true;

            // ✅ 回绕不清除历史统计（只重置序列）
            first_psn = curr_psn;
            last_psn  = curr_psn;
            max_psn   = curr_psn;
            expected_psn = curr_psn;
            step_learned_flag = false;
            auto_learned_psn_step = 1;
            return;
        }


        // ======================================================
        // 3.回溯间隔重传（旧包远回）
        // 场景：10,11,12,13,14,15,10
        // 新包已经前进，回头重传老旧未确认PSN，协议合法、属于重传、伪延时
        // 特点：curr_psn < 历史最大PSN(last_psn)，且不是跳变、不是回绕
        // ======================================================
        if (curr_psn < prev_psn && curr_psn <= prev_psn - auto_learned_psn_step * 2)
        {
            retrans_count++;
            item.is_retrans    = true;
            item.is_fake_delay = true;
            return;
        }

        // ============================
        // 4. 网络晚到包
        // ============================

        item.is_fake_delay    = true;
        return;
    }

    // ==============================================================
    // 【第二层】PSN 相等：紧邻重传
    // ==============================================================
    if (curr_psn == prev_psn)
    {
        retrans_count++;
        item.is_retrans    = true;
        item.is_fake_delay = true; //伪延时
        return;
    }

    // ==============================================================
    // 【第三层】PSN 增大：正常包 / 丢包 / 大跳变丢包
    // ==============================================================
    const uint32_t real_step = (curr_psn >= prev_psn) ? (curr_psn - prev_psn) : 0;
    // 自动学习步长（支持 +1 +2 +4 +N）
    if (!step_learned_flag )
    {
        auto_learned_psn_step = real_step;
        step_learned_flag     = true;
    }

    // 计算期望的下一个 PSN
    expected_psn = (last_psn + auto_learned_psn_step) & PSN_MASK;
    uint32_t jump = (curr_psn > expected_psn) ? (curr_psn - expected_psn) : 0;

    // ==========================================
    //  1. 正常有序包
    // ==========================================
    if (curr_psn == expected_psn)
    {
        total_valid_expected++; // 每次收到有效包，增加一次有效期望
        last_psn = curr_psn;
        if (curr_psn > max_psn) max_psn = curr_psn;
        expected_psn = last_psn + auto_learned_psn_step;
        return;
    }

    // ==========================================
    // 2. 异常大跳变（严重丢包）
    // 这种情况通常是 Go-back-N 重传导致的批量丢包
    // ==========================================
    if (jump > PSN_LARGE_JUMP)
    {
        // 记录为大跳变事件
        item.is_large_jump = true;
        item.is_fake_delay = true;
        item.is_lost_recovery = true;

        // 累加丢包数（跳跃幅度就是丢失的包数）
        lost_packets += jump;
        total_valid_expected++; // 当前这个包是有效的

        // 更新 PSN 基线（跳过丢失的区间）
        last_psn = curr_psn;
        if (curr_psn > max_psn) max_psn = curr_psn;

        // 重新计算期望值
        expected_psn = last_psn + auto_learned_psn_step;
        return;
    }

    // --------------------------
    // 3. 普通丢包（小幅度跳跃）
    // --------------------------
    if (jump > 0)
    {
        item.is_lost_recovery = true;
        item.is_fake_delay = true;

        lost_packets += jump;
        total_valid_expected++;    // 丢包恢复后的这个包，是一个有效包

        last_psn = curr_psn;
        if (curr_psn > max_psn) max_psn = curr_psn;
        expected_psn = last_psn + auto_learned_psn_step;
        return;
    }

    // --------------------------
    // 4. 其他异常情况（安全兜底）
    // --------------------------
    item.is_fake_delay = true;
    last_psn = curr_psn;
    if (curr_psn > max_psn) max_psn = curr_psn;
    expected_psn = last_psn + auto_learned_psn_step;
}

// 重传率 %
double QPFlowAnalytics::get_retrans_rate() const
{
    if (packets == 0) return 0.0;
    return (retrans_count * 100.0) / packets;
}

// 丢包率 %
double QPFlowAnalytics::get_lost_rate() const
{
    uint64_t real_lost = total_lost;
    uint64_t total = total_valid_expected + real_lost;
    if (total == 0) return 0.0;
    return (real_lost * 100.0) / total;
}

// 真实丢包数（黄金公式，与步长无关）
uint64_t QPFlowAnalytics::get_real_lost_packets() const
{
    return total_lost; // 直接返回累加的真实丢包数
}

// ==============================================
// 最终计算所有指标
// ==============================================
void QPFlowAnalytics::finalize_all()
{
    // 先调用父类：丢包率、重传率、平均包间隔计算
    finalize();

    const size_t total_point = timeline.size();
    if (total_point == 0)
        return;

    // 延迟统计所有平均值：仅最终计算一次
    int64_t sum_delay = 0;
    int64_t sum_jitter = 0;
    int64_t sum_rtt = 0;

    size_t valid_delay_cnt = 0;
    size_t rtt_valid_cnt = 0;

    // 单次遍历全量求和，后续统一除法求平均
    for (const auto& p : timeline)
    {
        sum_jitter += p.jitter_us;

        // 仅统计真实有效时延：排除重传/丢包恢复/PSN跳变伪延时
        if (p.delay_us > 0 && !p.is_fake_delay)
        {
            sum_delay += p.delay_us;
            valid_delay_cnt++;
        }

        if(p.is_large_jump)
            large_jump_count++;

        if(p.is_qp_reset)
            qp_reset_count++;

        if(p.is_psn_wrap)
            psn_wrap_count++;

        if(p.is_pause || p.is_pfc)
            pfc_pause_count++;

        // RTT有效数据统计
        if (p.rtt_us > 0)
        {
            sum_rtt += p.rtt_us;
            rtt_valid_cnt++;
        }
    }

    // 均值计算
    avg_delay = valid_delay_cnt > 0 ? sum_delay / static_cast<int64_t>(valid_delay_cnt) : 0;
    avg_jitter = sum_jitter / static_cast<int64_t>(total_point);
    avg_rtt = rtt_valid_cnt > 0 ? sum_rtt / static_cast<int64_t>(rtt_valid_cnt) : 0;

    request_map.clear();
}

// ======================================================
// 自定义间隔、抖动阈值手动设置接口
// ======================================================
void QPFlowAnalytics::set_threshold(int64_t latency_thresh, int64_t jitter_thresh)
{
    latency_spike_threshold_us = latency_thresh;
    jitter_high_threshold_us = jitter_thresh;
}

// ======================================================
// 【新增】自定义PSN跳变阈值设置接口
// ======================================================
void QPFlowAnalytics::set_psn_jump_threshold(uint32_t threshold)
{
    psn_jump_threshold = threshold;
}

void QPFlowAnalytics::reset(uint32_t curr_psn)
{
    first_psn             = curr_psn;
    last_psn              = curr_psn;
    max_psn               = curr_psn;
    expected_psn          = curr_psn;
    step_learned_flag     = false;
    auto_learned_psn_step = 1;

    total_valid_expected  = 0;

    large_jump_count = 0;   // 大跳变次数
    qp_reset_count = 0;     // QP 重置次数
    psn_wrap_count = 0;     // PSN 回绕次数
    pfc_pause_count = 0;        // pfc_pause 次数
    total_valid_expected = 0; // 累计有效的期望包数（排除大跳变跳过的不连续区间）
}

// ==============================
// 一键档位切换（内置三档行业标准预设，最实用）
// 严格/标准/宽松，覆盖所有客户场景，无需客户记数值
// ==============================
void QPFlowAnalytics::set_alert_level(AlertLevel level)
{
    switch (level)
    {
    case AlertLevel::rigorous:    // 严格：AI训练、核心存储RDMA
        latency_spike_threshold_us = 5000;    // 5ms
        jitter_high_threshold_us = 500;        // 0.5ms
        break;
    case AlertLevel::STANDARD:  // 标准：默认、中移IDC、信而泰交付通用
        latency_spike_threshold_us = 10000;   // 10ms
        jitter_high_threshold_us = 2000;      // 2ms
        break;
    case AlertLevel::LOOSE:     // 宽松：非核心流量、跨机房业务
        latency_spike_threshold_us = 50000;   // 50ms
        jitter_high_threshold_us = 5000;      // 5ms
        break;
    }
}

// ==============================================
// 工具函数
// ==============================================
bool QPFlowAnalytics::is_request_opcode(uint8_t op)
{
     // SEND/WRITE/READ 等请求类操作码
    return op == 0x00 || op == 0x02 || op == 0x04 || op == 0x06 || op == 0x08;
}

bool QPFlowAnalytics::is_ack_opcode(uint8_t op)
{
    // ACK 系列操作码
    return op == 0x01 || op == 0x03 || op == 0x05 || op == 0x07;
}
