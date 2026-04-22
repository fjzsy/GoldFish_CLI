#ifndef PROTOCOL_LAYERS_H
#define PROTOCOL_LAYERS_H

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <map>
#include "packet_info_extended.h"

#pragma pack(push,1)
// 解析结果的可视化表示
struct ProtocolField {
    std::string name;           // 字段名
    std::string value;          // 字段值（字符串）
    std::string description;    // 字段描述
    std::string hexValue;       // 十六进制表示
    std::string binaryValue;    // 二进制表示
    uint64_t rawValue;          // 原始值
    uint32_t bitOffset;         // 位偏移
    uint32_t bitLength;         // 位长度

    // 可视化属性
    std::string color;          // 显示颜色
    bool highlighted;           // 是否高亮
};

struct ProtocolLayer {
    std::string name;                    // 层名称（Ethernet/IP/UDP/BTH等）
    std::vector<ProtocolField> fields;   // 字段列表
    uint32_t startOffset;                // 在包中的起始偏移
    uint32_t length;                     // 层长度（字节）
    std::string description;             // 层描述
    std::string hexDump;                 // 该层的十六进制转储

    // 添加字段的辅助方法
    void addField(const std::string& name, const std::string& value,
                  uint32_t offset, uint32_t length, const std::string& desc = "") {
        ProtocolField field;
        field.name = name;
        field.value = value;
        field.bitOffset = offset * 8;
        field.bitLength = length * 8;
        field.description = desc;
        this->fields.push_back(field);
    }
};

// 完整的包解析结果
struct PacketAnalysis : public PacketInfo {
    uint64_t flowKey;                   // 预计算的流标识
    uint32_t anomalyScore;               // 异常分数

    // ============ 采样标记 ============
    bool isSampled;

    // ============ PFC标记 ============
    bool isPFC;
    bool isPause;
    uint8_t pfc_priority;    // PFC优先级

    uint64_t pfcClassEnableMask;
    uint16_t pfcPauseTime;


    // ============ 显示层（只在采样时生成） ============
    std::vector<ProtocolLayer> layers;

    // ============ 构造函数 ============
    PacketAnalysis() : isSampled(false), flowKey(0), anomalyScore(0) {}

     // 从 PacketInfo 构造
    explicit PacketAnalysis(const PacketInfo& info)
         : PacketInfo(info)
         , flowKey(((uint64_t)info.ip.srcIp << 32) | info.bth.qpNum)
         , isSampled(false)
         , anomalyScore(0) {
    }
};
#pragma pack(pop)
#endif // PROTOCOL_LAYERS_H
