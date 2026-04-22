#ifndef PROTOCOL_PARSER_FACTORY_H
#define PROTOCOL_PARSER_FACTORY_H

#include <iomanip>
#pragma once

#include "protocol_layers.h"
#include <memory>
#include <sstream>

// 解析器基类
class ProtocolParser {
public:
    virtual ~ProtocolParser() = default;

    // 解析方法
    virtual bool parse(const uint8_t* data, uint32_t length,
                       PacketAnalysis& analysis, uint32_t offset = 0) = 0;

    // 获取解析器名称
    virtual std::string getName() const = 0;

    // 获取该层协议的典型长度
    virtual uint32_t getHeaderLength() const = 0;


    // ============ 整数提取方法（全部内联，无分支） ============

    // 提取1字节
    static inline uint8_t getU8(const uint8_t* data, uint32_t offset) {
        return data[offset];
    }

    // 提取2字节（大端）
    static inline uint16_t getU16(const uint8_t* data, uint32_t offset) {
        return (uint16_t)data[offset] << 8 | data[offset + 1];
    }

    // 提取3字节（大端）
    static inline uint32_t getU24(const uint8_t* data, uint32_t offset) {
        return (uint32_t)data[offset] << 16 |
               (uint32_t)data[offset + 1] << 8 |
               data[offset + 2];
    }

    // 提取4字节（大端）
    static inline uint32_t getU32(const uint8_t* data, uint32_t offset) {
        return (uint32_t)data[offset] << 24 |
               (uint32_t)data[offset + 1] << 16 |
               (uint32_t)data[offset + 2] << 8 |
               data[offset + 3];
    }

    // 提取8字节（大端）
    static inline uint64_t getU64(const uint8_t* data, uint32_t offset) {
        return ((uint64_t)getU32(data, offset) << 32) |
               getU32(data, offset + 4);
    }

    // 提取MAC地址（返回uint64_t，低48位有效）
    static inline uint64_t getMac(const uint8_t* data, uint32_t offset) {
        uint64_t mac = 0;
        for (int i = 0; i < 6; i++) {
            mac = (mac << 8) | data[offset + i];
        }
        return mac;
    }

    // ============ 字符串方法单独保留（用于显示层） ============

        // 将MAC整数转字符串（只在生成layer时调用）
        static std::string macToString(uint64_t mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 (uint8_t)(mac >> 40), (uint8_t)(mac >> 32),
                 (uint8_t)(mac >> 24), (uint8_t)(mac >> 16),
                 (uint8_t)(mac >> 8), (uint8_t)mac);
        return std::string(buf);
    }

    // 将IP整数转字符串
    static std::string ipToString(uint32_t ip) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
        return std::string(buf);
    }

    // ============ 字节序转换（用内置函数替代） ============

    static inline uint16_t ntoh16(uint16_t val) {
        return (val >> 8) | (val << 8);
    }

    // static inline uint32_t ntoh32(uint32_t val) {
    //     return __builtin_bswap32(val);  // 编译器内置，比手动快
    // }

    // static inline uint64_t ntoh64(uint64_t val) {
    //     return __builtin_bswap64(val);
    // }

    // 通用的字段提取方法
    uint8_t extractUint8(const uint8_t* data, uint32_t offset) const {
        return data[offset];
    }

    uint16_t extractUint16(const uint8_t* data, uint32_t offset) const {
        return (data[offset] << 8) | data[offset + 1];
    }

    uint32_t extractUint24(const uint8_t* data, uint32_t offset) const {
        return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    }

    uint32_t extractUint32(const uint8_t* data, uint32_t offset) const {
        return (data[offset] << 24) | (data[offset + 1] << 16) |
               (data[offset + 2] << 8) | data[offset + 3];
    }

    uint64_t extractUint64(const uint8_t* data, uint32_t offset) const {
        uint64_t value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | data[offset + i];
        }
        return value;
    }

    // 提取MAC地址
    std::string extractMacAddress(const uint8_t* data, uint32_t offset) const {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 data[offset], data[offset + 1], data[offset + 2],
                 data[offset + 3], data[offset + 4], data[offset + 5]);
        return std::string(mac);
    }

    // 提取IP地址
    std::string extractIpAddress(const uint8_t* data, uint32_t offset) const {
        char ip[16];
        snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                 data[offset], data[offset + 1],
                 data[offset + 2], data[offset + 3]);
        return std::string(ip);
    }


    // 网络字节序转换
            uint16_t ntohs(uint16_t value) const {
        return (value >> 8) | (value << 8);
    }

    uint32_t ntohl(uint32_t value) const {
        return ((value >> 24) & 0xFF) |
               ((value >> 8) & 0xFF00) |
               ((value << 8) & 0xFF0000) |
               ((value << 24) & 0xFF000000);
    }

    uint64_t ntohll(uint64_t value) const {
        return ((uint64_t)ntohl(value & 0xFFFFFFFF) << 32) | ntohl(value >> 32);
    }
};

// 以太网解析器
class EthernetParser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, uint32_t length,
               PacketAnalysis& analysis, uint32_t offset = 0) override;

    std::string getName() const override { return "Ethernet"; }
    uint32_t getHeaderLength() const override { return 14; }

};

// IPv4解析器
class IPv4Parser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, uint32_t length,
               PacketAnalysis& analysis, uint32_t offset = 0) override;

    std::string getName() const override { return "IPv4"; }
    uint32_t getHeaderLength() const override { return 20; } // 最小长度

private:
    uint8_t getHeaderLengthFromPacket(const uint8_t* data) const {
        return (data[0] & 0x0F) * 4;  // IHL字段
    }
};

// UDP解析器
class UDPParser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, uint32_t length,
               PacketAnalysis& analysis, uint32_t offset = 0) override;

    std::string getName() const override { return "UDP"; }
    uint32_t getHeaderLength() const override { return 8; }
};

// BTH (RoCEv2) 解析器
class BTHParser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, uint32_t length,
               PacketAnalysis& analysis, uint32_t offset = 0) override;

    std::string getName() const override { return "BTH"; }
    uint32_t getHeaderLength() const override { return 12; }

private:
    std::string getOpcodeName(uint8_t opcode) const;
    std::string getOpcodeDescription(uint8_t opcode) const;
};

// RETH解析器
class RETHParser : public ProtocolParser {
public:
    bool parse(const uint8_t* data, uint32_t length,
               PacketAnalysis& analysis, uint32_t offset = 0) override;

    std::string getName() const override { return "RETH"; }
    uint32_t getHeaderLength() const override { return 16; }
};

// 解析器工厂
class ProtocolParserFactory {
public:
    static std::shared_ptr<ProtocolParser> createParser(const std::string& name) {
        if (name == "Ethernet") return std::make_shared<EthernetParser>();
        if (name == "IPv4") return std::make_shared<IPv4Parser>();
        if (name == "UDP") return std::make_shared<UDPParser>();
        if (name == "BTH") return std::make_shared<BTHParser>();
        if (name == "RETH") return std::make_shared<RETHParser>();
        return nullptr;
    }

    static std::vector<std::string> getAvailableParsers() {
        return {"Ethernet", "IPv4", "UDP", "BTH", "RETH"};
    }
};

#endif // PROTOCOL_PARSER_FACTORY_H
