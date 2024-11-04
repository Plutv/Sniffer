#pragma once

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <QString>
// 以太网头部
struct ethhdr {
    u_char dest[6];   // 目的 MAC 地址
    u_char src[6];    // 源 MAC 地址
    u_short type;     // 以太网类型
};

// IP 头部
struct iphdr {
    u_char ihl : 4;         // 首部长度
    u_char version : 4;     // 版本
    u_char tos;             // 服务类型
    u_short tot_len;        // 总长度
    u_short id;             // 标识符
    u_short frag_off;       // 分片偏移
    u_char ttl;             // 生存时间
    u_char protocol;        // 协议
    u_short check;          // 校验和
    struct in_addr saddr;   // 源地址
    struct in_addr daddr;   // 目的地址
};

// IPv6 头部
struct iphdr6 {
    u_int version : 4;   // 版本
    u_int traffic_class : 8; // 流量类别
    u_int flow_label : 20;   // 流标签
    u_short payload_len;       // 负载长度
    u_char next_header;        // 下一个头部
    u_char hop_limit;          // 跳数限制
    struct in6_addr saddr;      // 源地址
    struct in6_addr daddr;      // 目的地址
};

// TCP 头部
struct tcphdr {
    u_short src_port;
    u_short dst_port;
    u_int seq;
    u_int ack_seq;
    u_char res1 : 4, doff : 4;
    u_char fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    u_short window;
    u_short check;
    u_short urg_ptr;
};

// UDP 头部
struct udphdr {
    u_short source;       // 源端口
    u_short dest;         // 目标端口
    u_short length;       // 数据包长度
    u_short checksum;     // 校验和
};

// ICMP 头部
struct icmphdr {
    u_char type;          // ICMP 类型
    u_char code;          // ICMP 代码
    u_short checksum;     // 校验和
    union {
        struct {
            u_short id;   // 标识符
            u_short seq;  // 序列号
        } echo;            // Echo 请求/响应特有字段
        u_int gateway;  // 网关地址 (用于重定向)
        struct {
            u_short unused;   // 未使用字段
            u_short mtu;      // Path MTU
        } frag;               // 分段错误特有字段
    } un;
};

// ICMPv6 头部
struct icmphdr6 {
    u_char type;          // ICMPv6 类型
    u_char code;          // ICMPv6 代码
    u_short checksum;     // 校验和
    u_int reserved;     // 保留字段
};

// DNS 头部
struct dnshdr {
    u_short id;               // Transaction ID
    u_char rd : 1;             // Recursion Desired
    u_char tc : 1;             // Truncated
    u_char aa : 1;             // Authoritative Answer
    u_char opcode : 4;         // Opcode
    u_char qr : 1;             // Query/Response Flag
    u_char rcode : 4;          // Response Code
    u_char cd : 1;             // Checking Disabled
    u_char ad : 1;             // Authenticated Data
    u_char z : 1;              // Reserved
    u_char ra : 1;             // Recursion Available
    u_short qdcount;          // Question Count
    u_short ancount;          // Answer Count
    u_short nscount;          // Authority Record Count
    u_short arcount;          // Additional Record Count
    // 转换标志位为16位整数
    u_short getFlags() const {
        return (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) |
            (rd << 8) | (ra << 7) | (z << 6) | (ad << 5) | (cd << 4) | rcode;
    }

    // 打印标志位为十六进制格式
    QString flagsToHexString() const {
        u_short flags = getFlags();
        char buffer[6];
        sprintf(buffer, "0x%04x", flags);
        return QString(buffer);
    }
};


// ARP 头部
struct arphdr {
    u_short htype;          // 硬件类型
    u_short ptype;          // 协议类型
    u_char hlen;            // 硬件地址长度
    u_char plen;            // 协议地址长度
    u_short oper;           // 操作码
    u_char sha[6];          // 发送方 MAC 地址
    u_char spa[4];          // 发送方 IP 地址
    u_char tha[6];          // 目标 MAC 地址
    u_char tpa[4];          // 目标 IP 地址
};
// 数据包记录结构
struct Packet {
    int seq = -1;              // 序号
    QString time = "";        // 时间戳
    QString src = "";          // 源地址
    QString dest = "";         // 目的地址
    QString protocol = "";     // 协议类型
    int length = -1;           // 数据包长度
    QString info = "";         // 相关信息
    int data_len = -1;         // 应用层数据信息

    // 链路层头指针
    struct ethhdr* ethh = nullptr;
    // 网络层头指针
    struct iphdr* iph = nullptr;
    struct iphdr6* iph6 = nullptr;
    struct arphdr* arph = nullptr;
    // 传输层头指针
    struct tcphdr* tcph = nullptr;
    struct udphdr* udph = nullptr;
    struct icmphdr* icmph = nullptr;
    struct icmphdr6* icmph6 = nullptr;
    // 应用层数据
    void* http_data = nullptr;
    void* dns_data = nullptr;
};

#endif // PROTOCOL_H
