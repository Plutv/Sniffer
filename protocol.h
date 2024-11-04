#pragma once

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <QString>
// ��̫��ͷ��
struct ethhdr {
    u_char dest[6];   // Ŀ�� MAC ��ַ
    u_char src[6];    // Դ MAC ��ַ
    u_short type;     // ��̫������
};

// IP ͷ��
struct iphdr {
    u_char ihl : 4;         // �ײ�����
    u_char version : 4;     // �汾
    u_char tos;             // ��������
    u_short tot_len;        // �ܳ���
    u_short id;             // ��ʶ��
    u_short frag_off;       // ��Ƭƫ��
    u_char ttl;             // ����ʱ��
    u_char protocol;        // Э��
    u_short check;          // У���
    struct in_addr saddr;   // Դ��ַ
    struct in_addr daddr;   // Ŀ�ĵ�ַ
};

// IPv6 ͷ��
struct iphdr6 {
    u_int version : 4;   // �汾
    u_int traffic_class : 8; // �������
    u_int flow_label : 20;   // ����ǩ
    u_short payload_len;       // ���س���
    u_char next_header;        // ��һ��ͷ��
    u_char hop_limit;          // ��������
    struct in6_addr saddr;      // Դ��ַ
    struct in6_addr daddr;      // Ŀ�ĵ�ַ
};

// TCP ͷ��
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

// UDP ͷ��
struct udphdr {
    u_short source;       // Դ�˿�
    u_short dest;         // Ŀ��˿�
    u_short length;       // ���ݰ�����
    u_short checksum;     // У���
};

// ICMP ͷ��
struct icmphdr {
    u_char type;          // ICMP ����
    u_char code;          // ICMP ����
    u_short checksum;     // У���
    union {
        struct {
            u_short id;   // ��ʶ��
            u_short seq;  // ���к�
        } echo;            // Echo ����/��Ӧ�����ֶ�
        u_int gateway;  // ���ص�ַ (�����ض���)
        struct {
            u_short unused;   // δʹ���ֶ�
            u_short mtu;      // Path MTU
        } frag;               // �ֶδ��������ֶ�
    } un;
};

// ICMPv6 ͷ��
struct icmphdr6 {
    u_char type;          // ICMPv6 ����
    u_char code;          // ICMPv6 ����
    u_short checksum;     // У���
    u_int reserved;     // �����ֶ�
};

// DNS ͷ��
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
    // ת����־λΪ16λ����
    u_short getFlags() const {
        return (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) |
            (rd << 8) | (ra << 7) | (z << 6) | (ad << 5) | (cd << 4) | rcode;
    }

    // ��ӡ��־λΪʮ�����Ƹ�ʽ
    QString flagsToHexString() const {
        u_short flags = getFlags();
        char buffer[6];
        sprintf(buffer, "0x%04x", flags);
        return QString(buffer);
    }
};


// ARP ͷ��
struct arphdr {
    u_short htype;          // Ӳ������
    u_short ptype;          // Э������
    u_char hlen;            // Ӳ����ַ����
    u_char plen;            // Э���ַ����
    u_short oper;           // ������
    u_char sha[6];          // ���ͷ� MAC ��ַ
    u_char spa[4];          // ���ͷ� IP ��ַ
    u_char tha[6];          // Ŀ�� MAC ��ַ
    u_char tpa[4];          // Ŀ�� IP ��ַ
};
// ���ݰ���¼�ṹ
struct Packet {
    int seq = -1;              // ���
    QString time = "";        // ʱ���
    QString src = "";          // Դ��ַ
    QString dest = "";         // Ŀ�ĵ�ַ
    QString protocol = "";     // Э������
    int length = -1;           // ���ݰ�����
    QString info = "";         // �����Ϣ
    int data_len = -1;         // Ӧ�ò�������Ϣ

    // ��·��ͷָ��
    struct ethhdr* ethh = nullptr;
    // �����ͷָ��
    struct iphdr* iph = nullptr;
    struct iphdr6* iph6 = nullptr;
    struct arphdr* arph = nullptr;
    // �����ͷָ��
    struct tcphdr* tcph = nullptr;
    struct udphdr* udph = nullptr;
    struct icmphdr* icmph = nullptr;
    struct icmphdr6* icmph6 = nullptr;
    // Ӧ�ò�����
    void* http_data = nullptr;
    void* dns_data = nullptr;
};

#endif // PROTOCOL_H
