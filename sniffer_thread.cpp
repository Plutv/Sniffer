#include "network_sniffer.h"
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <qdebug.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct IPV4_HDR {
    unsigned char ip_header_len : 4;
    unsigned char ip_version : 4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_offset;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    struct in_addr ip_srcaddr;
    struct in_addr ip_destaddr;
};

SnifferThread::SnifferThread(QObject* parent) : QThread(parent), handle(nullptr), sniffing(false) {}

void SnifferThread::startSniffing(const QString& networkInterface) {
    sniffing = true;
    if (!isRunning()) start();
}

void SnifferThread::stopSniffing() {
    sniffing = false;
    if (handle) pcap_breakloop(handle);
}

void SnifferThread::run() {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        qDebug() << "Could not open device:" << errbuf;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res;

    while (sniffing && (res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;

        struct IPV4_HDR* ip_header = (struct IPV4_HDR*)(data + 14);  // 14 is Ethernet header length

        QString srcIP = QString(inet_ntoa(ip_header->ip_srcaddr));
        QString destIP = QString(inet_ntoa(ip_header->ip_destaddr));
        QString protocol = (ip_header->ip_protocol == IPPROTO_TCP) ? "TCP" :
            (ip_header->ip_protocol == IPPROTO_UDP) ? "UDP" :
            (ip_header->ip_protocol == IPPROTO_ICMP) ? "ICMP" : "OTHER";
        int length = ntohs(ip_header->ip_total_length);

        emit packetCaptured(srcIP, destIP, protocol, length);
    }
    pcap_close(handle);
}
