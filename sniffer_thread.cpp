#include "network_sniffer.h"
#include <pcap.h>
#include <winsock2.h>
#include <qdebug.h>

void packet_handler(SnifferThread* _this, const struct pcap_pkthdr* header, const u_char* packet);
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

void SnifferThread::startSniffing(const int netInterfaceIndex) {
    sniffing = true;
    this->_netInterfaceIndex = netInterfaceIndex;
    if (!isRunning()) start();
}

void SnifferThread::stopSniffing() {
    sniffing = false;
    if (handle) pcap_breakloop(handle);
}

void SnifferThread::run() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    QList<QString> interfaces;

    // ��ȡ�����豸�б�
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Error finding devices: " << errbuf;
        return;
    }

    // ѡ���豸
    int dev_num = this->_netInterfaceIndex + 1;
    int i = 0;
    for (device = alldevs; i < dev_num - 1 && device; device = device->next, i++);

    if (device == NULL) {
        qDebug() << "Error, The selected device does not exists!" << endl;
        return;
    }
    
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        qDebug() << "Could not open device:" << errbuf;
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res;
    int num = 0;

    while (sniffing && (res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        packet_handler(this, header, data);
        num++;
    }
    pcap_close(handle);
}

// ������̫��֡�Ĵ�С
#define ETHERNET_SIZE 14

// ��̫��ͷ��
struct ethhdr {
    u_char  dest[6];   // Ŀ�� MAC ��ַ
    u_char  src[6];    // Դ MAC ��ַ
    u_short type;      // ��̫������
};

// IP ͷ��
struct iphdr {
    u_char ihl : 4;         // �ײ�����
    u_char version : 4;     // �汾
    u_char tos;           // ��������
    u_short tot_len;      // �ܳ���
    u_short id;           // ��ʶ��
    u_short frag_off;     // ��Ƭƫ��
    u_char ttl;           // ����ʱ��
    u_char protocol;      // Э��
    u_short check;        // У���
    u_int saddr;          // Դ��ַ
    u_int daddr;          // Ŀ�ĵ�ַ
};

// TCP ͷ��
struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int   seq;
    unsigned int   ack_seq;
    unsigned char  res1 : 4, doff : 4;
    unsigned char  fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

void handle_tcp(const struct pcap_pkthdr* header, const u_char* packet, const struct iphdr* ip);
// ���ݰ�����ص�����
void packet_handler(SnifferThread* _this, const struct pcap_pkthdr* header, const u_char* packet) {
    //printf("Packet captured: Length = %d\n", header->len);

    const struct ethhdr* eth = (struct ethhdr*)packet;
    //printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    //    eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    //printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    //    eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);

    // �����ϲ�Э�飨�� IP �� ARP���������������
    if (ntohs(eth->type) == 0x0800) { // �����̫�������Ƿ�Ϊ IP
        struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_SIZE);
        printf("IP Source: %u.%u.%u.%u\n",
            (ip->saddr & 0xFF),
            (ip->saddr >> 8 & 0xFF),
            (ip->saddr >> 16 & 0xFF),
            (ip->saddr >> 24 & 0xFF));
        printf("IP Destination: %u.%u.%u.%u\n",
            (ip->daddr & 0xFF),
            (ip->daddr >> 8 & 0xFF),
            (ip->daddr >> 16 & 0xFF),
            (ip->daddr >> 24 & 0xFF));
        // ����Э��
        QString _protocol;
        switch (ip->protocol) {
        case IPPROTO_ICMP: // ICMP
            _protocol = "ICMP";
            // ��������Խ�һ������ ICMP ����
            break;
        case IPPROTO_TCP: // TCP
            _protocol = "TCP";
            // ��������Խ�һ������ TCP ����
            handle_tcp(header, packet, ip);
            break;
        case IPPROTO_UDP: // UDP
            _protocol = "UDP";
            // ��������Խ�һ������ UDP ����
            break;
        default:
            break;
        }
        struct IPV4_HDR* ip_header = (struct IPV4_HDR*)(packet + 14);  // 14 is Ethernet header length
        struct timeval ts = header->ts;
        QString src = QString(inet_ntoa(ip_header->ip_srcaddr));
        QString dest = QString(inet_ntoa(ip_header->ip_destaddr));
        QString protocol = _protocol;
        int length = ntohs(ip_header->ip_total_length);

        emit _this->packetCaptured( ts.tv_usec, src, dest, protocol, length, "Info");
    }
}

void handle_tcp(const struct pcap_pkthdr* header, const u_char* packet, const struct iphdr* ip) {
    int ip_header_size = ip->ihl * 4;  // IP ͷ������
    struct tcphdr* tcp = (struct tcphdr*)(packet + ETHERNET_SIZE + ip_header_size);

    // ��ȡԴ�˿ں�Ŀ��˿�
    int src_port = ntohs(tcp->source);
    int dst_port = ntohs(tcp->dest);

    //// ���Ŀ��˿��� 80�����ʾ HTTP ����
    //if (dst_port == 80 || src_port == 80) {
    //    // ���� TCP ͷ���Ĵ�С
    //    int tcp_header_size = tcp->doff * 4;

    //    // ��ȡ HTTP ���ݵ���ʼλ��
    //    const unsigned char* http_data = packet + ETHERNET_SIZE + ip_header_size + tcp_header_size;
    //    int http_data_length = header->caplen - (ETHERNET_SIZE + ip_header_size + tcp_header_size);

    //    // ��ӡ HTTP ����
    //    if (http_data_length > 0) {
    //        printf("HTTP Data:\n");
    //        fwrite(http_data, 1, http_data_length, stdout);  // �� HTTP ���ݴ�ӡ����
    //        printf("\n");
    //    }
    //}
}
