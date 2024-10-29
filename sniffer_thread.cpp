#include "network_sniffer.h"
#include <iostream>
using namespace std;
SnifferThread::SnifferThread(QObject* parent) : QThread(parent), handle(nullptr), sniffing(false) {}

void SnifferThread::startSniffing(const int netInterfaceIndex) {
    sniffing = true;
    _netInterfaceIndex = netInterfaceIndex;
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

    while (sniffing && (res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        packet_handler( header, data);
    }
    pcap_close(handle);
}

QString SnifferThread::formatMacAddress(const u_char* mac) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0'));
}

void SnifferThread::packet_handler(const struct pcap_pkthdr* header, const u_char* packet) {
    const struct ethhdr* eth = (struct ethhdr*)packet;

    QString src_mac = formatMacAddress(eth->src);
    QString dest_mac = formatMacAddress(eth->dest);
    
    // �����̫������
    if (ntohs(eth->type) == 0x0800) { // IP
        Packet* pkt = new Packet;
        packets.append(pkt);
        packets[index]->seq = index + 1;
        struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_SIZE);
        handleIP(ip, packet, header);
        emit packetCaptured(
            packets[index]->seq,
            packets[index]->time,
            packets[index]->src,
            packets[index]->dest,
            packets[index]->protocol,
            packets[index]->length,
            packets[index]->info);
        index++;
    }
    else if (ntohs(eth->type) == 0x0806) { // ARP
        Packet* pkt = new Packet;
        packets.append(pkt);
        packets[index]->seq = index + 1;
        struct arphdr* arp = (struct arphdr*)(packet + sizeof(struct ethhdr));
        handleARP(arp, header);
        emit packetCaptured(
            packets[index]->seq,
            packets[index]->time,
            packets[index]->src,
            packets[index]->dest,
            packets[index]->protocol,
            packets[index]->length,
            packets[index]->info);
        index++;
    }
    else if (ntohs(eth->type) == 0x86DD) { // IPv6
        Packet* pkt = new Packet;
        packets.append(pkt);
        packets[index]->seq = index + 1;
        struct iphdr6* ip6 = (struct iphdr6*)(packet + ETHERNET_SIZE);
        handleIPv6(ip6, packet, header);
        emit packetCaptured(
            packets[index]->seq,
            packets[index]->time,
            packets[index]->src,
            packets[index]->dest,
            packets[index]->protocol,
            packets[index]->length,
            packets[index]->info);
        index++;
    }
}

void SnifferThread::handleIP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    switch (ip->protocol) {
    case IPPROTO_ICMP:
        handleICMP(ip, packet, header);
        break;
;   case IPPROTO_TCP:
        handleTCP(ip, packet, header);
        break;
    case IPPROTO_UDP:
        handleUDP(ip, packet, header);
        break;
    default:
        packets[index]->protocol = "Others";
        break;
    }

    // ����������Ϣ
    packets[index]->src = QString(inet_ntoa(ip->saddr));
    packets[index]->dest = QString(inet_ntoa(ip->daddr));
    packets[index]->length = ntohs(ip->tot_len);
    struct timeval ts = header->ts;
    if (index == 0) {
        first_timestamp = ts;
        packets[index]->time = 0;
    }
    else {
        long time_diff_sec = header->ts.tv_sec - first_timestamp.tv_sec;
        long time_diff_usec = header->ts.tv_usec - first_timestamp.tv_usec;
        packets[index]->time = time_diff_sec + time_diff_usec / 1e6;
    }
}

void SnifferThread::handleIPv6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header) {
    // ��鴫���Э��
    switch (ip6->next_header) {
    case IPPROTO_TCP: {
        handleTCP6(ip6, packet, header);
        break;
    }
    case IPPROTO_UDP: {
        handleUDP6(ip6, packet, header);
        break;
    }
    case IPPROTO_ICMPV6: {
        handleICMP6(ip6, packet, header);
        break;
    }
    default:
        packets[index]->protocol = "Others";
        break;
    }
    // ����IPv6������Ϣ
    char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->saddr, str, sizeof(str));
    packets[index]->src = str;
    inet_ntop(AF_INET6, &ip6->daddr, str, sizeof(str));
    packets[index]->dest = str;
    packets[index]->length = 40;
    struct timeval ts = header->ts;
    if (index == 0) {
        first_timestamp = ts;
        packets[index]->time = 0;
    }
    else {
        long time_diff_sec = header->ts.tv_sec - first_timestamp.tv_sec;
        long time_diff_usec = header->ts.tv_usec - first_timestamp.tv_usec;
        packets[index]->time = time_diff_sec + time_diff_usec / 1e6;
    }
}

void SnifferThread::handleARP(const struct arphdr* arp, const struct pcap_pkthdr* header) {
    packets[index]->protocol = "ARP";
    // ���� ARP ��Ϣ
    QString arp_src_mac = formatMacAddress(arp->sha);
    QString src = QString("%1.%2.%3.%4").arg(arp->spa[0]).arg(arp->spa[1]).arg(arp->spa[2]).arg(arp->spa[3]);
    QString arp_dest_mac = formatMacAddress(arp->tha);
    QString dest = QString("%1.%2.%3.%4").arg(arp->tpa[0]).arg(arp->tpa[1]).arg(arp->tpa[2]).arg(arp->tpa[3]);
    packets[index]->src = src;
    packets[index]->dest = dest;
    if (ntohs(arp->oper) == 1) { // ARP ����
        packets[index]->info = QString("Who has %1? Tell %2")
            .arg(arp_src_mac).arg(src);
    }
    else if (ntohs(arp->oper) == 2) { // ARP ��Ӧ
        packets[index]->info = QString("%1 is at %2")
            .arg(dest).arg(arp_dest_mac);
    }
    else {
        packets[index]->info = "Unknown ARP Operation";
    }
    // ����ARP������Ϣ
    packets[index]->length = 28;
    struct timeval ts = header->ts;
    if (index == 0) {
        first_timestamp = ts;
        packets[index]->time = 0;
    }
    else {
        long time_diff_sec = header->ts.tv_sec - first_timestamp.tv_sec;
        long time_diff_usec = header->ts.tv_usec - first_timestamp.tv_usec;
        packets[index]->time = time_diff_sec + time_diff_usec / 1e6;
    }
}

void SnifferThread::handleTCP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    // TCP �����߼�
    packets[index]->protocol = "TCP";
    int ip_header_size = ip->ihl * 4;  // IP ͷ������
    struct tcphdr* tcp = (struct tcphdr*)(packet + ETHERNET_SIZE + ip_header_size);
    // ��ȡԴ�˿ں�Ŀ��˿�
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    packets[index]->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // ���Ŀ��˿��� 80����Ϊ HTTP
    cout << src_port << " " << dst_port << endl;
    if (dst_port == 80 || src_port == 80) {
        // ���� TCP ͷ���Ĵ�С
        packets[index]->protocol = "HTTP";
        int tcp_header_size = tcp->doff * 4;

        // ��ȡ HTTP ���ݵ���ʼλ��
        const unsigned char* http_data = packet + ETHERNET_SIZE + ip_header_size + tcp_header_size;
        int http_data_length = header->caplen - (ETHERNET_SIZE + ip_header_size + tcp_header_size);

        // �� HTTP ���ݴ��� Packet �ṹ��
        if (http_data_length > 0) {
            packets[index]->info = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
            /*bool isText = true;
            for (int i = 0; i < http_data_length; ++i) {
                if (!isprint(http_data[i]) && http_data[i] != '\r' && http_data[i] != '\n') {

                    break;
                }
            }
            if (isText) {
                packets[index]->info = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
            }
            else {
                packets[index]->info = "Binary Data";
            }*/
        }
        else {
            packets[index]->info = "No HTTP Data";
        }
    }
}

void SnifferThread::handleTCP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header) {
    // TCP �����߼�
    packets[index]->protocol = "TCP";
    int ip6_header_size = 40;  // IP ͷ������
    struct tcphdr* tcp = (struct tcphdr*)(packet + ETHERNET_SIZE + ip6_header_size);
    // ��ȡԴ�˿ں�Ŀ��˿�
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    packets[index]->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // ���Ŀ��˿��� 80����Ϊ HTTP
    cout << src_port << " " << dst_port << endl;
    if (dst_port == 80 || src_port == 80) {
        // ���� TCP ͷ���Ĵ�С
        packets[index]->protocol = "HTTP";
        int tcp_header_size = tcp->doff * 4;

        // ��ȡ HTTP ���ݵ���ʼλ��
        const unsigned char* http_data = packet + ETHERNET_SIZE + ip6_header_size + tcp_header_size;
        int http_data_length = header->caplen - (ETHERNET_SIZE + ip6_header_size + tcp_header_size);

        // �� HTTP ���ݴ��� Packet �ṹ��
        if (http_data_length > 0) {
            packets[index]->info = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
            /*bool isText = true;
            for (int i = 0; i < http_data_length; ++i) {
                if (!isprint(http_data[i]) && http_data[i] != '\r' && http_data[i] != '\n') {

                    break;
                }
            }
            if (isText) {
                packets[index]->info = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
            }
            else {
                packets[index]->info = "Binary Data";
            }*/
        }
        else {
            packets[index]->info = "No HTTP Data";
        }
    }
}

void SnifferThread::handleICMP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header) {
    // ƫ�Ƶ� IPv6 ͷ����ICMPv6 ��������ʼλ��
    int ip6_header_size = sizeof(struct iphdr6);
    struct icmphdr6* icmp6 = (struct icmphdr6*)(packet + ETHERNET_SIZE + ip6_header_size);

    // ���� ICMPv6 �� type �� code
    switch (icmp6->type) {
    case 135:  // �ھ�����
        packets[index]->info = "Neighbor Solicitation";
        break;
    case 136:   // �ھ�ͨ��
        packets[index]->info = "Neighbor Advertisement";
        break;
    case 128:   // �������� (Ping)
        packets[index]->info = "ICMPv6 Echo Request";
        break;
    case 129:     // ����Ӧ�� (Ping Response)
        packets[index]->info = "ICMPv6 Echo Reply";
        break;
    default:
        packets[index]->info = QString("ICMPv6 Type: %1, Code: %2")
            .arg(icmp6->type)
            .arg(icmp6->code);
        break;
    }

    // ʱ�������
    struct timeval ts = header->ts;
    if (index == 0) {
        first_timestamp = ts;
        packets[index]->time = 0;
    }
    else {
        long time_diff_sec = ts.tv_sec - first_timestamp.tv_sec;
        long time_diff_usec = ts.tv_usec - first_timestamp.tv_usec;
        packets[index]->time = time_diff_sec + time_diff_usec / 1e6;
    }
}

void SnifferThread::handleUDP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header) {
    // UDP �����߼�
    packets[index]->protocol = "UDP";
    struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr6));
    packets[index]->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS �����߼�
        packets[index]->protocol = "DNS";
        int ip6_header_size = 40;  // IP ͷ������
        // ��ȡ DNS ���ݰ�����Ϣ
        const u_char* dns_data = packet + ETHERNET_SIZE + ip6_header_size + sizeof(struct udphdr);
        int dns_length = header->caplen - (ETHERNET_SIZE + ip6_header_size + sizeof(struct udphdr));

        // ���� DNS ���ݰ�������ʵ�ֿ��Ը�����Ҫ��д
        if (dns_length > 0) {
            // ��������� DNS ���ݰ����ݲ���� packets[index]->info
            // ʾ��: �������Ǽ򵥴�ӡԭʼ����
            packets[index]->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            packets[index]->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
}

void SnifferThread::handleICMP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    // ICMP �����߼�
    packets[index]->protocol = "ICMP";
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (icmp->type == 8) { // ICMP ����
        packets[index]->info = "ICMP Echo (ping) request";
    }
    else if (icmp->type == 0) { // ICMP ��Ӧ
        packets[index]->info = "ICMP Echo (ping) reply";
    }
}

void SnifferThread::handleUDP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    // UDP �����߼�
    packets[index]->protocol = "UDP";
    int ip_header_size = ip->ihl * 4;  // IP ͷ������
    struct udphdr* udp = (struct udphdr*)(packet + ETHERNET_SIZE + ip_header_size);
    packets[index]->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS �����߼�
        packets[index]->protocol = "DNS";
        int ip_header_size = ip->ihl * 4;  // IP ͷ������
        // ��ȡ DNS ���ݰ�����Ϣ
        const u_char* dns_data = packet + ETHERNET_SIZE + ip_header_size + sizeof(struct udphdr);
        int dns_length = header->caplen - (ETHERNET_SIZE + ip_header_size + sizeof(struct udphdr));

        // ���� DNS ���ݰ�������ʵ�ֿ��Ը�����Ҫ��д
        if (dns_length > 0) {
            // ��������� DNS ���ݰ����ݲ���� packets[index]->info
            // ʾ��: �������Ǽ򵥴�ӡԭʼ����
            packets[index]->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            packets[index]->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
}
