#include "network_sniffer.h"
#include <iostream>
using namespace std;
SnifferThread::SnifferThread(QObject* parent) : QThread(parent), handle(nullptr), sniffing(false) {}
SnifferThread::~SnifferThread() {
    //for (int i = 0; i < packets.size(); ++i) {
    //    delete packets[i]; // �ͷ�ÿ�� Packet ����ռ�õ��ڴ�
    //}
    //packets.clear(); // ����б��Ƴ�����Ԫ��
}
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

Packet* SnifferThread::getSelectedPacket(int index) {
    if (index < packets.size()) {
        return packets[index];
    }
    else {
        qDebug() << "Selected packet not exits!";
        return nullptr;
    }
}

void SnifferThread::appendPacket() {
    Packet* pkt = new Packet;
    packets.append(pkt);
    packets[index]->seq = index + 1;
    qDebug() << "later: " << packets[index];
}

void SnifferThread::senderSignal() {
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

void SnifferThread::packet_handler(const struct pcap_pkthdr* header, const u_char* data) {
    // �洢���ݰ��ĸ���
    const u_char* packet = new u_char[header->len];
    memcpy((void*)packet, data, header->len);
    struct ethhdr* eth = (struct ethhdr*)packet;
    QString src_mac = formatMacAddress(eth->src);
    QString dest_mac = formatMacAddress(eth->dest);
    if (ntohs(eth->type) == 0x0800 ||
        ntohs(eth->type) == 0x0806 ||
        ntohs(eth->type) == 0x86DD) {
        appendPacket();
    }
    else {
        return;
    }
    packets[index]->ethh = eth;
    packets[index]->length = header->caplen;
    // ������벶���һ�������ʱ��
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
    // �����̫������, IP ARP IPv6
    if (ntohs(eth->type) == 0x0800) { // IP
        struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_SIZE);
        packets[index]->iph = ip;
        handleIP();
    }
    else if (ntohs(eth->type) == 0x0806) { // ARP
        struct arphdr* arp = (struct arphdr*)(packet + ETHERNET_SIZE);
        packets[index]->arph = arp;
        handleARP();
    }
    else if (ntohs(eth->type) == 0x86DD) { // IPv6
        struct iphdr6* ip6 = (struct iphdr6*)(packet + ETHERNET_SIZE);
        packets[index]->iph6 = ip6;
        handleIPv6();
    }
    if (ntohs(eth->type) == 0x0800 ||
        ntohs(eth->type) == 0x0806 ||
        ntohs(eth->type) == 0x86DD) {
        senderSignal();
    }
}

void SnifferThread::handleIP() {
    u_char protocol = packets[index]->iph->protocol;
    switch (protocol) {
    case IPPROTO_ICMP:
        handleICMP();
        break;
;   case IPPROTO_TCP:
        handleTCP();
        break;
    case IPPROTO_UDP:
        handleUDP();
        break;
    default:
        packets[index]->protocol = "others";
        break;
    }

    // ����������Ϣ
    packets[index]->src = QString(inet_ntoa(packets[index]->iph->saddr));
    packets[index]->dest = QString(inet_ntoa(packets[index]->iph->daddr));
}

void SnifferThread::handleIPv6() {
    // ��鴫���Э��
    u_char protocol = packets[index]->iph6->next_header;
    struct iphdr6* ip6 = packets[index]->iph6;
    switch (protocol) {
    case IPPROTO_TCP: {
        handleTCP();
        break;
    }
    case IPPROTO_UDP: {
        handleUDP();
        break;
    }
    case IPPROTO_ICMPV6: {
        handleICMP6();
        break;
    }
    default:
        packets[index]->protocol = "others";
        break;
    }
    // ����IPv6������Ϣ
    char str[INET6_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET6, &ip6->saddr, str, sizeof(str));
    packets[index]->src = str;
    inet_ntop(AF_INET6, &ip6->daddr, str, sizeof(str));
    packets[index]->dest = str;
}

void SnifferThread::handleARP() {
    packets[index]->protocol = "ARP";
    // ���� ARP ��Ϣ����ȡsrc dst info
    struct arphdr* arp = packets[index]->arph;
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
}

void SnifferThread::handleTCP() {
    // TCP �����߼�
    bool isIP6 = !packets[index]->iph;
    packets[index]->protocol = "TCP";
    struct tcphdr* tcp = nullptr;
    int ip_header_size = -1, ip6_header_size = 40;  // IP/IPv6 ͷ������
    if (!isIP6) {
        ip_header_size = packets[index]->iph->ihl * 4; 
        tcp = (struct tcphdr*)((u_char*)packets[index]->iph + ip_header_size);
    }
    else {
        tcp = (struct tcphdr*)((u_char*)packets[index]->iph6 + ip6_header_size);
    }
    packets[index]->tcph = tcp;
    // ��ȡԴ�˿ں�Ŀ��˿�
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    packets[index]->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // ���Ŀ��˿��� 80����Ϊ HTTP
    if (dst_port == 80 || src_port == 80) {
        // ���� TCP ͷ���Ĵ�С
        packets[index]->protocol = "HTTP";
        int tcp_header_size = tcp->doff * 4;
        u_char* http_data = nullptr;
        int http_data_length = -1;
        if (!isIP6) {
            http_data = (u_char*)packets[index]->iph + ip_header_size + tcp_header_size;
            http_data_length = packets[index]->length - (ETHERNET_SIZE + ip_header_size + tcp_header_size);
        }
        else {
            http_data = (u_char*)packets[index]->iph6 + ip6_header_size + tcp_header_size;
            http_data_length = packets[index]->length - (ETHERNET_SIZE + ip6_header_size + tcp_header_size);
        }
        // �� HTTP ���ݴ��� Packet �ṹ��
        if (http_data_length > 0) {
            packets[index]->info = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
        }
        else {
            packets[index]->info = "No HTTP Data";
        }
    }
}

void SnifferThread::handleICMP6() {
    packets[index]->protocol = "ICMPv6";
    // ƫ�Ƶ� IPv6 ͷ����ICMPv6 ��������ʼλ��
    int ip6_header_size = 40;
    struct icmphdr6* icmp6 = (struct icmphdr6*)((u_char*)packets[index]->iph6 + ip6_header_size);
    packets[index]->icmph6 = icmp6;
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
}

void SnifferThread::handleICMP() {
    // ICMP �����߼�
    packets[index]->protocol = "ICMP";
    int ip_header_size = packets[index]->iph->ihl * 4;  // IP ͷ������
    struct icmphdr* icmp = (struct icmphdr*)((u_char*)packets[index]->iph + ip_header_size);
    packets[index]->icmph = icmp;
    if (icmp->type == 8) { // ICMP ����
        packets[index]->info = "ICMP Echo (ping) request";
    }
    else if (icmp->type == 0) { // ICMP ��Ӧ
        packets[index]->info = "ICMP Echo (ping) reply";
    }
}

void SnifferThread::handleUDP() {
    // UDP �����߼�
    packets[index]->protocol = "UDP";
    bool isIP6 = !packets[index]->iph;
    struct udphdr* udp = nullptr;
    int ip_header_size = -1, ip6_header_size = 40;
    if (!isIP6) {
        ip_header_size = packets[index]->iph->ihl * 4;  // IP ͷ������
        udp = (struct udphdr*)((u_char*)packets[index]->iph + ip_header_size);
    }
    else {
        udp = (struct udphdr*)((u_char*)packets[index]->iph6 + ip6_header_size);
    }
    packets[index]->udph = udp;
    packets[index]->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS �����߼�
        packets[index]->protocol = "DNS";
        int dns_length = -1, udp_length = sizeof(struct udphdr);
        u_char* dns_data = nullptr;
         // ��ȡ DNS ���ݰ�����Ϣ
        if (!isIP6) {
            dns_data = (u_char*)packets[index]->iph + ip_header_size + udp_length;
            dns_length = packets[index]->length - (ETHERNET_SIZE + ip_header_size + udp_length);
        }
        else {
            dns_data = (u_char*)packets[index]->iph6 + ip6_header_size + udp_length;
            dns_length = packets[index]->length - (ETHERNET_SIZE + ip6_header_size + udp_length);
        }
        // ���� DNS ���ݰ�
        if (dns_length > 0) {
            // ��������� DNS ���ݰ����ݲ��޸� packets[index]->info
            packets[index]->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            packets[index]->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
}
