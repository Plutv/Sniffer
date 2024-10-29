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

    // 获取可用设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Error finding devices: " << errbuf;
        return;
    }

    // 选择设备
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
    
    // 检查以太网类型
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

    // 解析其他信息
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
    // 检查传输层协议
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
    // 解析IPv6其他信息
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
    // 处理 ARP 信息
    QString arp_src_mac = formatMacAddress(arp->sha);
    QString src = QString("%1.%2.%3.%4").arg(arp->spa[0]).arg(arp->spa[1]).arg(arp->spa[2]).arg(arp->spa[3]);
    QString arp_dest_mac = formatMacAddress(arp->tha);
    QString dest = QString("%1.%2.%3.%4").arg(arp->tpa[0]).arg(arp->tpa[1]).arg(arp->tpa[2]).arg(arp->tpa[3]);
    packets[index]->src = src;
    packets[index]->dest = dest;
    if (ntohs(arp->oper) == 1) { // ARP 请求
        packets[index]->info = QString("Who has %1? Tell %2")
            .arg(arp_src_mac).arg(src);
    }
    else if (ntohs(arp->oper) == 2) { // ARP 响应
        packets[index]->info = QString("%1 is at %2")
            .arg(dest).arg(arp_dest_mac);
    }
    else {
        packets[index]->info = "Unknown ARP Operation";
    }
    // 解析ARP其他信息
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
    // TCP 处理逻辑
    packets[index]->protocol = "TCP";
    int ip_header_size = ip->ihl * 4;  // IP 头部长度
    struct tcphdr* tcp = (struct tcphdr*)(packet + ETHERNET_SIZE + ip_header_size);
    // 获取源端口和目标端口
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    packets[index]->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // 如果目标端口是 80，则为 HTTP
    cout << src_port << " " << dst_port << endl;
    if (dst_port == 80 || src_port == 80) {
        // 计算 TCP 头部的大小
        packets[index]->protocol = "HTTP";
        int tcp_header_size = tcp->doff * 4;

        // 获取 HTTP 数据的起始位置
        const unsigned char* http_data = packet + ETHERNET_SIZE + ip_header_size + tcp_header_size;
        int http_data_length = header->caplen - (ETHERNET_SIZE + ip_header_size + tcp_header_size);

        // 将 HTTP 数据存入 Packet 结构中
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
    // TCP 处理逻辑
    packets[index]->protocol = "TCP";
    int ip6_header_size = 40;  // IP 头部长度
    struct tcphdr* tcp = (struct tcphdr*)(packet + ETHERNET_SIZE + ip6_header_size);
    // 获取源端口和目标端口
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    packets[index]->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // 如果目标端口是 80，则为 HTTP
    cout << src_port << " " << dst_port << endl;
    if (dst_port == 80 || src_port == 80) {
        // 计算 TCP 头部的大小
        packets[index]->protocol = "HTTP";
        int tcp_header_size = tcp->doff * 4;

        // 获取 HTTP 数据的起始位置
        const unsigned char* http_data = packet + ETHERNET_SIZE + ip6_header_size + tcp_header_size;
        int http_data_length = header->caplen - (ETHERNET_SIZE + ip6_header_size + tcp_header_size);

        // 将 HTTP 数据存入 Packet 结构中
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
    // 偏移到 IPv6 头部后，ICMPv6 的数据起始位置
    int ip6_header_size = sizeof(struct iphdr6);
    struct icmphdr6* icmp6 = (struct icmphdr6*)(packet + ETHERNET_SIZE + ip6_header_size);

    // 解析 ICMPv6 的 type 和 code
    switch (icmp6->type) {
    case 135:  // 邻居请求
        packets[index]->info = "Neighbor Solicitation";
        break;
    case 136:   // 邻居通告
        packets[index]->info = "Neighbor Advertisement";
        break;
    case 128:   // 回显请求 (Ping)
        packets[index]->info = "ICMPv6 Echo Request";
        break;
    case 129:     // 回显应答 (Ping Response)
        packets[index]->info = "ICMPv6 Echo Reply";
        break;
    default:
        packets[index]->info = QString("ICMPv6 Type: %1, Code: %2")
            .arg(icmp6->type)
            .arg(icmp6->code);
        break;
    }

    // 时间戳计算
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
    // UDP 处理逻辑
    packets[index]->protocol = "UDP";
    struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr6));
    packets[index]->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS 处理逻辑
        packets[index]->protocol = "DNS";
        int ip6_header_size = 40;  // IP 头部长度
        // 提取 DNS 数据包的信息
        const u_char* dns_data = packet + ETHERNET_SIZE + ip6_header_size + sizeof(struct udphdr);
        int dns_length = header->caplen - (ETHERNET_SIZE + ip6_header_size + sizeof(struct udphdr));

        // 解析 DNS 数据包，具体实现可以根据需要来写
        if (dns_length > 0) {
            // 在这里解析 DNS 数据包内容并填充 packets[index]->info
            // 示例: 这里我们简单打印原始数据
            packets[index]->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            packets[index]->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
}

void SnifferThread::handleICMP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    // ICMP 处理逻辑
    packets[index]->protocol = "ICMP";
    struct icmphdr* icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (icmp->type == 8) { // ICMP 请求
        packets[index]->info = "ICMP Echo (ping) request";
    }
    else if (icmp->type == 0) { // ICMP 回应
        packets[index]->info = "ICMP Echo (ping) reply";
    }
}

void SnifferThread::handleUDP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header) {
    // UDP 处理逻辑
    packets[index]->protocol = "UDP";
    int ip_header_size = ip->ihl * 4;  // IP 头部长度
    struct udphdr* udp = (struct udphdr*)(packet + ETHERNET_SIZE + ip_header_size);
    packets[index]->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS 处理逻辑
        packets[index]->protocol = "DNS";
        int ip_header_size = ip->ihl * 4;  // IP 头部长度
        // 提取 DNS 数据包的信息
        const u_char* dns_data = packet + ETHERNET_SIZE + ip_header_size + sizeof(struct udphdr);
        int dns_length = header->caplen - (ETHERNET_SIZE + ip_header_size + sizeof(struct udphdr));

        // 解析 DNS 数据包，具体实现可以根据需要来写
        if (dns_length > 0) {
            // 在这里解析 DNS 数据包内容并填充 packets[index]->info
            // 示例: 这里我们简单打印原始数据
            packets[index]->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            packets[index]->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
}
