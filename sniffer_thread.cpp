#include "network_sniffer.h"
#include <iostream>
using namespace std;
SnifferThread::SnifferThread(QObject* parent) : QThread(parent), handle(nullptr), sniffing(false) {}
SnifferThread::~SnifferThread() {
    if(handle) pcap_close(handle);
    for (int i = 0; i < packets.size(); ++i) {
        delete packets[i]; // 释放每个 Packet 对象占用的内存
    }
    packets.clear(); // 清空列表，移除所有元素
}
void SnifferThread::startSniffing(const int netInterfaceIndex) {
    sniffing = true;
    _netInterfaceIndex = netInterfaceIndex;
    if (!isRunning()) start();
}

void SnifferThread::clearPackets() {
    for (int i = 0; i < packets.size(); ++i) {
        delete packets[i]; // 释放每个 Packet 对象占用的内存
    }
    packets.clear(); // 清空列表，移除所有元素
}

void SnifferThread::stopSniffing() {
    sniffing = false;
}

bool SnifferThread::bpfIsValid(QString exp) {
    struct bpf_program fp;  // 用于编译过滤器
    if (pcap_compile(handle, &fp, exp.toUtf8().constData(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        return false;
    }
    return true;
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

    // 设置 BPF 过滤器
    struct bpf_program fp;  // 用于编译过滤器
    if (pcap_compile(handle, &fp, bpfFilter.toUtf8().constData(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        qDebug() << "Error compiling filter:" << pcap_geterr(handle);
        pcap_freealldevs(alldevs);
        return;
    }

    // 应用过滤器
    if (pcap_setfilter(handle, &fp) == -1) {
        qDebug() << "Error setting filter:" << pcap_geterr(handle);
        pcap_freealldevs(alldevs);
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* data;
    int res;

    while (sniffing && (res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue;
        packet_handler( header, data);
    }
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

void SnifferThread::appendPacket(Packet* _packet) {
    packets.append(_packet);
    _packet->seq = packets.size();
    emit packetCaptured(
        _packet->seq,
        _packet->time,
        _packet->src,
        _packet->dest,
        _packet->protocol,
        _packet->length,
        _packet->info);
}

void SnifferThread::packet_handler(const struct pcap_pkthdr* header, const u_char* data) {
    // 存储数据包的副本
    const u_char* packet = new u_char[header->len];
    memcpy((void*)packet, data, header->len);
    Packet* _packet = new Packet;
    struct ethhdr* eth = (struct ethhdr*)packet;
    QString src_mac = formatMacAddress(eth->src);
    QString dest_mac = formatMacAddress(eth->dest);
    _packet->ethh = eth;
    _packet->length = header->caplen;
    // 获取捕获时间（秒和微秒）
    time_t rawtime = header->ts.tv_sec;
    struct tm* timeinfo = localtime(&rawtime); // 转换为本地时间

    // 获取时、分、秒
    int hours = timeinfo->tm_hour;
    int minutes = timeinfo->tm_min;
    int seconds = timeinfo->tm_sec;

    // 转换微秒为毫秒
    int milliseconds = header->ts.tv_usec / 1000;

    // 使用 QString 格式化时间字符串
    QString timestamp = QString("%1:%2:%3.%4")
        .arg(hours, 2, 10, QChar('0'))        // 时，补齐两位
        .arg(minutes, 2, 10, QChar('0'))      // 分，补齐两位
        .arg(seconds, 2, 10, QChar('0'))      // 秒，补齐两位
        .arg(milliseconds, 3, 10, QChar('0'));// 毫秒，补齐三位
    _packet->time = timestamp;
    // 检查以太网类型, IP ARP IPv6
    if (ntohs(eth->type) == 0x0800) { // IP
        struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_SIZE);
        _packet->iph = ip;
        handleIP(_packet);
    }
    else if (ntohs(eth->type) == 0x0806) { // ARP
        struct arphdr* arp = (struct arphdr*)(packet + ETHERNET_SIZE);
        _packet->arph = arp;
        handleARP(_packet);
    }
    else if (ntohs(eth->type) == 0x86DD) { // IPv6
        struct iphdr6* ip6 = (struct iphdr6*)(packet + ETHERNET_SIZE);
        _packet->iph6 = ip6;
        handleIPv6(_packet);
    }
}

void SnifferThread::handleIP(Packet* _packet) {
    u_char protocol = _packet->iph->protocol;
    // 解析其他信息
    _packet->src = QString(inet_ntoa(_packet->iph->saddr));
    _packet->dest = QString(inet_ntoa(_packet->iph->daddr));
    switch (protocol) {
    case IPPROTO_ICMP:
        handleICMP(_packet);
        break;
;   case IPPROTO_TCP:
        handleTCP(_packet);
        break;
    case IPPROTO_UDP:
        handleUDP(_packet);
        break;
    default:
        delete _packet;
        break;
    }
}

void SnifferThread::handleIPv6(Packet* _packet) {
    // 检查传输层协议
    u_char protocol = _packet->iph6->next_header;
    struct iphdr6* ip6 = _packet->iph6;
    // 解析IPv6其他信息
    char str[INET6_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET6, &ip6->saddr, str, sizeof(str));
    _packet->src = str;
    inet_ntop(AF_INET6, &ip6->daddr, str, sizeof(str));
    _packet->dest = str;
    switch (protocol) {
    case IPPROTO_TCP: {
        handleTCP(_packet);
        break;
    }
    case IPPROTO_UDP: {
        handleUDP(_packet);
        break;
    }
    case IPPROTO_ICMPV6: {
        handleICMP6(_packet);
        break;
    }
    default:
        delete _packet;
        break;
    }
}

void SnifferThread::handleARP(Packet* _packet) {
    _packet->protocol = "ARP";
    // 处理 ARP 信息，获取src dst info
    struct arphdr* arp = _packet->arph;
    QString arp_src_mac = formatMacAddress(arp->sha);
    QString src = QString("%1.%2.%3.%4").arg(arp->spa[0]).arg(arp->spa[1]).arg(arp->spa[2]).arg(arp->spa[3]);
    QString arp_dest_mac = formatMacAddress(arp->tha);
    QString dest = QString("%1.%2.%3.%4").arg(arp->tpa[0]).arg(arp->tpa[1]).arg(arp->tpa[2]).arg(arp->tpa[3]);
    _packet->src = src;
    _packet->dest = dest;
    if (ntohs(arp->oper) == 1) { // ARP 请求
        _packet->info = QString("Who has %1? Tell %2")
            .arg(arp_src_mac).arg(src);
    }
    else if (ntohs(arp->oper) == 2) { // ARP 响应
        _packet->info = QString("%1 is at %2")
            .arg(dest).arg(arp_dest_mac);
    }
    else {
        _packet->info = "Unknown ARP Operation";
    }
    appendPacket(_packet);
}

QString SnifferThread::formatTCPFlags(const tcphdr* tcpHeader) {
    QString flags;
    if (tcpHeader->fin) flags += "FIN ";
    if (tcpHeader->syn) flags += "SYN ";
    if (tcpHeader->rst) flags += "RST ";
    if (tcpHeader->psh) flags += "PSH ";
    if (tcpHeader->ack) flags += "ACK ";
    if (tcpHeader->urg) flags += "URG ";
    if (tcpHeader->ece) flags += "ECE ";
    if (tcpHeader->cwr) flags += "CWR ";
    return flags.trimmed();
}

void SnifferThread::handleTCP(Packet* _packet) {
    // TCP 处理逻辑
    bool isIP6 = !_packet->iph;
    _packet->protocol = "TCP";
    struct tcphdr* tcp = nullptr;
    int ip_header_size = -1, ip6_header_size = 40;  // IP/IPv6 头部长度
    if (!isIP6) {
        ip_header_size = _packet->iph->ihl * 4; 
        tcp = (struct tcphdr*)((u_char*)_packet->iph + ip_header_size);
    }
    else {
        tcp = (struct tcphdr*)((u_char*)_packet->iph6 + ip6_header_size);
    }
    _packet->tcph = tcp;
    // 获取源端口和目标端口
    u_short src_port = ntohs(tcp->src_port);
    u_short dst_port = ntohs(tcp->dst_port);
    _packet->info = QString("TCP %1 -> %2")
        .arg(src_port)
        .arg(dst_port);
    // 如果目标端口是 80，则可能为 HTTP
    if (dst_port == 80 || src_port == 80) {
        // 计算 TCP 头部的大小
        int tcp_header_size = tcp->doff * 4;
        u_char* http_data = nullptr;
        int http_data_length = -1;
        if (!isIP6) {
            http_data = (u_char*)_packet->iph + ip_header_size + tcp_header_size;
            http_data_length = _packet->length - (ETHERNET_SIZE + ip_header_size + tcp_header_size);
        }
        else {
            http_data = (u_char*)_packet->iph6 + ip6_header_size + tcp_header_size;
            http_data_length = _packet->length - (ETHERNET_SIZE + ip6_header_size + tcp_header_size);
        }
        if (http_data_length > 0) {
            QString dataContent = QString::fromUtf8(reinterpret_cast<const char*>(http_data), http_data_length);
            // 判断 HTTP 协议标识符
            if (dataContent.startsWith("GET") ||
                dataContent.startsWith("POST") ||
                dataContent.startsWith("HEAD") ||
                dataContent.startsWith("PUT") ||
                dataContent.startsWith("DELETE") ||
                dataContent.startsWith("OPTIONS") ||
                dataContent.startsWith("CONNECT") ||
                dataContent.startsWith("TRACE")) {
                qDebug() << ">>>> Yes, HTTP >>> dataContent.left(50)";
                _packet->info = dataContent.left(50); // 截取前50个字符作为信息
                _packet->protocol = "HTTP";
                // 将 HTTP 数据存入 Packet 结构中
                _packet->data_len = http_data_length;
                _packet->http_data = http_data;
                appendPacket(_packet);
                return;
            }
        }
        delete _packet;
        return;
    }
    appendPacket(_packet);
}

void SnifferThread::handleICMP6(Packet* _packet) {
    _packet->protocol = "ICMPv6";
    // 偏移到 IPv6 头部后，ICMPv6 的数据起始位置
    int ip6_header_size = 40;
    struct icmphdr6* icmp6 = (struct icmphdr6*)((u_char*)_packet->iph6 + ip6_header_size);
    _packet->icmph6 = icmp6;
    // 解析 ICMPv6 的 type 和 code
    switch (icmp6->type) {
    case 135:  // 邻居请求
        _packet->info = "Neighbor Solicitation";
        break;
    case 136:   // 邻居通告
        _packet->info = "Neighbor Advertisement";
        break;
    case 128:   // 回显请求 (Ping)
        _packet->info = "ICMPv6 Echo Request";
        break;
    case 129:     // 回显应答 (Ping Response)
        _packet->info = "ICMPv6 Echo Reply";
        break;
    default:
        _packet->info = QString("ICMPv6 Type: %1, Code: %2")
            .arg(icmp6->type)
            .arg(icmp6->code);
        break;
    }
    appendPacket(_packet);
}

void SnifferThread::handleICMP(Packet* _packet) {
    // ICMP 处理逻辑
    _packet->protocol = "ICMP";
    int ip_header_size = _packet->iph->ihl * 4;  // IP 头部长度
    struct icmphdr* icmp = (struct icmphdr*)((u_char*)_packet->iph + ip_header_size);
    _packet->icmph = icmp;
    if (icmp->type == 8) { // ICMP 请求
        _packet->info = "ICMP Echo (ping) request";
    }
    else if (icmp->type == 0) { // ICMP 回应
        _packet->info = "ICMP Echo (ping) reply";
    }
    appendPacket(_packet);
}

void SnifferThread::handleUDP(Packet* _packet) {
    // UDP 处理逻辑
    _packet->protocol = "UDP";
    bool isIP6 = !_packet->iph;
    struct udphdr* udp = nullptr;
    int ip_header_size = -1, ip6_header_size = 40;
    if (!isIP6) {
        ip_header_size = _packet->iph->ihl * 4;  // IP 头部长度
        udp = (struct udphdr*)((u_char*)_packet->iph + ip_header_size);
    }
    else {
        udp = (struct udphdr*)((u_char*)_packet->iph6 + ip6_header_size);
    }
    _packet->udph = udp;
    _packet->info = QString("UDP %1 -> %2")
        .arg(ntohs(udp->source))
        .arg(ntohs(udp->dest));
    if ((udp->source) == 53 || ntohs(udp->dest) == 53) {
        // DNS 处理逻辑
        _packet->protocol = "DNS";
        int dns_length = -1, udp_length = sizeof(struct udphdr);
        u_char* dns_data = nullptr;
         // 提取 DNS 数据包的信息
        if (!isIP6) {
            dns_data = (u_char*)_packet->iph + ip_header_size + udp_length;
            dns_length = _packet->length - (ETHERNET_SIZE + ip_header_size + udp_length);
        }
        else {
            dns_data = (u_char*)_packet->iph6 + ip6_header_size + udp_length;
            dns_length = _packet->length - (ETHERNET_SIZE + ip6_header_size + udp_length);
        }
        // 解析 DNS 数据包
        _packet->data_len = dns_length;
        _packet->dns_data = dns_data;
        if (dns_length > 0) {
            // 在这里解析 DNS 数据包内容并修改 _packet->info
            _packet->info = QString("DNS Data (Length: %1): ").arg(dns_length);
            _packet->info += QString::fromUtf8(reinterpret_cast<const char*>(dns_data), dns_length);
        }
    }
    appendPacket(_packet);
}
