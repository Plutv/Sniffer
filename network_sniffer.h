#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H
// 定义以太网帧的大小
#define ETHERNET_SIZE 14

#include <QMainWindow>
#include <QThread>
#include <QTableWidget>
#include <pcap.h>
#include <winsock2.h>
#include <qdebug.h>
#include "protocol.h"

QT_BEGIN_NAMESPACE
namespace Ui { class NetworkSnifferClass; }
QT_END_NAMESPACE

class SnifferThread : public QThread {
    Q_OBJECT
public:
    explicit SnifferThread(QObject* parent = nullptr);
    void startSniffing(const int netInterfaceIndex);
    void stopSniffing();

signals:
    void packetCaptured(const int seq,const double time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

protected:
    void run() override;

private:
    void packet_handler(const struct pcap_pkthdr* header, const u_char* packet);
    QString formatMacAddress(const u_char* mac);
    void handleIP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header);
    void handleIPv6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header);
    void handleARP(const struct arphdr* arp, const struct pcap_pkthdr* header);
    void handleTCP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header);
    void handleICMP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header);
    void handleUDP(const struct iphdr* ip, const u_char* packet, const struct pcap_pkthdr* header);
    void handleTCP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header);
    void handleICMP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header);
    void handleUDP6(const struct iphdr6* ip6, const u_char* packet, const struct pcap_pkthdr* header);

    pcap_t* handle;
    int _netInterfaceIndex;
    int index = 0;        // 当前包索引
    struct timeval first_timestamp;
    bool sniffing;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    QList<Packet*> packets; // 存储捕获的数据包信息
};

class NetworkSniffer : public QMainWindow {
    Q_OBJECT

public:
    explicit NetworkSniffer(QWidget* parent = nullptr);
    QList<QString> getAvailableNetworkInterfaces();
    ~NetworkSniffer();

private slots:
    void onStartButtonClicked();
    void displayPacket(const int seq, const double time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

private:
    Ui::NetworkSnifferClass* ui;
    SnifferThread* snifferThread;
};

#endif // NETWORK_SNIFFER_H
