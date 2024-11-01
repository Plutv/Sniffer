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
    ~SnifferThread();
    void startSniffing(const int netInterfaceIndex);
    void clearPackets();
    void stopSniffing();
    QString formatMacAddress(const u_char* mac);
    Packet* getSelectedPacket(int index);
    QString formatTCPFlags(const tcphdr* tcpHeader);
    QString bpfFilter;
    bool bpfIsValid(QString exp);
    pcap_t* handle;
signals:
    void packetCaptured(const int seq,const QString time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

protected:
    void run() override;

private:
    void packet_handler(const struct pcap_pkthdr* header, const u_char* data);
    void appendPacket(Packet* _packet); // 添加捕获的报文
    void handleIP(Packet* _packet);
    void handleIPv6(Packet* _packet);
    void handleARP(Packet* _packet);
    void handleTCP(Packet* _packet);
    void handleUDP(Packet* _packet);
    void handleICMP(Packet* _packet);
    void handleICMP6(Packet* _packet);

    int _netInterfaceIndex;
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
    void displayPacketDetails();
    void displayPacketHex();

private slots:
    void onStartButtonClicked();
    void onApplyButtonClicked();
    void onClearButtonClicked();
    void onResetButtonClicked();
    void onSelectedNicChanged();
    void onTableSelectionChanged();
    void displayPacket(const int seq, const QString time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

private:
    Ui::NetworkSnifferClass* ui;
    SnifferThread* snifferThread;
};

#endif // NETWORK_SNIFFER_H
