#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H
// ������̫��֡�Ĵ�С
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
    void stopSniffing();
    QString formatMacAddress(const u_char* mac);
    Packet* getSelectedPacket(int index);

signals:
    void packetCaptured(const int seq,const double time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

protected:
    void run() override;

private:
    void packet_handler(const struct pcap_pkthdr* header, const u_char* data);
    void appendPacket(); // ����²���ı���
    void senderSignal(); // ���Ͳ�׽���ĵ��ź�
    
    void handleIP();
    void handleIPv6();
    void handleARP();
    void handleTCP();
    void handleUDP();
    void handleICMP();
    void handleICMP6();

    pcap_t* handle;
    int _netInterfaceIndex;
    int index = 0;        // ��ǰ������
    struct timeval first_timestamp;
    bool sniffing;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    QList<Packet*> packets; // �洢��������ݰ���Ϣ
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
    void onTableSelectionChanged();
    void displayPacket(const int seq, const double time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info);

private:
    Ui::NetworkSnifferClass* ui;
    SnifferThread* snifferThread;
};

#endif // NETWORK_SNIFFER_H
