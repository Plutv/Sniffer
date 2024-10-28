#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H

#include <QMainWindow>
#include <QThread>
#include <QTableWidget>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

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
    void packetCaptured(int time, const QString& src, const QString& dest, const QString& protocol, int length, const QString& Info);

protected:
    void run() override;

private:
    pcap_t* handle;
    int _netInterfaceIndex;
    bool sniffing;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
};

class NetworkSniffer : public QMainWindow {
    Q_OBJECT

public:
    explicit NetworkSniffer(QWidget* parent = nullptr);
    QList<QString> getAvailableNetworkInterfaces();
    ~NetworkSniffer();

private slots:
    void onStartButtonClicked();
    void onNicSelectBoxActivated();
    void displayPacket(int time, const QString& src, const QString& dest, const QString& protocol, int length, const QString& Info);

private:
    Ui::NetworkSnifferClass* ui;
    SnifferThread* snifferThread;
};

#endif // NETWORK_SNIFFER_H
