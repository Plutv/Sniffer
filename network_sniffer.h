#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H

#include <QMainWindow>
#include <QThread>
#include <QTableWidget>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>

QT_BEGIN_NAMESPACE
namespace Ui { class Network_SnifferClass; }
QT_END_NAMESPACE

class SnifferThread : public QThread {
    Q_OBJECT
public:
    explicit SnifferThread(QObject* parent = nullptr);
    void startSniffing(const QString& networkInterface);
    void stopSniffing();

signals:
    void packetCaptured(const QString& srcIP, const QString& destIP, const QString& protocol, int length);

protected:
    void run() override;

private:
    pcap_t* handle;
    bool sniffing;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
};

class Network_Sniffer : public QMainWindow {
    Q_OBJECT

public:
    explicit Network_Sniffer(QWidget* parent = nullptr);
    ~Network_Sniffer();

private slots:
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void displayPacket(const QString& srcIP, const QString& destIP, const QString& protocol, int length);

private:
    Ui::Network_SnifferClass* ui;
    SnifferThread* snifferThread;
};

#endif // NETWORK_SNIFFER_H
