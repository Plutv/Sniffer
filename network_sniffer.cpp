#include "network_sniffer.h"
#include "ui_network_sniffer.h"
#include <QDebug>

NetworkSniffer::NetworkSniffer(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::NetworkSnifferClass), snifferThread(new SnifferThread(this)) {
    ui->setupUi(this);
    // ��ȡ������������Ϣ
    QList<QString> networkInterfaces = getAvailableNetworkInterfaces();
    for (const QString& netInterface : networkInterfaces) {
        ui->nicSelectBox->addItem(netInterface);
    }
    ui->nicSelectBox->setCurrentIndex(-1);
    connect(snifferThread, &SnifferThread::packetCaptured, this, &NetworkSniffer::displayPacket);
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(onStartButtonClicked()));
    connect(ui->nicSelectBox, QOverload<int>::of(&QComboBox::activated), this, &NetworkSniffer::onNicSelectBoxActivated);
    ui->tableWidget->setColumnCount(6);
    QStringList headers = { "Time", "Source", "Destination", "Protocol", "Length", "Info"};
    ui->tableWidget->setHorizontalHeaderLabels(headers);
}

NetworkSniffer::~NetworkSniffer() {
    delete ui;
}

QList<QString> NetworkSniffer::getAvailableNetworkInterfaces() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    QList<QString> interfaces;

    // ��ȡ�����豸�б�
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Error finding devices: " << errbuf;
        return interfaces;  // ���ؿ��б�
    }

    // ���豸������ӵ��б���
    for (device = alldevs; device; device = device->next) {
        QString description = device->description ? device->description : "No description";
        interfaces.append(description);
    }

    // �ͷ��豸�б�
    pcap_freealldevs(alldevs);

    return interfaces;
}

void NetworkSniffer::onStartButtonClicked() {
    QString text = ui->startButton->text();
    if (text == "Start") {
        ui->startButton->setText("Stop");
        snifferThread->startSniffing(ui->nicSelectBox->currentIndex());  // ��ʼ��̽
    }
    else {
        ui->startButton->setText("Start");
        snifferThread->stopSniffing();  // ֹͣ��̽
    }
}

void NetworkSniffer::onNicSelectBoxActivated() {
    // ѡ������

}

void NetworkSniffer::displayPacket(int time, const QString& src, const QString& dest, const QString& protocol, int length, const QString& Info) {
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(time)));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(src));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(dest));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(protocol));
    ui->tableWidget->setItem(row, 4, new QTableWidgetItem(QString::number(length)));
    ui->tableWidget->setItem(row, 5, new QTableWidgetItem(Info));
}
