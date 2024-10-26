#include "network_sniffer.h"
#include "ui_network_sniffer.h"
#include <QDebug>

Network_Sniffer::Network_Sniffer(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::Network_SnifferClass), snifferThread(new SnifferThread(this)) {
    ui->setupUi(this);
    connect(snifferThread, &SnifferThread::packetCaptured, this, &Network_Sniffer::displayPacket);
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(on_startButton_clicked()));
    ui->tableWidget->setColumnCount(4);
    QStringList headers = { "Source IP", "Destination IP", "Protocol", "Length" };
    ui->tableWidget->setHorizontalHeaderLabels(headers);
}

Network_Sniffer::~Network_Sniffer() {
    delete ui;
}

void Network_Sniffer::on_startButton_clicked() {
    QString text = ui->startButton->text();
    if (text == "Start") {
        ui->startButton->setText("Stop");
        snifferThread->startSniffing("eth0");  // ¿ªÊ¼ÐáÌ½
    }
    else {
        ui->startButton->setText("Start");
        snifferThread->stopSniffing();  // Í£Ö¹ÐáÌ½
    }
}

void Network_Sniffer::on_stopButton_clicked() {
    snifferThread->stopSniffing();
}

void Network_Sniffer::displayPacket(const QString& srcIP, const QString& destIP, const QString& protocol, int length) {
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(srcIP));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(destIP));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(protocol));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(QString::number(length)));
}
