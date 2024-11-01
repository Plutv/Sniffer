#include "network_sniffer.h"
#include "ui_network_sniffer.h"
#include <QDebug>
#include <QScrollBar>

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
    connect(ui->startButton, &QPushButton::clicked, this, &NetworkSniffer::onStartButtonClicked);
    connect(ui->clearButton, &QPushButton::clicked, this, &NetworkSniffer::onClearButtonClicked);
    connect(ui->applyButton, &QPushButton::clicked, this, &NetworkSniffer::onApplyButtonClicked);
    connect(ui->resetButton, &QPushButton::clicked, this, &NetworkSniffer::onResetButtonClicked);
    connect(ui->nicSelectBox, static_cast<void (QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, &NetworkSniffer::onSelectedNicChanged);
    connect(ui->tableWidget, &QTableWidget::itemSelectionChanged, this, &NetworkSniffer::onTableSelectionChanged);
    ui->tableWidget->setColumnCount(7);
    QStringList headers = { "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
    snifferThread->bpfFilter = "tcp or udp or icmp or arp";
    // ������ͷ���кţ�
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setHorizontalHeaderLabels(headers);
    ui->treeWidget->setHeaderLabel("Packet details: ");
}

NetworkSniffer::~NetworkSniffer() {
    delete ui;
}

void NetworkSniffer::onSelectedNicChanged() {
    int index = ui->nicSelectBox->currentIndex();
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
    int dev_num = index + 1;
    int i = 0;
    for (device = alldevs; i < dev_num - 1 && device; device = device->next, i++);

    if (device == NULL) {
        qDebug() << "Error, The selected device does not exists!" << endl;
        return;
    }

    snifferThread->handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
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
        ui->applyButton->setEnabled(false);
        ui->resetButton->setEnabled(false);
        snifferThread->startSniffing(ui->nicSelectBox->currentIndex());  // ��ʼ��̽
    }
    else {
        ui->startButton->setText("Start");
        ui->applyButton->setEnabled(true);
        ui->resetButton->setEnabled(true);
        snifferThread->stopSniffing();  // ֹͣ��̽
    }
}

void NetworkSniffer::onClearButtonClicked() {
    snifferThread->clearPackets();
    if (ui->tableWidget) {
        ui->tableWidget->clearSelection();
        ui->tableWidget->setRowCount(0);
    }
    else {
        qDebug() << "tableWidget is not initialized!";
    }

    if (ui->treeWidget) {
        ui->treeWidget->clear();
    }
    else {
        qDebug() << "treeWidget is not initialized!";
    }

    if (ui->textEdit) {
        ui->textEdit->clear();
    }
    else {
        qDebug() << "textEdit is not initialized!";
    }
}

void NetworkSniffer::onResetButtonClicked() {
    snifferThread->bpfFilter = "";
    ui->filterEdit->setText("");
}

void NetworkSniffer::onApplyButtonClicked() {
    QString filter = ui->filterEdit->text();
    if (filter.compare(QString::fromLocal8Bit("http")) == 0) {
        filter = "tcp and port 80";
    }
    if (!snifferThread->handle) {
        ui->startButton->setEnabled(false);
        return;
    }
    if (snifferThread->bpfIsValid(filter)) { // ���ʽ��Ч
        ui->filterEdit->setStyleSheet("QLineEdit { background-color: rgba(0, 255, 0, 100); }"); 
        ui->startButton->setEnabled(true);
    }
    else { // ���ʽ��Ч
        ui->filterEdit->setStyleSheet("QLineEdit { background-color: rgba(255, 0, 0, 100); }"); 
        ui->startButton->setEnabled(false);
    }
    snifferThread->bpfFilter = filter;
}

void NetworkSniffer::displayPacket(const int seq, const QString time, const QString& src, const QString& dest, const QString& protocol, const int length, const QString& Info) {
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    ui->tableWidget->setItem(row, 0, new QTableWidgetItem(QString::number(seq)));
    ui->tableWidget->setItem(row, 1, new QTableWidgetItem(time));
    ui->tableWidget->setItem(row, 2, new QTableWidgetItem(src));
    ui->tableWidget->setItem(row, 3, new QTableWidgetItem(dest));
    ui->tableWidget->setItem(row, 4, new QTableWidgetItem(protocol));
    ui->tableWidget->setItem(row, 5, new QTableWidgetItem(QString::number(length)));
    ui->tableWidget->setItem(row, 6, new QTableWidgetItem(Info));
    // �̶���6�еĿ��
    ui->tableWidget->setColumnWidth(6, 250); // ����Ϊ150���ؿ�

    // ���������Ƿ��ڵײ�
    QScrollBar* scrollBar = ui->tableWidget->verticalScrollBar();
    bool autoScrollEnabled = (scrollBar->value() == scrollBar->maximum());

    // ����ڵײ�������������һ��
    if (autoScrollEnabled) {
        ui->tableWidget->scrollToBottom();
    }
}
QString parseDnsQuery(const u_char* dns_data, int offset);
void NetworkSniffer::displayPacketDetails() {
    QTreeWidget* detailsTree = ui->treeWidget;
    detailsTree->clear();
    int index = ui->tableWidget->currentIndex().row();
    Packet* packet = snifferThread->getSelectedPacket(index);

    if (!packet) {
        detailsTree->clear();
        qDebug() << "Packet not exists! Might be deleted!";
        return;
    }

    detailsTree->setColumnCount(1);  // ��������һ������ʾ����
    // ��·����Ϣ
    QTreeWidgetItem* linkLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Link Layer");
    linkLayer->addChild(new QTreeWidgetItem(linkLayer, QStringList() << "Source MAC: " + snifferThread->formatMacAddress(packet->ethh->src)));
    linkLayer->addChild(new QTreeWidgetItem(linkLayer, QStringList() << "Destination MAC: " + snifferThread->formatMacAddress(packet->ethh->dest)));

    // �������Ϣ
    if (packet->iph) {
        QTreeWidgetItem* networkLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Network Layer (IPv4)");
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Source IP: " + QString(inet_ntoa(packet->iph->saddr))));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Destination IP: " + QString(inet_ntoa(packet->iph->daddr))));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Version: " + QString::number(packet->iph->version)));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Header Length: " + QString::number(packet->iph->ihl * 4) + " bytes"));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Type of Service: " + QString::number(packet->iph->tos)));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Total Length: " + QString::number(ntohs(packet->iph->tot_len)) + " bytes"));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Identification: 0x" + QString::number(ntohs(packet->iph->id), 16).toUpper()));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Flags and Fragment Offset: 0x" + QString::number(ntohs(packet->iph->frag_off), 16).toUpper()));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Time to Live (TTL): " + QString::number(packet->iph->ttl)));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Protocol: " + QString::number(packet->iph->protocol)));
        networkLayer->addChild(new QTreeWidgetItem(networkLayer, QStringList() << "Header Checksum: 0x" + QString::number(ntohs(packet->iph->check), 16).toUpper()));
    }
    else if (packet->iph6) {
        char str[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET6, &packet->iph6->saddr, str, sizeof(str));
        QTreeWidgetItem* networkLayer6 = new QTreeWidgetItem(detailsTree, QStringList() << "Network Layer (IPv6)");
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Source IP: " + QString(str)));
        inet_ntop(AF_INET6, &packet->iph6->daddr, str, sizeof(str));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Destination IP: " + QString(str)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Next Header: " + QString::number(packet->iph6->next_header)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Hop Limit: " + QString::number(packet->iph6->hop_limit)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Version: " + QString::number(packet->iph6->version)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Traffic Class: " + QString::number(packet->iph6->traffic_class)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Flow Label: " + QString::number(packet->iph6->flow_label)));
        networkLayer6->addChild(new QTreeWidgetItem(networkLayer6, QStringList() << "Payload Length: " + QString::number(ntohs(packet->iph6->payload_len)) + " bytes"));
    }
    else if (packet->arph) {
        struct arphdr* arp = packet->arph;
        QTreeWidgetItem* arpLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Network Layer (ARP)");
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Hardware Type: " + QString::number(ntohs(packet->arph->htype))));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Protocol Type: " + QString::number(ntohs(packet->arph->ptype))));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Hardware Address Length: " + QString::number(packet->arph->hlen)));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Protocol Address Length: " + QString::number(packet->arph->plen)));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Operation: " + QString::number(ntohs(packet->arph->oper))));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Sender MAC: " + snifferThread->formatMacAddress(packet->arph->sha)));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Sender IP: " + QString("%1.%2.%3.%4").arg(arp->spa[0]).arg(arp->spa[1]).arg(arp->spa[2]).arg(arp->spa[3])));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Target MAC: " + snifferThread->formatMacAddress(packet->arph->tha)));
        arpLayer->addChild(new QTreeWidgetItem(arpLayer, QStringList() << "Target IP: " + QString("%1.%2.%3.%4").arg(arp->tpa[0]).arg(arp->tpa[1]).arg(arp->tpa[2]).arg(arp->tpa[3])));
    }

    // �������Ϣ
    if (packet->tcph) {
        QTreeWidgetItem* transportLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Transport Layer (TCP)");
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Source Port: " + QString::number(ntohs(packet->tcph->src_port))));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Destination Port: " + QString::number(ntohs(packet->tcph->dst_port))));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Sequence Number: " + QString::number(ntohl(packet->tcph->seq))));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Acknowledgment Number: " + QString::number(ntohl(packet->tcph->ack_seq))));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Header Length: " + QString::number(packet->tcph->doff * 4) + " bytes"));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Flags: " + snifferThread->formatTCPFlags(packet->tcph)));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Window Size: " + QString::number(ntohs(packet->tcph->window))));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Checksum: 0x" + QString::number(ntohs(packet->tcph->check), 16).toUpper()));
        transportLayer->addChild(new QTreeWidgetItem(transportLayer, QStringList() << "Urgent Pointer: " + QString::number(ntohs(packet->tcph->urg_ptr))));
    }
    else if (packet->udph) {
        QTreeWidgetItem* transportLayerUDP = new QTreeWidgetItem(detailsTree, QStringList() << "Transport Layer (UDP)");
        transportLayerUDP->addChild(new QTreeWidgetItem(transportLayerUDP, QStringList() << "Source Port: " + QString::number(ntohs(packet->udph->source))));
        transportLayerUDP->addChild(new QTreeWidgetItem(transportLayerUDP, QStringList() << "Destination Port: " + QString::number(ntohs(packet->udph->dest))));
        transportLayerUDP->addChild(new QTreeWidgetItem(transportLayerUDP, QStringList() << "Length: " + QString::number(ntohs(packet->udph->length))));
        transportLayerUDP->addChild(new QTreeWidgetItem(transportLayerUDP, QStringList() << "Checksum: 0x" + QString::number(ntohs(packet->udph->checksum), 16).toUpper()));
    }
    else if (packet->icmph) {
        QTreeWidgetItem* icmpLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Transport Layer (ICMP)");
        icmpLayer->addChild(new QTreeWidgetItem(icmpLayer, QStringList() << "Type: " + QString::number(packet->icmph->type)));
        icmpLayer->addChild(new QTreeWidgetItem(icmpLayer, QStringList() << "Code: " + QString::number(packet->icmph->code)));
        icmpLayer->addChild(new QTreeWidgetItem(icmpLayer, QStringList() << "Checksum: " + QString::number(ntohs(packet->icmph->checksum))));
        if (packet->icmph->type == 0 || packet->icmph->type == 8) {
            icmpLayer->addChild(new QTreeWidgetItem(icmpLayer, QStringList() << "Identifier: " + QString::number(ntohs(packet->icmph->un.echo.id))));
            icmpLayer->addChild(new QTreeWidgetItem(icmpLayer, QStringList() << "Sequence Number: " + QString::number(ntohs(packet->icmph->un.echo.seq))));
        }
    }
    else if (packet->icmph6) {
        QTreeWidgetItem* icmpLayer6 = new QTreeWidgetItem(detailsTree, QStringList() << "Transport Layer (ICMPv6)");
        icmpLayer6->addChild(new QTreeWidgetItem(icmpLayer6, QStringList() << "Type: " + QString::number(packet->icmph6->type)));
        icmpLayer6->addChild(new QTreeWidgetItem(icmpLayer6, QStringList() << "Code: " + QString::number(packet->icmph6->code)));
        icmpLayer6->addChild(new QTreeWidgetItem(icmpLayer6, QStringList() << "Checksum: 0x" + QString::number(ntohs(packet->icmph6->checksum), 16).toUpper()));
    }
    // Ӧ�ò�����
    if (packet->http_data) {
        QTreeWidgetItem* applicationLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Application Layer (HTTP)");
        QString httpContent = QString::fromUtf8(reinterpret_cast<const char*>(packet->http_data), packet->data_len);
        // �ָ� HTTP �����к�ͷ��
        QStringList lines = httpContent.split("\r\n", Qt::SkipEmptyParts);
        if (lines.size() > 0) {
            // �����У�����: "GET /connecttest.txt HTTP/1.1"
            QString requestLine = lines[0];
            QTreeWidgetItem* requestLineItem = new QTreeWidgetItem(applicationLayer, QStringList() << "Request Line: " + requestLine);

            // ��ȡ������URL��HTTP�汾
            QStringList requestParts = requestLine.split(" ");
            if (requestParts.size() == 3) {
                requestLineItem->addChild(new QTreeWidgetItem(requestLineItem, QStringList() << "Method: " + requestParts[0]));
                requestLineItem->addChild(new QTreeWidgetItem(requestLineItem, QStringList() << "URL: " + requestParts[1]));
                requestLineItem->addChild(new QTreeWidgetItem(requestLineItem, QStringList() << "HTTP Version: " + requestParts[2]));
            }

            // ͷ���ֶΣ�����: "Connection: Close"
            for (int i = 1; i < lines.size(); ++i) {
                QStringList headerParts = lines[i].split(": ");
                if (headerParts.size() == 2) {
                    QTreeWidgetItem* headerItem = new QTreeWidgetItem(applicationLayer, QStringList() << headerParts[0] + ": " + headerParts[1]);
                }
            }
        }
    }
    else if (packet->dns_data) {
        QTreeWidgetItem* applicationLayer = new QTreeWidgetItem(detailsTree, QStringList() << "Application Layer (DNS)");
        QString dnsContent = QString::fromUtf8(reinterpret_cast<const char*>(packet->dns_data), packet->data_len);
        struct dnshdr* dns_header = reinterpret_cast<struct dnshdr*>(packet->dns_data);
        int dns_header_length = sizeof(struct dnshdr); // ������ DNS ͷ���Ľṹ��
        // Transaction ID
        QString transactionId = QString("0x%1").arg(ntohs(dns_header->id), 4, 16, QLatin1Char('0')); // ת��Ϊʮ������
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Transaction ID: " + transactionId));

        // Flags
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Flags: 0x" + dns_header->flagsToHexString()));

        // Questions, Answer RRs, Authority RRs, Additional RRs
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Questions: " + QString::number(ntohs(dns_header->qdcount))));
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Answer RRs: " + QString::number(ntohs(dns_header->ancount))));
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Authority RRs: " + QString::number(ntohs(dns_header->nscount))));
        applicationLayer->addChild(new QTreeWidgetItem(applicationLayer, QStringList() << "Additional RRs: " + QString::number(ntohs(dns_header->arcount))));

        // Queries
        QTreeWidgetItem* queriesItem = new QTreeWidgetItem(applicationLayer, QStringList() << "Queries");
        int offset = dns_header_length; // �� DNS ͷ����ʼ��ƫ����

        // ������ѯ
        //for (int i = 0; i < ntohs(dns_header->qdcount); i++) {
        //    QString query = parseDnsQuery((u_char*)packet->dns_data + offset, packet->data_len - offset);
        //    queriesItem->addChild(new QTreeWidgetItem(queriesItem, QStringList() << query));
        //    offset += query.size() + 5; // query ĩβ�� 2 �ֽ����ͺ� 2 �ֽ���
        //}
    }


    detailsTree->expandAll();
}

// ��������DNS��ѯ����
QString parseDnsQuery(const u_char* dns_data, int offset) {
    const u_char* p = dns_data + offset;
    QStringList labels;  // ʹ�� QStringList ���洢��������

    // ��������
    while (*p != 0) {
        u_char len = *p; // ��ȡ�������ֵĳ���
        p++;
        labels.append(QString::fromUtf8(reinterpret_cast<const char*>(p), len)); // ������������ӵ��б�
        p += len; // �ƶ�����һ������
    }
    QString domainName = labels.join("."); // ��ϳ���������
    p++; // �������ֽ�

    // ������ѯ���ͺͲ�ѯ��
    u_short qtype = ntohs(*reinterpret_cast<const u_short*>(p)); // ��ȡ��ѯ����
    p += 2; // ������ѯ����
    u_short qclass = ntohs(*reinterpret_cast<const u_short*>(p)); // ��ȡ��ѯ��

    // ��ʽ�����ص��ַ���
    QString queryInfo = QString("Domain: %1, Type: %2, Class: %3")
        .arg(domainName)
        .arg(qtype)
        .arg(qclass);
    return queryInfo;
}

void NetworkSniffer::displayPacketHex() {
    QTextEdit* hexView = ui->textEdit;
    int index = ui->tableWidget->currentIndex().row();
    Packet* packet = snifferThread->getSelectedPacket(index);
    if (!packet) {
        hexView->clear();
        qDebug() << "Packet not exists! Might be deleted!";
        return;
    }
    hexView->clear();
    QString hexContent;
    u_char* data = (u_char*)packet->ethh;
    for (int i = 0; i < packet->length; ++i) {
        hexContent += QString("%1 ").arg(data[i], 2, 16, QLatin1Char('0')).toUpper();
        if ((i + 1) % 16 == 0) hexContent += "\n";
    }

    hexView->setPlainText(hexContent);
}

void NetworkSniffer::onTableSelectionChanged() {
    displayPacketDetails();
    displayPacketHex();
}
