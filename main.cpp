#include "network_sniffer.h"
#include <QtWidgets/QApplication>

// 2024E8015082045_zjy  2024/11/5

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetworkSniffer w;
    w.show();
    return a.exec();
}
