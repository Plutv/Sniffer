#include "network_sniffer.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Network_Sniffer w;
    w.show();
    return a.exec();
}
