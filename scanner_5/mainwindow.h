#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidgetItem>
#include <pcap.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
//     pcap_open_live();
//     pcap_close();

private:
    pcap_t* handle;
    const u_char* data;
    struct pcap_pkthdr* pkthdr;
    struct ether_header* ether_h;
    struct iphdr* ip_h;
    struct tcphdr* tcp_h;
    struct udphdr* udp_h;



private slots:
    void add_p();
    void p_exit();

private:
    Ui::MainWindow *ui;

};



#endif // MAINWINDOW_H
