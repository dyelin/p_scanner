#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QtGui>
#include <QMessageBox>
#include <QTreeWidget>
#include <QCoreApplication>
#include <pcap.h>
#include <QThread>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->pb_start, SIGNAL(clicked()),this, SLOT(add_p()));
    connect(ui->pb_stop, SIGNAL(clicked()),this,SLOT(p_exit()));
}

MainWindow::~MainWindow()
{
    delete ui;
}


#define BUFSIZE 65536

void MainWindow::add_p(){


    char errbuf[PCAP_ERRBUF_SIZE];
    char dev[] = "eth0";
    handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);

        if(handle == NULL){
           //fprintf(stderr, "Couldn't open decide %s: %s \n", dev,errbuf);
            QMessageBox::warning(NULL, "Error", "Couldn't open decide %s: %s \n", dev,errbuf);
           // return(2);
        }

    int a=1;
    QTreeWidgetItem* list = new QTreeWidgetItem(ui->treeWidget);
    list->setText(0, QString("%1").arg(a));

    if(ether_h->ether_type == ntohs(ETHERTYPE_IP)){

        list->setText(2, QString("%1").arg("IPv4"));


        struct in_addr s_addr = *((struct in_addr*)&(ip_h->saddr));
        struct in_addr d_addr = *((struct in_addr*)&(ip_h->daddr));

        QTreeWidgetItem* IP_P = new QTreeWidgetItem(list);
        IP_P->setText(3, QString("%1").arg(inet_ntoa(s_addr)));
        IP_P->setText(4, QString("%1").arg(inet_ntoa(d_addr)));

        if(ip_h->protocol == IPPROTO_TCP){

            IP_P->setText(5, QString("%1").arg("TCP"));

        }
        else if(ip_h->protocol == IPPROTO_UDP){

            IP_P->setText(5, QString("%1").arg("UDP"));

        }
    }
    else if(ether_h->ether_type==ntohs(ETHERTYPE_ARP)){

        list->setText(2, QString("%1").arg("ARP"));
    }
}



void MainWindow::p_exit(){


//    scanner.terminate();
//    scanner.wait();
    pcap_close(handle);
}

