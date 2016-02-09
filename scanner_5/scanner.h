
#ifndef SCANNER_H
#define SCANNER_H
#include <QObject>
//class scanner
//{
//public:
//    scanner();
//};


class Scanner : public QObject {

    Q_OBJECT


private:
    pcap_t* handle;
    const u_char* data;
    struct pcap_pkthdr* pkthdr;
    struct ether_header* ether_h;
    struct iphdr* ip_h;
    struct tcphdr* tcp_h;
    struct udphdr* udp_h;

public slots:
    void p_start();


};
void run() {

while(!isFinished()){



    u_char* move;

    int res = pcap_next_ex(handle, &pkthdr, &data);
    if (res == 0) continue;

    move = (u_char *)data;
    ether_h = (struct ether_header *)move;

//            for(int i=0;i<6;i++){
//                QByteArray d_mac = new QByteArray(ether_h->ether_dhost));
//                //printf("%02x",d_mac[i]);
//            }

    if (ether_h->ether_type == ntohs(ETHERTYPE_IP)){

        move += sizeof(struct ether_header);
        ip_h = (struct iphdr *)move;

        struct in_addr s_addr = *((struct in_addr*)&(ip_h->saddr));
        struct in_addr d_addr = *((struct in_addr*)&(ip_h->daddr));

        if(ip_h->protocol == IPPROTO_TCP){

            tcp_h =(struct tcphdr *)((char*)ip_h + (ip_h->ihl*4));

        }

        else if(ip_h->protocol == IPPROTO_UDP){

            udp_h =(struct udphdr *)((char*)ip_h + (ip_h->ihl*4));

        }

        else if(ip_h->protocol == IPPROTO_ICMP){


        }

    else if (ether_h->ether_type == ntohs(ETHERTYPE_ARP)){


    }

    if(res < 0) break;

}

}

#endif // SCANNER_H
