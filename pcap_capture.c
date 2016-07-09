#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;

    dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    
    pcd = pcap_open_live(dev, BUFSIZ,  1/*PROMISCUOUS*/, -1, errbuf);

    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(pcd, 0, callback, NULL);
}


// 패킷 헤더에 대한 정보: http://www.netmanias.com/ko/post/blog/5372/ethernet-ip-tcp-ip/packet-header-ethernet-ip-tcp-ip
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int i, Etype, ProtocolID, IPlen;
    u_char *srcMAC, *dstMAC;
    u_char *srcIP, *dstIP;
    int srcPort, dstPort;

    printf("CAPTURE PACKET!\n");

    /* ethernet header */
    srcMAC = packet+6;
    printf("Source MAC       : ");
    printf("%02x", srcMAC[0]);
    for(i=1;i<6;i++)
        printf(":%02x", srcMAC[i]);
    printf("\n");

    dstMAC = packet;
    printf("Destination MAC  : ");
    printf("%02x", dstMAC[0]);
    for(i=1;i<6;i++)
        printf(":%02x", dstMAC[i]);
    printf("\n");
    
    // Check if it's IP packet
    Etype = ntohs(*(u_short*)(packet+12));
    if(Etype!=0x0800) // 0x0800 : IP code
    {
        printf("Non-IP packet\n\n");
        return;
    }
    
    /* IP header */
    packet += 14; // now packer points to IP header(Ethernet header : 14 byte)
    
    srcIP = packet+12;
    printf("Source IP        : ");
    printf("%d", srcIP[0]);
    for(i=1;i<4;i++)
        printf(".%d", srcIP[i]);
    printf("\n");

    dstIP = packet+16;
    printf("Destination IP   : ");
    printf("%d", dstIP[0]);
    for(i=1;i<4;i++)
        printf(".%d", dstIP[i]);
    printf("\n");
    
    // Check if it's TCP packet
    ProtocolID = *(u_char*)(packet+9);
    if(ProtocolID!=6) // 6 : TCP code
    {
        printf("Non-TCP packet (Protocol: %d)\n\n", ProtocolID);
        return;
    }

    /* TCP header */
    IPlen = (*(u_char*)(packet) & 0xf) * 4;
    packet += IPlen; // now packer points to TCP header

    srcPort = ntohs(*(u_short*)(packet));
    printf("Source Port      : %d\n", srcPort);

    dstPort = ntohs(*(u_short*)(packet+2));
    printf("Destination Port : %d\n", dstPort);

    printf("\n");
}    
