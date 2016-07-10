#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>
//for structure
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

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
    struct ether_header *etherHdr;
    struct ip *ipHdr;
    struct tcphdr *tcpHdr;

    printf("CAPTURE PACKET!\n");

    /* ethernet header */
    etherHdr = (struct ether_header*)packet;
    printf("Source MAC       : %s\n", ether_ntoa(etherHdr->ether_shost));
    printf("Destination MAC  : %s\n", ether_ntoa(etherHdr->ether_dhost));
    
    // Check if it's IP packet
    if(ntohs(etherHdr->ether_type)!=ETHERTYPE_IP)
    {
        printf("Non-IP packet\n\n");
        return;
    }

    /* IP header */
    ipHdr = (struct ip*)(packet + 14/*Ether_LEN*/);
    printf("Source IP        : %s\n", inet_ntoa(ipHdr->ip_src));
    printf("Destination IP   : %s\n", inet_ntoa(ipHdr->ip_dst));

    // Check if it's TCP packet
    if(ipHdr->ip_p != IPPROTO_TCP)
    {
        printf("Non-TCP packet\n\n");
        return;
    }

    /* TCP header */
    tcpHdr = (struct tcphdr*)(packet + 14/*Ether_LEN*/ + 4*ipHdr->ip_hl/*IP_Header_LEN*/);
    printf("Source port      : %d\n", ntohs(tcpHdr->th_sport));
    printf("Destination port : %d\n", ntohs(tcpHdr->th_dport));


    printf("\n");
}    
