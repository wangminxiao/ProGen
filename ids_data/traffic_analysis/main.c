// https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
// http://tonylukasavage.com/blog/2010/12/19/offline-packet-capture-analysis-with-c-c----amp--libpcap/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>
#include <string.h>
#include <tgmath.h>
#include <x86intrin.h>

/*
pcap and network related
*/
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "packet.h"

#define ETHER_HDR_TRUNCATE 0

int tcp = 0, udp = 0, icmp = 0, others = 0, total = 0;
//function to convert ascii char[] to hex-string (char[])

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ether_header *ep;
    unsigned short ether_type;

    // read Ethernet header if not truncated
    if (!ETHER_HDR_TRUNCATE)
    {
        ep = (struct ether_header *)packet;

        // protocol type
        ether_type = ntohs(ep->ether_type);
        // IPv4
        if (ether_type == ETHERTYPE_IP)
        {
            packet += ETHER_HDR_LEN;
        }

        // UNSW IPv4
        if (ether_type == 0)
        {
            packet += 16;
        }

        // 802.1Q
        else if (ether_type == ETHERTYPE_VLAN)
        {
            ether_type = ntohs(*(uint16_t *)(packet + 16));

            // only process IP packet
            if (ether_type == ETHERTYPE_IP)
            {
                packet += ETHER_HDR_LEN;
                packet += 4;
            }

            else
                return;
        }
    }

    Packet p;

    /* Timestamp */
    unsigned long time_in_micros = pkthdr->ts.tv_sec * 1000000 + pkthdr->ts.tv_usec;
    p.timestamp = time_in_micros;
    // printf("timestamp: %lu\n", time_in_micros);

    /* IP header */
    // Note: caida traces does not include ethernet headers
    // data_center (IMC 2010): enternet headers, YES
    // MACCDC_2012
    const struct ip *ipHeader;
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    ipHeader = (struct ip *)(packet);

    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

    struct in_addr tmpPkt1, tmpPkt2;
    inet_aton(sourceIp, &tmpPkt1);
    inet_aton(destIp, &tmpPkt2);

    p.srcip = ntohl(tmpPkt1.s_addr);
    p.dstip = ntohl(tmpPkt2.s_addr);

    p.ip_hl = (unsigned int)ipHeader->ip_hl;
    p.ip_v = (unsigned int)ipHeader->ip_v;
    p.ip_tos = (uint8_t)ipHeader->ip_tos;
    p.ip_len = ntohs(ipHeader->ip_len);
    p.ip_id = ntohs(ipHeader->ip_id);
    p.ip_off = ntohs(ipHeader->ip_off);
    p.ip_ttl = (uint8_t)ipHeader->ip_ttl;
    p.ip_p = (uint8_t)ipHeader->ip_p;
    p.ip_sum = ntohs(ipHeader->ip_sum);

    // TCP/UDP
    total++;
    switch (ipHeader->ip_p)
    {
    // ICMP Protocol
    case 1:
        icmp++;
        break;

    // TCP Protocol
    case 6:
        tcp++;

        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + p.ip_hl * 4);
        const u_char *tcp_payload;

        p.srcport = ntohs(tcpHeader->th_sport);
        p.dstport = ntohs(tcpHeader->th_dport);
        p.p_hl = tcpHeader->th_off;
        p.tcp_flags = tcpHeader->th_flags;
        p.tcp_win = ntohs(tcpHeader->th_win);

        // Calculate payload start
        tcp_payload = packet + p.ip_hl * 4 + p.p_hl * 4;
        // Get payload length
        int tcp_payload_length = pkthdr->len - (ETHER_HDR_LEN + p.ip_hl * 4 + p.p_hl * 4);
        p.p_len = tcp_payload_length;
        if (tcp_payload_length >= 8000){
            tcp_payload_length = 8000;
        }
        for (int i = 0; i < tcp_payload_length; i++) {
            snprintf(p.payload + i * 2, 3, "%02X", tcp_payload[i]);
        }

        break;

    // UDP Protocol
    case 17:
        udp++;
        struct udphdr *udpHeader = (struct udphdr *)(packet + p.ip_hl * 4);
        const u_char *udp_payload;

        p.p_hl = 2;
        p.srcport = ntohs(udpHeader->uh_sport);
        p.dstport = ntohs(udpHeader->uh_dport);

        // Calculate payload start
        udp_payload = packet + p.ip_hl * 4 + p.p_hl * 4;
        // Get payload length
        int udp_payload_length = pkthdr->len - (ETHER_HDR_LEN + p.ip_hl * 4 + p.p_hl * 4);
        p.p_len = udp_payload_length;
        if (udp_payload_length >= 8000){
            udp_payload_length = 8000;
        }
        for (int i = 0; i < udp_payload_length; i++) {
            snprintf(p.payload + i * 2, 3, "%02X", udp_payload[i]);
        }

        break;

    default:
        others++;
        p.p_hl = 2;
        p.srcport = 0;
        p.dstport = 0;
        break;
    }

    //printf("%u, %u, %hu, %hu, %u, %lu, %hu, %u, %u, %u, %hu, %u, %hu, %hu, %hu\n", p.srcip, p.dstip, p.srcport, p.dstport, p.ip_p, p.timestamp, p.ip_len, p.ip_v, p.ip_hl, p.ip_tos, p.ip_id, p.ip_ttl, p.ip_sum, p.tcp_flags, p.tcp_win);

    trace_pkts = (Packet *)realloc(trace_pkts, (trace_count + 1) * sizeof(Packet));
    trace_pkts[trace_count] = p;
    // printf("%u\n", trace_count);
    trace_count++;
}

void pcapParser(char *fileName)
{
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // open trace file for offline processing
    printf("Pre-process pcap file %s\n", fileName);
    trace_count = 0;

    descr = pcap_open_offline(fileName, errbuf);

    if (descr == NULL)
    {
        printf("[FILE ERROR] pcap_open_live() failed: \n");
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0)
    {
        printf("pcap_loop() failed: %s\n", pcap_geterr(descr));
    }

    printf("This pcap chunk reading is done... total %d packets \n", trace_count);
}

int pcap2csv(char *pcapFile, char *csvFile)
{
    printf("pcap file: %s\n", pcapFile);
    printf("csv file: %s\n", csvFile);

    pcapParser(pcapFile);
    printf("TCP: %d, UDP: %d, ICMP: %d, Others: %d, total: %d\n", tcp, udp, icmp, others, total);

    FILE *fp;
    fp = fopen(csvFile, "w+");

    fprintf(fp, "srcip,dstip,srcport,dstport,proto,time,pkt_len,version,ihl,phl,tos,id,flag,off,ttl,chksum,tcp_flag,windows,pl_len,payload\n");

    for (int i = 0; i < trace_count; i++)
    {
        Packet p = trace_pkts[i];

        unsigned short int ip_flag = p.ip_off >> 13;
        unsigned short int ip_off = p.ip_off & IP_OFFMASK;

        char proto[128];
        if (p.ip_p == 6)
        {
            strcpy(proto, "TCP");
        }
        else if (p.ip_p == 17)
        {
            strcpy(proto, "UDP");
        }
        //------------unsw------------------------//
        else if (p.ip_p == 89)
        {
            strcpy(proto, "ospf");
        }
        else if (p.ip_p == 132)
        {
            strcpy(proto, "sctp");
        }
        else if (p.ip_p >= 146 && p.ip_p >= 252)
        {
            strcpy(proto, "unas");
        }
        //---------------------------------------//
        else if (p.ip_p == 1)
        {
            strcpy(proto, "D");
        }
        else
        {
            strcpy(proto, "D");
        }

        fprintf(fp, "%u,%u,%hu,%hu,%s,%lu,%hu,%u,%u,%u,%u,%hu,%hu,%hu,%u,%hu,%u,%hu,%u,%s\n", p.srcip, p.dstip, p.srcport, p.dstport, proto, p.timestamp, p.ip_len, p.ip_v, p.ip_hl, p.p_hl, p.ip_tos, p.ip_id, ip_flag, ip_off, p.ip_ttl, p.ip_sum, p.tcp_flags, p.tcp_win, p.p_len, p.payload);
    }

    fclose(fp);

    return 0;
}