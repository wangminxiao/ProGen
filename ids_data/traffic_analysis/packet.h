#ifndef PACKET_H
#define PACKET_H

// http://yuba.stanford.edu/~casado/pcap/section4.html

#include <stdio.h>
#define MAX_PAYLOAD_LEN 8000//65535

// Self-defined packet structure
typedef struct Packet
{
    // Timestamp in microseconds
    unsigned long timestamp;    /* timestamp */

    // IP header
    unsigned int ip_hl;         /* header length */
    unsigned int ip_v;          /* version */
    uint8_t ip_tos;             /* type of service */
    u_short ip_len;             /* total length */
    u_short ip_id;              /* identification */
    u_short ip_off;             /* fragment offset field */
    uint8_t ip_ttl;             /* time to live */
    uint8_t ip_p;               /* protocol */
    u_short ip_sum;             /* checksum */
    uint32_t srcip;             /* source IP */
    uint32_t dstip;             /* destination IP */

    // TCP/UDP
    u_short srcport;            /* source port */
    u_short dstport;            /* destination port */
    u_short	p_hl;               /* udp header len, uh_ulen */
    u_short	p_len;
    char payload[MAX_PAYLOAD_LEN*2+1];


    // TCP
    u_char	tcp_flags;          /* flags in tcp header */
    u_short	tcp_win;            /* tcp windows */

}Packet;

Packet* trace_pkts;
int trace_count = 0;

#endif