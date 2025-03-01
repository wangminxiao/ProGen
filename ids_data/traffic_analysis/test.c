#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

#define MAX_FILE_NAME_LEN 256

typedef struct {
    char file_name[MAX_FILE_NAME_LEN];
    pcap_t *handle;
    time_t start_time;
} FlowInfo;

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;
    int ip_header_length;

    // Extract IP header
    ip_header = (struct ip *)(packet + 14); // Ethernet header is 14 bytes
    ip_header_length = ip_header->ip_hl * 4;

    // Check the protocol type
    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);

            // Create a unique file name based on the flow
            snprintf(user->file_name, MAX_FILE_NAME_LEN, "tcp_flow_%s_%d_%s_%d.pcap",
                     inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport),
                     inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header_length);

            // Create a unique file name based on the flow
            snprintf(user->file_name, MAX_FILE_NAME_LEN, "udp_flow_%s_%d_%s_%d.pcap",
                     inet_ntoa(ip_header->ip_src), ntohs(udp_header->uh_sport),
                     inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_dport));
            break;
        }
        default:
            // Ignore non-TCP/UDP packets
            return;
    }

    // Check if a pcap handle for this flow has been created
    if (user->handle == NULL) {
        // Create a new pcap file for this flow
        user->handle = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper_t *dumper = pcap_dump_open(user->handle, user->file_name);

        if (dumper == NULL) {
            fprintf(stderr, "Error creating pcap dump file for flow %s\n", user->file_name);
            return;
        }

        pcap_dump_close(dumper);
        time(&(user->start_time));  // Record the start time for the flow
    }

    // Check if the current packet is within the 300 seconds duration
    if (pkthdr->ts.tv_sec - user->start_time <= 300) {
        // Write the packet to the appropriate pcap file
        pcap_dumper_t *dumper = pcap_dump_open(user->handle, user->file_name);
        pcap_dump((u_char *)dumper, pkthdr, packet);
        pcap_dump_close(dumper);
    } else {
        // If the duration exceeds 300 seconds, close the current pcap handle
        pcap_close(user->handle);
        user->handle = NULL;
    }
}

int main(int argc, char *argv[]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    FlowInfo flow_info = {0};

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Open pcap file
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file '%s': %s\n", argv[1], errbuf);
        return 2;
    }

    // Start packet processing loop
    pcap_loop(handle, (int)strlen(flow_info.file_name), packet_handler, (u_char *)&flow_info);

    // Close the handle
    pcap_close(handle);

    return 0;
}
