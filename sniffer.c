//
// Created by alon on 1/12/23.
//

#include "sniffer.h"
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "arpa/inet.h"

void got_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    FILE *pfile;
    pfile = fopen("211344015_208007351.txt", "a");

    if (pfile == NULL) {
        printf("Error opening file!\n");
        return;
    }
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ip)); // thats it?
    const struct ip *ip_header = (struct ip*)(packet);

    int  source_port, dest_port;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN] , *timestamp, *total_length, *cache_flag, *steps_flag, *type_flag, *status_code, *cache_control, *data;
    inet_ntop(AF_INET, &ip_header->ip_src, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);
    source_port = (int)ntohs(tcp_header->th_sport);
    dest_port = (int)ntohs(tcp_header->th_dport);



    fprintf(pfile,
            "source ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %s, total_length: %s, cache_flag: %s, steps_flag: %s, type_flag: %s, status_code: %s, cache_control: %s, data: %s",
            source_ip, dest_ip, source_port, dest_port, timestamp, total_length, cache_flag, steps_flag, type_flag, status_code, cache_control, data);

    fclose(pfile);
}

int main() {
    pcap_t *handle;
    char error_buf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("eth3", BUFSIZ, 1, 1000, error_buf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}

