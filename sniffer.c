//
// Created by alon on 1/12/23.
//

#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include "arpa/inet.h"

typedef struct application_header {
    unsigned int unix_time;
    unsigned short total_length;
    unsigned char reserved: 3;
    unsigned char cache: 1;
    unsigned char steps: 1;
    unsigned char type: 1;
    unsigned short status_code: 10;
    unsigned short cache_control;
    unsigned short padding;
    unsigned char data[8180];
} app_header;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    FILE *pfile;
    pfile = fopen("211344015_208007351.txt", "a+");
    printf("cdbclbl");
    if (pfile == NULL) {
        printf("Error opening file!\n");
        return;
    }

    struct ether_header *eth_header = (struct ether_header *) packet;
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) +
                                                   sizeof(struct ip)); // thats it?
    const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    app_header *appH = (app_header *) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));


    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN], *data;
    inet_ntop(AF_INET, &ip_header->ip_src, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);
    unsigned int source_port =  ntohs(tcp_header->th_sport);
    unsigned int dest_port = ntohs(tcp_header->th_dport);
    unsigned int timestamp = appH->unix_time;
    unsigned int total_length =  ntohs(header->caplen);
    unsigned char cache_flag = appH->cache;
    unsigned char steps_flag = appH->steps;
    unsigned char type_flag = appH->type;
    unsigned int status_code = appH->status_code;
    unsigned short cache_control = appH->cache_control;

    fprintf(pfile,"%u\n",(unsigned int)header->ts.tv_sec);
    fprintf(pfile,
            "source ip: %s, dest_ip: %s, source_port: %u, dest_port: %u, timestamp: %u, total_length: %u, cache_flag: %hu, steps_flag: %u, type_flag: %u, status_code: %u, cache_control: %hu, data: \n",
            source_ip, dest_ip, source_port, dest_port, timestamp, total_length, cache_flag, steps_flag, type_flag, status_code, cache_control);

    fclose(pfile);
}


int main() {
    pcap_t *handle;
    char error_buf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("lo", BUFSIZ, 1, 1000, error_buf);
    printf("1\n");

    // Step 2: Compile filter_exp into BPF psuedo-code
    printf("1.5\n");
    pcap_compile(handle, &fp, filter_exp, 0, net); // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    printf("1.7\n");
    pcap_setfilter(handle, &fp);
    printf("2\n");
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}

