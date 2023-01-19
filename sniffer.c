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
    uint32_t unix_time;
    uint16_t total_length;
    union {
        uint16_t flags;
        uint16_t reserved: 3;
        uint16_t cache: 1;
        uint16_t steps: 1;
        uint16_t type: 1;
        uint16_t status_code: 10;
    };

    uint16_t cache_control;
    uint16_t padding;
} app_header;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    FILE *pfile;
    pfile = fopen("211344015_208007351.txt", "a+");
    if (pfile == NULL) {
        printf("Error opening file!\n");
        return;
    }

    struct ether_header *eth_header = (struct ether_header *) packet;
    const struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + (ip_header->ip_hl) * 4);
    app_header *appH = (app_header *) (packet + sizeof(struct ether_header) + (ip_header->ip_hl) * 4 +
                                       tcp_header->doff * 4);

    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->ip_src, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip, INET_ADDRSTRLEN);
    //
    unsigned char *data = (unsigned char *) (packet + sizeof(struct ether_header) + (ip_header->ip_hl) * 4 +
                                             tcp_header->doff * 4 + sizeof(app_header));
    unsigned int data_size = header->len - sizeof(struct ether_header) - (ip_header->ip_hl) * 4 - tcp_header->doff * 4;
    fprintf(pfile, "---------");
    if (tcp_header->psh) {
        fprintf(pfile, " PSH ");
    }
    if (tcp_header->syn) {
        fprintf(pfile, " SYN ");
    }
    if (tcp_header->ack) {
        fprintf(pfile, " ACK ");
    }
    if (tcp_header->fin) {
        fprintf(pfile, " FIN ");
    }
    fprintf(pfile, "----------");


    if (tcp_header->psh) {
        fprintf(pfile,
                "source ip: %s, dest_ip: %s\nsource_port: %u, dest_port: %hu\ntimestamp: %u\ntotal_length: %hu\ncache Flag: %u\nsteps Flag: %u\ntype Flag: %u\nstatus Code: %u\ncache_control: %hu\ndata:",
                source_ip, dest_ip, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport),
                ntohl(appH->unix_time), ntohs(appH->total_length), (ntohs(appH->flags) >> 12) & 0x1,
                (ntohs(appH->flags) >> 11) & 0x1, (ntohs(appH->flags) >> 10) & 0x1, ntohs(appH->flags) & 0x3ff,
                ntohs(appH->cache_control));


        for (int i = 0; i < data_size; i++) {
            if (!(i & 15)) fprintf(pfile, "\n%04X:  ", i);
            fprintf(pfile, "%02X ", ((unsigned char *) data)[i]);
        }
    } else {
        fprintf(pfile,
                "source ip: %s, dest_ip: %s\nsource_port: %u, dest_port: %hu\n no application header!\n",
                source_ip, dest_ip, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
    }

    fprintf(pfile,
            "\n");

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
    // Step 2: Compile filter_exp into BPF
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}

