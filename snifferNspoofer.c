
#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include "arpa/inet.h"
#include <stdlib.h>
#include <string.h>
//#include <netinet/ip.h>
#include <net/ethernet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
//#include <netinet/ip_icmp.h>

#define ICMP_ECHOREPLY 0;



/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};

struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}
void send_raw_ip_packet(struct ipheader* ip){
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct ipheader * ip_header = (struct ipheader *) (packet + 14);
    struct  icmpheader * icmp_heder = ((struct icmpheader *) (packet + 14+ sizeof(struct ipheader)));

    if(icmp_heder->icmp_type == 8) {
        printf("spooing packet...\n");
        char pong[1500];
        memset(pong,0,1500);
        struct ipheader * pong_ip_header = (struct ipheader *) (pong + 14);
        struct  icmpheader * pong_icmp_heder = ((struct icmpheader *) (pong + 14+ sizeof(struct ipheader)));
        pong_ip_header->iph_destip = ip_header->iph_sourceip;
        pong_ip_header->iph_sourceip = ip_header->iph_destip;
        pong_ip_header->iph_ihl = ip_header->iph_ihl;
        pong_ip_header->iph_chksum = ip_header->iph_chksum;
        pong_ip_header->iph_ident = ip_header->iph_ident;
        pong_ip_header->iph_ver = ip_header->iph_ver;
        pong_ip_header->iph_flag = ip_header->iph_flag;
        pong_ip_header->iph_offset = ip_header->iph_offset;
        pong_ip_header->iph_ver = ip_header->iph_ver;
        pong_ip_header->iph_protocol = ip_header->iph_protocol;
        pong_ip_header->iph_tos = ip_header->iph_tos;
        pong_ip_header->iph_ttl = ip_header->iph_ttl;
        pong_ip_header->iph_len = htons(sizeof (struct ipheader ) + sizeof(struct icmpheader));

        pong_icmp_heder->icmp_code = icmp_heder->icmp_code;
        pong_icmp_heder->icmp_type = ICMP_ECHOREPLY;
        pong_icmp_heder->icmp_id = icmp_heder->icmp_id;
        pong_icmp_heder->icmp_seq = icmp_heder->icmp_seq;
        pong_icmp_heder->icmp_chksum = in_cksum((unsigned short *) pong_icmp_heder, sizeof(struct icmpheader));


        send_raw_ip_packet(pong_ip_header);
    }
}


int main() {
    pcap_t *handle;
    char error_buf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("br-01afb1c958ad", BUFSIZ, 1, 1000, error_buf);
    // Step 2: Compile filter_exp into BPF
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}
