#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <string.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>



// ip header

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





/*tcp header */
struct tcpheader
{
    u_short th_sport;    /* source port */
    u_short th_dport;    /* destination port */
    unsigned int th_seq; /* sequence number */
    unsigned int th_ack; /* acknowledgement number */
    u_short th_win;      /* window */
    u_short th_sum;      /* checksum */
    u_short th_urp;      /* urgent pointer */
};


/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};

struct udpheader
{
    u_int16_t udp_sport; /* source port */
    u_int16_t udp_dport; /* destination port */
    u_int16_t udp_ulen;  /* udp length */
    u_int16_t udp_sum;   /* udp checksum */
};



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



//icmp cheksum


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


/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    struct udphdr* udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);
    //printf("~~~~~~~~~~~udp len=%dn", udpLen);
    //add the pseudo header
    //printf("add pseudo headern");
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;

    //add the IP payload
    //printf("add ip payloadn");
    //initialize checksum to 0
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ipPayload++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    //printf("one's complementn");
    sum = ~sum;
    //set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;

}



void udp_spoof(){
    char buffer[1500];

    memset(buffer, 0, 1500);
    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer +
                                                  sizeof(struct ipheader));

    /*********************************************************
       Step 1: Fill in the UDP data field.
     ********************************************************/
    char *data = buffer + sizeof(struct ipheader) +
                 sizeof(struct udpheader);
    const char *msg = "Hello Server!\n";
    int data_len = strlen(msg);
    strncpy (data, msg, data_len);

    /*********************************************************
       Step 2: Fill in the UDP header.
     ********************************************************/
    udp->udp_sport = htons(12345);
    udp->udp_dport = htons(9090);
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
    udp->udp_sum =  0; /* Many OSes ignore this field, so we do not
                         calculate it. */

    /*********************************************************
       Step 3: Fill in the IP header.
     ********************************************************/

    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.9.0.1");
    ip->iph_protocol = IPPROTO_UDP; // The value is 17.
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct udpheader) + data_len);

    /*********************************************************
       Step 4: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet (ip);

}



void icmp_spoof() {
    char buffer[1500];

    memset(buffer, 0, 1500);

    /*********************************************************
       Step 1: Fill in the ICMP header.
     ********************************************************/
    struct icmpheader *icmp = (struct icmpheader *)
            (buffer + sizeof(struct ipheader));
    icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

    // Calculate the checksum for integrity
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

    /*********************************************************
       Step 2: Fill in the IP header.
     ********************************************************/
    struct ipheader *ip = (struct ipheader *) buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.9.0.1");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

    /*********************************************************
       Step 3: Finally, send the spoofed packet
     ********************************************************/
    send_raw_ip_packet (ip);

}



/* Psuedo TCP header */
struct pseudo_tcp
{
    unsigned saddr, daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[512];
};


//tcp cheksum

unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip +
                                                 sizeof(struct ipheader));

    int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

    /* pseudo tcp header for the checksum computation */
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

    p_tcp.saddr  = ip->iph_sourceip.s_addr;
    p_tcp.daddr  = ip->iph_destip.s_addr;
    p_tcp.mbz    = 0;
    p_tcp.ptcl   = IPPROTO_TCP;
    p_tcp.tcpl   = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    return  (unsigned short) in_cksum((unsigned short *)&p_tcp,
                                      tcp_len + 12);
}

void tcp_spoof(){
    char packet[5000];
    memset(packet, 0, sizeof(packet));

    // Create pointers to the headers
    struct ipheader *ip = (struct ipheader *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));

    // IP header
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 100;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("10.9.0.1");
    ip->iph_protocol = IPPROTO_TCP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
    ip->iph_ident = htons(rand());


    // TCP header
    tcp->source = htons(5556);
    tcp->dest = htons(5555);
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = sizeof(struct tcphdr) / 4;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->window = htons(5000);
    tcp->check = calculate_tcp_checksum(ip);
    tcp->urg_ptr = 0;

    send_raw_ip_packet(ip);


}



int main(){

    //icmp_spoof();
    //udp_spoof();
    tcp_spoof();


    return 0;
}