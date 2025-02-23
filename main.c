#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>  
#include <net/ethernet.h>
#include <net/if.h>
#include <netpacket/packet.h>

const int max_ip_v4_packet_size = 65535; 
typedef struct {
   struct ethhdr* eth;
   struct iphdr* ip;
   struct tcphdr* tcp;
   int payload_size;
   unsigned char* payload;
} packet;

void print_range(unsigned char* buffer, int from, int to) {
    for (int i = from; i < to; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");
}

void print_mac(unsigned char* buffer, int from, int to) {
    for (int i = from; i < to - 1; i++) {
        printf("%02X:", buffer[i]);
    }
    printf("%02X\n", buffer[to - 1]);
}

void print_bits(unsigned char* buffer, int from, int to) {
    for (int i = from; i < to; i++) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (buffer[i] >> j) & 1);
        }
        printf(" ");
    }
    printf("\n");
}

unsigned long range_hex_to_decimal(unsigned char* buffer, int from, int to) {
    unsigned long result = 0;

    for (int i = from; i < to; i++) {
        result = (result << 8) | buffer[i];
    }

    return result;
}

void parse_ethernet_header(unsigned char* buffer, int from, int to) {
    int destiantion_mac_size = 6;
    int source_mac_size = 6;
    int ethertype_size = 2;

    int source_mac_start = destiantion_mac_size + from;
    int ethertype_start = source_mac_start + source_mac_size;

    printf("\n");
    printf("Destination MAC: ");
    print_mac(buffer, from , source_mac_start);

    printf("Source MAC: "); 
    print_mac(buffer, source_mac_start, ethertype_start);
    
    printf("Ether Type: "); 
    print_range(buffer, ethertype_start, to);
}

int parse_tcp_header(unsigned char* buffer, int from) {
    int source_port_size = 2;
    int destination_port_size = 2;
    int sequence_number_size = 4;
    int acknowledgment_number_size = 4;
    int data_offset_size = 1;
    int flags_size = 1;
    int window_size = 2;
    int checksum_size = 2;
    int urgent_pointer_size = 2;
    int data_offset_word_size = 4;

    int source_port_start = from;
    int destination_port_start = source_port_start + source_port_size;
    int sequence_number_start = destination_port_start + destination_port_size;
    int acknowledgment_number_start = sequence_number_start + sequence_number_size;
    int data_offset_start = acknowledgment_number_start + acknowledgment_number_size;
    int flags_start = data_offset_start + data_offset_size;
    int window_size_start = flags_start + flags_size;
    int checksum_start = window_size_start + window_size;
    int urgent_pointer_start = checksum_start + checksum_size;
    int options_start = urgent_pointer_start + urgent_pointer_size; 

    printf("\n");
    unsigned long source_port = range_hex_to_decimal(buffer, source_port_start, destination_port_start);
    printf("Source Port: %ld\n", source_port);

    unsigned long destination_port = range_hex_to_decimal(buffer, destination_port_start, sequence_number_start);
    printf("Destination Port: %ld\n", destination_port);

    unsigned long sequence_number = range_hex_to_decimal(buffer, sequence_number_start, acknowledgment_number_start);
    printf("Sequence Number: %ld\n", sequence_number);

    unsigned long acknowledgment_number = range_hex_to_decimal(buffer, acknowledgment_number_start, data_offset_start);
    printf("Acknowledgment Number: %ld\n", acknowledgment_number);

    int data_offset_reserved = buffer[data_offset_start];
    int data_offset = ((data_offset_reserved >> 4) & 0x0F) * data_offset_word_size;
    printf("Data Offset: %d bytes\n", data_offset);

    int reserved = (data_offset_reserved & 0x0F);
    printf("Reserved: %x\n", reserved);

    int flags = buffer[flags_start];
    printf("Flags: ");
    if (flags & 0x02) printf("SYN ");
    if (flags & 0x10) printf("ACK ");
    if (flags & 0x01) printf("FIN ");
    if (flags & 0x04) printf("RST ");
    if (flags & 0x08) printf("PSH ");
    if (flags & 0x20) printf("URG ");
    printf("\n");

    unsigned long window = range_hex_to_decimal(buffer, window_size_start, checksum_start);
    printf("Window Size: %ld\n", window);

    printf("Checksum: ");
    print_range(buffer, checksum_start, urgent_pointer_start);

    unsigned long urgent_pointer = range_hex_to_decimal(buffer, urgent_pointer_start, options_start);
    printf("Urgent Pointer: %ld\n", urgent_pointer);

    printf("Options: ");
    if (from + data_offset - options_start <= 0) {
        printf("Empty");
    }
    print_range(buffer, options_start, from + data_offset);

    return data_offset;
}

void print_ip(unsigned char* buffer, int from) {
    printf("%d.%d.%d.%d\n", buffer[from], buffer[from + 1], buffer[from + 2], buffer[from + 3]);
}

int parse_ip_header(unsigned char* buffer, int from) {
    int version_ihl_size = 1;
    int ecn_size = 1;
    int total_length_size = 2;
    int identification_size = 2;
    int flags_fragment_offset_size = 2;
    int ttl_size = 1;
    int protocol_size = 1;
    int checksum_size = 2;
    int source_ip_size = 4;
    int destination_ip_size = 4;
    int ihl_word_size = 4;

    int version_ihl = buffer[from];  
    int version = (version_ihl >> 4);
    int ihl = (version_ihl & 0x0F) * ihl_word_size;

    int ecn_start = from + version_ihl_size;
    int total_length_start = ecn_start + ecn_size;
    int identification_start = total_length_start + total_length_size;
    int flags_fragment_offset_start = identification_start + identification_size;
    int ttl_start = flags_fragment_offset_start + flags_fragment_offset_size;
    int protocol_start = ttl_start + ttl_size;
    int checksum_start = protocol_start + protocol_size;
    int source_ip_start = checksum_start + checksum_size;
    int destination_ip_start = source_ip_start + source_ip_size;
    int options_start = destination_ip_start + destination_ip_size;

    printf("\n");
    printf("Version: %d\n", version);
    printf("Header Length: %d bytes\n", ihl);

    printf("ECN & DSCP: ");
    print_range(buffer, ecn_start, total_length_start);

    unsigned long total_length = range_hex_to_decimal(buffer, total_length_start, identification_start);
    printf("Total Length: %ld bytes\n", total_length);

    printf("Identification: ");
    print_range(buffer, identification_start, flags_fragment_offset_start);

    printf("Flags & Fragment Offset: ");
    print_bits(buffer, flags_fragment_offset_start, ttl_start);

    unsigned long ttl = range_hex_to_decimal(buffer, ttl_start, protocol_start);
    printf("Time to Live: %ld\n", ttl);

    unsigned long protocol = range_hex_to_decimal(buffer, protocol_start, checksum_start); 
    printf("Protocol: %ld \n", protocol);

    printf("Header Checksum: ");
    print_range(buffer, checksum_start, source_ip_start);

    printf("Source IP: ");
    print_ip(buffer, source_ip_start);

    printf("Destination IP: ");
    print_ip(buffer, destination_ip_start);

    printf("Options IP: ");
    if (from + ihl - options_start <= 0) {
        printf("Empty");
    }
    print_range(buffer, options_start, from + ihl);

    return ihl;
}

void print_sections(unsigned char* buffer, int size) {
    int ethernet_header_start = 0;
    int ethernet_header_size = 14;
    int ip_header_start = ethernet_header_start + ethernet_header_size;

    printf("Ethernet header:\n");
    parse_ethernet_header(buffer, ethernet_header_start, ip_header_start);
    printf("Raw Ethernet header: ");
    print_range(buffer, ethernet_header_start, ip_header_start);
    printf("\n");

    printf("IP header:\n");
    int ip_header_size = parse_ip_header(buffer, ip_header_start);
    int tcp_header_start = ip_header_start + ip_header_size;
    printf("Raw IP header: ");
    print_range(buffer, ip_header_start, tcp_header_start);
    printf("\n");

    printf("TCP header:\n");
    int tcp_header_size = parse_tcp_header(buffer, tcp_header_start);
    int payload_start = tcp_header_start + tcp_header_size;
    printf("Raw TCP header: ");
    print_range(buffer, tcp_header_start, payload_start);
    printf("\n");

    printf("Payload:\n");
    if (size - payload_start == 0) {
        printf("Empty");
    }
    print_range(buffer, payload_start, size);
    printf("\n");
}

void print_raw_bits(unsigned char* buffer, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);
    }

    printf("\n\n");
}

void print_eth_built_in(const struct ethhdr* eth) {
    printf("Ethernet Header:\n");
    printf("   Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   Protocol: 0x%04X\n", ntohs(eth->h_proto));
}

void print_ip_built_in(const struct iphdr* ip) {
    printf("IP Header:\n");
    printf("   Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    printf("   Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    printf("   Protocol: %d\n", ip->protocol);
    printf("   Total Length: %d\n\n", ntohs(ip->tot_len));
}

void print_tcp_built_in(const struct tcphdr* tcp) {
    unsigned int header_len = tcp->doff * 4;  
    unsigned char flags = 0;
    flags = *((unsigned char*)tcp + 13); 
    printf("TCP Header:\n");
    printf("   Header Length: %d bytes\n", header_len);
    printf("   Flags: ");
    if (flags & TH_SYN) printf("SYN ");
    if (flags & TH_ACK) printf("ACK ");
    if (flags & TH_FIN) printf("FIN ");
    if (flags & TH_RST) printf("RST ");
    if (flags & TH_PUSH) printf("PSH ");
    if (flags & TH_URG) printf("URG ");
    printf("\n");
    printf("   Window Size: %u\n", ntohs(tcp->window));
    printf("   Checksum: 0x%04X\n", ntohs(tcp->check));
    printf("   Urgent Pointer: %u\n\n", ntohs(tcp->urg_ptr));
}

void print_built_in(const packet* current_packet) {
    struct ethhdr* eth = current_packet->eth;
    print_eth_built_in(eth);
     
    struct iphdr* ip = current_packet->ip;
    print_ip_built_in(ip);

    struct tcphdr* tcp = current_packet->tcp;
    print_tcp_built_in(tcp);
}

int parse_packet(unsigned char* buffer, packet* current_packet) {

    struct ethhdr* eth =(struct ethhdr*) buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return -1;
    }

    struct iphdr* ip = (struct iphdr*) (buffer + sizeof(struct ethhdr)); 
    if (ip->protocol != IPPROTO_TCP) {
        return -1;
    }

    int ip_header_size = ip->ihl * 4;
    int eth_ip_header_size = sizeof(struct ethhdr) + ip_header_size; 
    struct tcphdr* tcp = (struct tcphdr*) (buffer + eth_ip_header_size);

    if (ntohs(tcp->dest) != 3000)  {
        return -1;  
    }

    current_packet->eth = eth;
    current_packet->ip = ip;
    current_packet->tcp = tcp;
    
    current_packet->payload_size = ntohs(ip->tot_len) - ip_header_size - tcp->doff * 4;

    if (current_packet->payload_size > 0) {
        current_packet->payload = malloc(current_packet->payload_size * sizeof(unsigned char));
    }
    memcpy(current_packet->payload, buffer + eth_ip_header_size + tcp->doff * 4, current_packet->payload_size);
    return 0;
}

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp, const unsigned char *payload, int payload_len) {
    int tcp_len = sizeof(struct tcphdr) + payload_len;

    struct pseudo_header psh;
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    int psize = sizeof(struct pseudo_header) + tcp_len;
    unsigned char *pseudogram = calloc(1, psize);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, tcp_len);

    unsigned short checksum = calculate_checksum((unsigned short*)pseudogram, psize);
    free(pseudogram);
    return checksum;
}


unsigned char* init_syn_ack(const packet* current_packet, int seq, int ack, int syn_flag, int fin_flag){
    unsigned char* response = malloc(max_ip_v4_packet_size);
    struct ethhdr* eth_response = (struct ethhdr*) response;

    memcpy(eth_response->h_dest, current_packet->eth->h_source, ETH_ALEN);
    memcpy(eth_response->h_source, current_packet->eth->h_dest, ETH_ALEN);
    eth_response->h_proto = current_packet->eth->h_proto;

    struct iphdr* ip_response = (struct iphdr*) (response + sizeof(struct ethhdr));
    struct tcphdr* tcp_response = (struct tcphdr*) (response + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    ip_response->ihl = 5;
    ip_response->version = current_packet->ip->version;
    ip_response->tos = current_packet->ip->tos;
    ip_response->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_response->id = htons(rand() % 65535);
    ip_response->frag_off = 0;
    ip_response->ttl = current_packet->ip->ttl;
    ip_response->protocol = current_packet->ip->protocol;
    ip_response->saddr = current_packet->ip->daddr;
    ip_response->daddr = current_packet->ip->saddr;

    tcp_response->source = current_packet->tcp->dest;
    tcp_response->dest = current_packet->tcp->source;
    tcp_response->seq = htonl(seq);
    tcp_response->ack_seq = ack;
    tcp_response->doff = 5;
    tcp_response->syn = syn_flag;
    tcp_response->ack = 1;
    tcp_response->fin = fin_flag;
    tcp_response->window = htons(max_ip_v4_packet_size);
    tcp_response->urg_ptr = 0;
    tcp_response->check = 0;
    tcp_response->check = tcp_checksum(ip_response, tcp_response, NULL, 0);

    ip_response->check = 0;
    ip_response->check = calculate_checksum((unsigned short*)ip_response, sizeof(struct iphdr));

    return response;
} 

int main() {
    unsigned char* buffer = malloc(max_ip_v4_packet_size);
    int server_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (server_fd < 0) {
        printf("Socket creation failed, run with sudo\n");
        exit(2);
    }

    struct sockaddr_ll client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_ll);

    int phase = 0;
    int server_seq = rand() % 100000;
    while (1) {
        int bytes_received = recvfrom(server_fd, buffer, max_ip_v4_packet_size, 0, 
                                      (struct sockaddr*) &client_addr, &addr_len);
        if (bytes_received < 0) {
            printf("recvfrom failed");
            close(server_fd);
            free(buffer);
            exit(1);
        }
        
        packet* current_packet = malloc(sizeof(packet));

        if (parse_packet(buffer, current_packet) == -1) {
            continue;
        }

        printf("\nReceived pacet of size %d bytes\n", bytes_received);

        // print_built_in(current_packet); print using built in structures

        //print_raw_bits(buffer, bytes_received);
        //print_sections(buffer, bytes_received);
      
        if (phase == 0 && current_packet->tcp->syn) {

        unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 1, 0);
        int result = sendto(server_fd, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                            (struct sockaddr*)&client_addr, addr_len);
        perror("sendto");

        phase++;
        } else if(phase == 1 && current_packet->tcp->ack) {
            phase++;
            printf("Connection established\n");
            server_seq++;
        } else if(phase == 2 && current_packet->tcp->ack) {
            phase++;
            printf("send2\n");
            printf("Payload length %d\n", current_packet->payload_size);
            unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(current_packet->payload_size + ntohl(current_packet->tcp->seq)), 0, 0);
            int result = sendto(server_fd, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                            (struct sockaddr*)&client_addr, addr_len);
        } else if(phase == 3 && current_packet->tcp->fin) {
            printf("send3\n");
            phase = 0;

            unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 0);
            int result_sync = sendto(server_fd, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                            (struct sockaddr*)&client_addr, addr_len);
            printf("send fin\n");
            unsigned char* fin = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 1);
            int result_fin = sendto(server_fd, fin, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                            (struct sockaddr*)&client_addr, addr_len);
            sleep(1);
        }

    }

    close(server_fd);
    free(buffer);
    return 0;
}

