#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>

#include "packet.h"
#include "ip.h"
#include "ethernet.h"
#include "tcp.h"
#include "context.h"

void print_range(unsigned char* buffer, int from, int to) {
    for (int i = from; i < to; i++) {
        printf("%02X ", buffer[i]);
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

void print_raw_bits(unsigned char* buffer, int size) {
    for (int i = 0; i < size; i++) {
        printf("%02X ", buffer[i]);
    }

    printf("\n\n");
}

void print_built_in(const struct packet* current_packet) {
    struct ethhdr* eth = current_packet->eth;
    print_eth_built_in(eth);
     
    struct iphdr* ip = current_packet->ip;
    print_ip_built_in(ip);

    struct tcphdr* tcp = current_packet->tcp;
    print_tcp_built_in(tcp);
}


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
int parse_packet(unsigned char* buffer, struct packet* current_packet) {

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

unsigned char* init_syn_ack(const struct packet* current_packet, struct client_context* context, int ack, int syn_flag, int fin_flag){
    unsigned char* response = malloc(MAX_IP_V4_PACKET_SIZE);
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
    tcp_response->seq = htonl(context->server_sequence);
    tcp_response->ack_seq = ack;
    tcp_response->doff = 5;
    tcp_response->syn = syn_flag;
    tcp_response->ack = 1;
    tcp_response->fin = fin_flag;
    tcp_response->window = htons(MAX_IP_V4_PACKET_SIZE);
    tcp_response->urg_ptr = 0;
    tcp_response->check = 0;
    tcp_response->check = tcp_checksum(ip_response, tcp_response, NULL, 0);

    ip_response->check = 0;
    ip_response->check = calculate_checksum((unsigned short*)ip_response, sizeof(struct iphdr));

    return response;
} 

