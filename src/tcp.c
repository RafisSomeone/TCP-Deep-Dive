#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "tcp.h"
#include "packet.h"

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

unsigned short tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp, const unsigned char *payload, int payload_len) {
    int tcp_len = (int)(sizeof(struct tcphdr)) + payload_len;

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

