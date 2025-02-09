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

int range_hex_to_decimal(unsigned char* buffer, int from, int to) {
    int result = 0;

    for (int i = from; i < to; i++) {
        result = (result << 8) | buffer[i];
    }

    return result;
}

void print_ethernet_header(unsigned char* buffer, int from, int to) {
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

void print_tcp_header(unsigned char* buffer, int from, int to) {
    int source_port_size = 2;
    int destination_port_size = 2;
    int sequence_number_size = 4;
    int acknowledgment_number_size = 4;
    int data_offset_size = 1;
    int reserved_flags_size = 1;
    int window_size = 2;
    int checksum_size = 2;
    int urgent_pointer_size = 2;
    int data_offset_word_size = 4;

    int source_port_start = from;
    int destination_port_start = source_port_start + source_port_size;
    int sequence_number_start = destination_port_start + destination_port_size;
    int acknowledgment_number_start = sequence_number_start + sequence_number_size;
    int data_offset_start = acknowledgment_number_start + acknowledgment_number_size;
    int reserved_flags_start = data_offset_start + data_offset_size;
    int window_size_start = reserved_flags_start + reserved_flags_size;
    int checksum_start = window_size_start + window_size;
    int urgent_pointer_start = checksum_start + checksum_size;
    int options_start = urgent_pointer_start + urgent_pointer_size; 

    printf("\n");
    int source_port = range_hex_to_decimal(buffer, source_port_start, destination_port_start);
    printf("Source Port: %d\n", source_port);

    int destination_port = range_hex_to_decimal(buffer, destination_port_start, sequence_number_start);
    printf("Destination Port: %d\n", destination_port);

    int sequence_number = range_hex_to_decimal(buffer, sequence_number_start, acknowledgment_number_start);
    printf("Sequence Number: %d\n", sequence_number);

    int acknowledgment_number = range_hex_to_decimal(buffer, acknowledgment_number_start, data_offset_start);
    printf("Acknowledgment Number: %d\n", acknowledgment_number);

    int data_offset_flags = buffer[data_offset_start];
    int data_offset = ((data_offset_flags >> 4) & 0x0F) * data_offset_word_size;
    printf("Data Offset: %d bytes\n", data_offset);

    int reserved = (data_offset_flags & 0x0F);
    printf("Reserved: %x\n", reserved);

    printf("Flags: ");
    print_bits(buffer, reserved_flags_start, window_size_start);

    int window = range_hex_to_decimal(buffer, window_size_start, checksum_start);
    printf("Window Size: %d\n", window);

    printf("Checksum: ");
    print_range(buffer, checksum_start, urgent_pointer_start);

    int urgent_pointer = range_hex_to_decimal(buffer, urgent_pointer_start, options_start);
    printf("Urgent Pointer: %d\n", urgent_pointer);
}

void print_ip(unsigned char* buffer, int from) {
    printf("%d.%d.%d.%d\n", buffer[from], buffer[from + 1], buffer[from + 2], buffer[from + 3]);
}

void print_ip_header(unsigned char* buffer, int from, int to) {
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

    printf("\n");
    printf("Version: %d\n", version);
    printf("Header Length: %d bytes\n", ihl);

    printf("ECN & DSCP: ");
    print_range(buffer, ecn_start, total_length_start);

    int total_length = range_hex_to_decimal(buffer, total_length_start, identification_start);
    printf("Total Length: %d bytes\n", total_length);

    printf("Identification: ");
    print_range(buffer, identification_start, flags_fragment_offset_start);

    printf("Flags & Fragment Offset: ");
    print_bits(buffer, flags_fragment_offset_start, ttl_start);

    int ttl = range_hex_to_decimal(buffer, ttl_start, protocol_start);
    printf("Time to Live: %d\n", ttl);

    int protocol = range_hex_to_decimal(buffer, protocol_start, checksum_start); 
    printf("Protocol: %d \n", protocol);

    printf("Header Checksum: ");
    print_range(buffer, checksum_start, source_ip_start);

    printf("Source IP: ");
    print_ip(buffer, source_ip_start);

    printf("Destination IP: ");
    print_ip(buffer, destination_ip_start);
}

void print_sections(unsigned char* buffer, int size) {
    int ethernet_header_size = 14;
    int ip_header_size = 20;
    int tcp_header_size = 20;

    int ethernet_header_start = 0;
    int ip_header_start = ethernet_header_start + ethernet_header_size;
    int tcp_header_start = ip_header_start + ip_header_size;
    int payload_start = tcp_header_start + tcp_header_size;

    printf("Ethernet header:\n");
    print_range(buffer, ethernet_header_start, ip_header_start);
    print_ethernet_header(buffer, ethernet_header_start, ip_header_start);
    printf("\n");

    printf("IP header:\n");
    print_range(buffer, ip_header_start, tcp_header_start);
    print_ip_header(buffer, ip_header_start, tcp_header_start);
    printf("\n");

    printf("TCP header:\n");
    print_range(buffer, tcp_header_start, payload_start);
    print_tcp_header(buffer, tcp_header_start, payload_start);
    printf("\n");

    printf("Payload:\n");
    print_range(buffer, payload_start, size);
    printf("\n");
}

int main() {
    int max_ip_v4_packet_size = 65536; 
    unsigned char* buffer = malloc(max_ip_v4_packet_size);
    int server_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (server_fd < 0) {
        printf("Socket creation failed, run with sudo\n");
        exit(2);
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        int bytes_received = recvfrom(server_fd, buffer, max_ip_v4_packet_size, 0, 
                                      (struct sockaddr*)&client_addr, &addr_len);
        if (bytes_received < 0) {
            printf("recvfrom failed");
            break;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr)); 

        int ip_header_size = ip->ihl * 4;
        int eth_ip_header_size = sizeof(struct ethhdr) + ip_header_size; 

            
        if (ip->protocol != IPPROTO_TCP) {
            continue;
        }

        struct tcphdr *tcp = (struct tcphdr *)(buffer + eth_ip_header_size);
        if (ntohs(tcp->dest) != 3000)  {
            continue;  
        }

        printf("\nReceived packet of size %d bytes\n", bytes_received);
        printf("Ethernet Header:\n");
        printf("   Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("   Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("   Protocol: 0x%04X\n", ntohs(eth->h_proto));

        if (ntohs(eth->h_proto) == ETH_P_IP) {
            printf("IP Header:\n");
            printf("   Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("   Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
            printf("   Protocol: %d\n", ip->protocol);
            printf("   Total Length: %d\n\n", ntohs(ip->tot_len));
        }

        for (int i = 0; i < bytes_received; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\n\n");

        print_sections(buffer, bytes_received);

    }

    close(server_fd);
    free(buffer);
    return 0;
}

