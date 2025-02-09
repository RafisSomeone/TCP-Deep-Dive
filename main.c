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
    printf("\n\n");
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

    printf("IP header:\n");
    print_range(buffer, ip_header_start, tcp_header_start);

    printf("TCP header:\n");
    print_range(buffer, tcp_header_start, payload_start);

    printf("Payload:\n");
    print_range(buffer, payload_start, size);
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

