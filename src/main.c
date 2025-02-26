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

#include "packet.h"
#include "tcp.h"
#include "ip.h"
#include "options.h"

int main(int argc, char** argv) {
    struct options opts = parse_options(argc, argv);
    
    if (opts.help == 1) {
        return 0;
    }

    unsigned char* buffer = malloc(MAX_IP_V4_PACKET_SIZE);
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
        int bytes_received = recvfrom(server_fd, buffer, MAX_IP_V4_PACKET_SIZE, 0, 
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

