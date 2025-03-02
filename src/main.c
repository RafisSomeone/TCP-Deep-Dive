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
#include "context.h"

enum state {
    LISTENING,
    HANDSHAKE_INITIATED,
    DATA_TRANSFER,
    CLOSING_CONNECTION
};


enum state transition_from_listening(struct packet* current_packet, struct client_context context) {
    if (current_packet->tcp->syn) {
        unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 1, 0);
        int result = sendto(context.connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                            (struct sockaddr*)&context.address, context.address_len);
        if (result < 0) perror("sendto");
        return HANDSHAKE_INITIATED;
    }

    return LISTENING;
}

enum state transition_from_handshake_initiated(struct packet* current_packet, struct client_context context) {
    if(current_packet->tcp->ack) {
        //if(opts.debug) printf("Connection established\n");
        context.server_sequence++;
        return DATA_TRANSFER;
    }

    return HANDSHAKE_INITIATED;
}

enum state transition_from_data_transfer(struct packet* current_packet, struct client_context context) {
    if (current_packet->tcp->fin) {
        unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 0);
        int result_sync = sendto(context.connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                          (struct sockaddr*)&context.address, context.address_len);

        unsigned char* fin = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 1);
        int result_fin = sendto(context.connection, fin, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                          (struct sockaddr*)&context.address, context.address_len);
        sleep(1);

        return LISTENING;
    }

    unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(current_packet->payload_size + ntohl(current_packet->tcp->seq)), 0, 0);
    int result = sendto(context.connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
                          (struct sockaddr*)&context.address, context.address_len);

    return DATA_TRANSFER;
}

enum state handle_packet(enum state current_state, struct packet* current_packet, struct client_context context, struct options opts) {
    if (opts.debug) printf("Current state: %d\n", current_state);

    switch(current_state) {
        case LISTENING:
            return transition_from_listening(current_packet, context);
        case HANDSHAKE_INITIATED:
            return transition_from_handshake_initiated(current_packet, context);
        case DATA_TRANSFER:
            return transition_from_data_transfer(current_packet, context);
        default:
            fprintf(stderr, "Uknown state, reset\n");
            return LISTENING;
    }
}

int main(int argc, char** argv) {

    struct options opts = parse_options(argc, argv);
    
    if (opts.help == 1) {
        return 0;
    }

    struct client_context context;
    unsigned char* buffer = malloc(MAX_IP_V4_PACKET_SIZE);
    context.connection = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (context.connection < 0) {
        fprintf(stderr, "Socket creation failed, run with sudo\n");
        exit(2);
    }
    
    context.address_len = sizeof(struct sockaddr_ll);
    context.server_sequence = rand() % 100000;

    enum state current_state = LISTENING;

    while (1) {
        int bytes_received = recvfrom(context.connection, buffer, MAX_IP_V4_PACKET_SIZE, 0, 
                                      (struct sockaddr*) &context.address, &context.address_len);
        if (bytes_received < 0) {
            fprintf(stderr, "recvfrom failed\n");
            shutdown(context.connection, SHUT_RDWR);
            close(context.connection);
            free(buffer);
            exit(1);
        }
        
        struct packet* current_packet = malloc(sizeof(struct packet));
        if (parse_packet(buffer, current_packet) == -1) {
            continue;
        }

        //if (opts.debug) print_built_in(current_packet); 
        if (opts.verbose) print_raw_bits(buffer, bytes_received);
        if (opts.verbose) print_sections(buffer, bytes_received);

        current_state = handle_packet(current_state, current_packet, context, opts);

//        if (phase == 0 && current_packet->tcp->syn) {
//
//        unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 1, 0);
//        int result = sendto(connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
//                            (struct sockaddr*)&client_addr, addr_len);
//        perror("sendto");
//
//        phase++;
//        } else if(phase == 1 && current_packet->tcp->ack) {
//            phase++;
//            printf("Connection established\n");
//            server_seq++;
//        } else if(phase == 2 && current_packet->tcp->ack) {
//            phase++;
//            printf("send2\n");
//            printf("Payload length %d\n", current_packet->payload_size);
//            unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(current_packet->payload_size + ntohl(current_packet->tcp->seq)), 0, 0);
//            int result = sendto(connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
//                            (struct sockaddr*)&client_addr, addr_len);
//        } else if(phase == 3 && current_packet->tcp->fin) {
//            printf("send3\n");
//            phase = 0;
//
//            unsigned char* syn_ack = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 0);
//            int result_sync = sendto(connection, syn_ack, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
//                            (struct sockaddr*)&client_addr, addr_len);
//            printf("send fin\n");
//            unsigned char* fin = init_syn_ack(current_packet, server_seq, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 1);
//            int result_fin = sendto(*connection, fin, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), 0, 
//                            (struct sockaddr*)&client_addr, addr_len);
//            sleep(1);
//        }

    }

    shutdown(context.connection, SHUT_RDWR);
    close(context.connection);
    free(buffer);
    return 0;
}

