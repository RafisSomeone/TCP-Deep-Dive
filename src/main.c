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


void print_tcpdump_from_buffer(const unsigned char* buffer, int size, const char* color) {
    struct timeval tv;
    gettimeofday(&tv, NULL);  // Get current timestamp

    struct ethhdr* eth = (struct ethhdr*)buffer;
    struct iphdr* ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    struct tcphdr* tcp = (struct tcphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
    int ip_header_size = ip->ihl * 4;
    int tcp_header_size = tcp->doff * 4;
    int payload_size = size - (sizeof(struct ethhdr) + ip_header_size + tcp_header_size);
    unsigned char* payload = (unsigned char*)(buffer + sizeof(struct ethhdr) + ip_header_size + tcp_header_size);

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

    // Apply color to output
    printf("%s", color);

    // Print timestamp
    printf("%02ld:%02ld:%02ld.%06ld ", 
           (tv.tv_sec / 3600) % 24, (tv.tv_sec / 60) % 60, tv.tv_sec % 60, tv.tv_usec);

    // Print IP header information
    printf("IP %s.%d > %s.%d: ", 
           src_ip, ntohs(tcp->source), dst_ip, ntohs(tcp->dest));

    // Print TCP Flags
    printf("Flags [");
    if (tcp->syn) printf("S");
    if (tcp->ack) printf(".");
    if (tcp->fin) printf("F");
    if (tcp->rst) printf("R");
    if (tcp->psh) printf("P");
    if (tcp->urg) printf("U");
    printf("], ");

    // Print Sequence and Acknowledgment Numbers
    printf("seq %u", ntohl(tcp->seq));
    if (tcp->ack) {
        printf(", ack %u", ntohl(tcp->ack_seq));
    }

    // Print Window Size
    printf(", win %u", ntohs(tcp->window));

    // Print Payload Length
    printf(", length %d", payload_size);

    // Reset color
    printf("\x1b[0m" "\n");
}

struct response {
    unsigned char* data;
    struct response* next;
};

struct state_transition {
    enum state next_state;
    struct response* response_head;
};

struct state_transition transition_from_listening(struct packet* current_packet, struct client_context* context) {
    if (current_packet->tcp->syn) {
        printf("Handshake response\n");
        unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 1, 0);

        struct response* data = malloc(sizeof(struct response));
        data->data = syn_ack;
        data->next = NULL;
        return (struct state_transition) {HANDSHAKE_INITIATED, data};
    }

    return (struct state_transition) {LISTENING, NULL};
}

struct state_transition transition_from_handshake_initiated(struct packet* current_packet, struct client_context* context) {
    if(current_packet->tcp->ack) {
        //if(opts.debug) printf("Connection established\n");
        printf("Handshake completed, waiting for data\n");
        printf("Server sequence: %d\n", context->server_sequence);
        context->server_sequence++;
        printf("Server sequence: %d\n", context->server_sequence);
        return (struct state_transition) {DATA_TRANSFER, NULL};
    }

    return (struct state_transition) {HANDSHAKE_INITIATED, NULL};
}

struct state_transition transition_from_data_transfer(struct packet* current_packet, struct client_context* context) {
    if (current_packet->tcp->fin) {
        unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 0);
        unsigned char* fin = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 0, 1);
        struct response* second = malloc(sizeof(struct response));
        struct response* first = malloc(sizeof(struct response));
        second->data = fin;
        second->next = NULL;
        first-> data = syn_ack;
        first-> next = second;

        return (struct state_transition) {LISTENING, first};
    }

    unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(current_packet->payload_size + ntohl(current_packet->tcp->seq)), 0, 0);
    struct response* data = malloc(sizeof(struct response));
    data->data = syn_ack;
    data->next = NULL;
    return (struct state_transition) {DATA_TRANSFER, data};
}

void handle_transition(struct state_transition transition, struct client_context* context) {
    int size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    struct response* head = transition.response_head;
    while (head != NULL) {
            int result = sendto(context->connection, head->data, size, 0, (struct sockaddr*)&context->address, context->address_len);
            print_tcpdump_from_buffer(head->data, size, "\x1b[36m");
            head = head->next;
        }
}

enum state handle_packet(enum state current_state, struct packet* current_packet, struct client_context* context, struct options opts) {
    if (opts.debug) printf("\nCurrent state: %d\n", current_state);
    struct state_transition transition;
    switch(current_state) {
        case LISTENING:
            transition = transition_from_listening(current_packet, context);
            break;
        case HANDSHAKE_INITIATED:
            transition = transition_from_handshake_initiated(current_packet, context);
            break;
        case DATA_TRANSFER:
            transition = transition_from_data_transfer(current_packet, context);
            break;
        default:
            fprintf(stderr, "Uknown state, reset\n");
            transition = (struct state_transition) {LISTENING};
    }

    handle_transition(transition, context);
    current_state = transition.next_state;
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

        if (opts.verbose) print_tcpdump_from_buffer(buffer, bytes_received, "\x1b[36m");

        struct packet* current_packet = malloc(sizeof(struct packet));
        if (parse_packet(buffer, current_packet) == -1) {
            continue;
        }

        if (opts.verbose) print_raw_bits(buffer, bytes_received);
        if (opts.verbose) print_sections(buffer, bytes_received);

        current_state = handle_packet(current_state, current_packet, &context, opts);
    }

    shutdown(context.connection, SHUT_RDWR);
    close(context.connection);
    free(buffer);
    return 0;
}

