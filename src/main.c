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

struct response {
    unsigned char* data;
    struct response* next;
};

struct state_transition {
    enum state next_state;
    struct response* response_head;
};

struct state_transition transition_from_listening(struct packet* current_packet, struct client_context* context, struct options opts) {
    if (current_packet->tcp->syn) {
        if (opts.debug) printf("Handshake response\n");

        unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(ntohl(current_packet->tcp->seq) + 1), 1, 0);

        struct response* data = malloc(sizeof(struct response));
        data->data = syn_ack;
        data->next = NULL;
        return (struct state_transition) {HANDSHAKE_INITIATED, data};
    }

    return (struct state_transition) {LISTENING, NULL};
}

struct state_transition transition_from_handshake_initiated(struct packet* current_packet, struct client_context* context, struct options opts) {
    if(current_packet->tcp->ack) {
        if (opts.debug) printf("Handshake completed, waiting for data\n");

        context->server_sequence++;
        return (struct state_transition) {DATA_TRANSFER, NULL};
    }

    return (struct state_transition) {HANDSHAKE_INITIATED, NULL};
}

struct state_transition transition_from_data_transfer(struct packet* current_packet, struct client_context* context, struct options opts) {
    if (current_packet->tcp->fin) {
        if (opts.debug) printf("Closing connection\n");

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

    if (opts.debug) printf("Data received\n");
    unsigned char* syn_ack = init_syn_ack(current_packet, context, htonl(current_packet->payload_size + ntohl(current_packet->tcp->seq)), 0, 0);
    struct response* data = malloc(sizeof(struct response));
    data->data = syn_ack;
    data->next = NULL;
    return (struct state_transition) {DATA_TRANSFER, data};
}

void handle_transition(struct state_transition transition, struct client_context* context) {
    int size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    struct response* head = transition.response_head;
    while (head) {
            int result = sendto(context->connection, head->data, size, 0, (struct sockaddr*)&context->address, context->address_len);
            print_tcpdump_from_buffer(head->data, size, COLOR_CYAN);

            struct response* next = head->next;
            free(head);
            head = next;
        }
}

enum state handle_packet(enum state current_state, struct packet* current_packet, struct client_context* context, struct options opts) {
    struct state_transition transition;

    switch(current_state) {
        case LISTENING:
            transition = transition_from_listening(current_packet, context, opts);
            break;
        case HANDSHAKE_INITIATED:
            transition = transition_from_handshake_initiated(current_packet, context, opts);
            break;
        case DATA_TRANSFER:
            transition = transition_from_data_transfer(current_packet, context, opts);
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

        struct packet* current_packet = malloc(sizeof(struct packet));
        if (parse_packet(buffer, current_packet) == -1) {
            continue;
        }

        if (opts.debug) print_tcpdump_from_buffer(buffer, bytes_received, COLOR_GREEN);
        if (opts.verbose) print_raw_bits(buffer, bytes_received);
        if (opts.verbose) print_sections(buffer, bytes_received);

        current_state = handle_packet(current_state, current_packet, &context, opts);
    }

    shutdown(context.connection, SHUT_RDWR);
    close(context.connection);
    free(buffer);
    return 0;
}

