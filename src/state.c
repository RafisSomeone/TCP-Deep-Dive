#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include "packet.h"
#include "context.h"
#include "options.h"
#include "state.h"

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

