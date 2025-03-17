#ifndef CONTEXT_H
#define CONTEXT_H

#include <netpacket/packet.h>
#include "packet.h"

struct client_context {
    struct sockaddr_ll address;
    socklen_t address_len;
    int connection;
    int server_sequence;
};

struct client_context init_context();
void cleanup(struct client_context* context, unsigned char* buffer);
void packet_cleanup(struct packet* current);

#endif
