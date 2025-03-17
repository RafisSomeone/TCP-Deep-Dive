#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>

#include "context.h"
#include "ip.h"

struct client_context init_context() {
    struct client_context context;
    context.connection = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    context.address_len = sizeof(struct sockaddr_ll);

    if (context.connection < 0) {
        fprintf(stderr, "Socket creation failed, run with sudo\n");
        exit(2);
    }
    
    srand(time(NULL));
    context.server_sequence = rand();

    return context;
}

void server_cleanup(struct client_context* context, unsigned char* buffer) {
    if (context && context->connection >= 0) {
        shutdown(context->connection, SHUT_RDWR);
        close(context->connection);
        context->connection = -1; 
    }

    if (buffer) {
        free(buffer);
        buffer = NULL;
    }
}

