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
#include "state.h"
#include "utils.h"

int main(int argc, char** argv) {

    struct options opts = parse_options(argc, argv);
    
    if (opts.help == 1) {
        return 0;
    }

    struct client_context context;
    unsigned char* buffer = safe_malloc(MAX_IP_V4_PACKET_SIZE);
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

        struct packet* current_packet = safe_malloc(sizeof(struct packet));
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

