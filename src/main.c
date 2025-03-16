#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <time.h>

#include "packet.h"
#include "tcp.h"
#include "ip.h"
#include "options.h"
#include "context.h"
#include "state.h"
#include "utils.h"

int main(int argc, char** argv) {
   struct options opts = parse_options(argc, argv);
    
    if (opts.help) {
        return 0;
    }

    struct client_context context = init_context();
    unsigned char* buffer = safe_malloc(MAX_IP_V4_PACKET_SIZE);

    enum state current_state = LISTENING;

    while (1) {
        int bytes_received = recvfrom(context.connection, buffer, MAX_IP_V4_PACKET_SIZE, 0, 
                                      (struct sockaddr*) &context.address, &context.address_len);
        if (bytes_received < 0) {
            fprintf(stderr, "recvfrom failed\n");
            cleanup(&context, buffer);
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

    cleanup(&context, buffer);
    return 0;
}

