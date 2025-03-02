#include <stdio.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "ethernet.h"

void print_mac(unsigned char* buffer, int from, int to) {
    for (int i = from; i < to - 1; i++) {
        printf("%02X:", buffer[i]);
    }
    printf("%02X\n", buffer[to - 1]);
}

void parse_ethernet_header(unsigned char* buffer, int from, int to) {
    int destiantion_mac_size = 6;
    int source_mac_size = 6;
    int ethertype_size = 2;

    int source_mac_start = destiantion_mac_size + from;
    int ethertype_start = source_mac_start + source_mac_size;

    printf("\n");
    printf("Destination MAC: ");
    print_mac(buffer, from , source_mac_start);

    printf("Source MAC: "); 
    print_mac(buffer, source_mac_start, ethertype_start);
    
    printf("Ether Type: "); 
    print_range(buffer, ethertype_start, to);
}

