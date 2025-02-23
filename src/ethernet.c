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

void print_eth_built_in(const struct ethhdr* eth) {
    printf("Ethernet Header:\n");
    printf("   Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("   Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   Protocol: 0x%04X\n", ntohs(eth->h_proto));
}

