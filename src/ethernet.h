#ifndef ETHERNET_H
#define ETHERNET_H

#include <linux/if_ether.h>

void parse_ethernet_header(unsigned char* buffer, int from, int to);
void print_eth_built_in(const struct ethhdr* eth);

#endif
