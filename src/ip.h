#ifndef IP_H
#define IP_H

#include <netinet/in.h>
#include <netinet/ip.h>

static const int MAX_IP_V4_PACKET_SIZE = 65535; 

void print_ip(unsigned char* buffer, int from);
int parse_ip_header(unsigned char* buffer, int from);

#endif
