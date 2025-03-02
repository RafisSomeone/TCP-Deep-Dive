#ifndef TCP_H
#define TCP_H

#include <netinet/in.h>
#include <netinet/tcp.h>

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_length;
};

int parse_tcp_header(unsigned char* buffer, int from);
unsigned short tcp_checksum(const struct iphdr *ip, const struct tcphdr *tcp, const unsigned char *payload, int payload_len);

#endif
