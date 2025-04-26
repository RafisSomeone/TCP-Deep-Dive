#ifndef PACKET_H
#define PACKET_H

#include "context.h"

#define COLOR_CYAN "\x1b[36m"
#define COLOR_GREEN "\x1b[32m"

struct packet {
  struct ethhdr *eth;
  struct iphdr *ip;
  struct tcphdr *tcp;
  int payload_size;
  unsigned char *payload;
};

void print_raw_bits(unsigned char *buffer, int size);
void print_range(unsigned char *buffer, int from, int to);
unsigned long range_hex_to_decimal(unsigned char *buffer, int from, int to);
unsigned short calculate_checksum(unsigned short *buf, int len);
void print_sections(unsigned char *buffer, int size);
int parse_packet(unsigned char *buffer, struct packet *current_packet);
unsigned char *init_syn_ack(const struct packet *current_packet,
                            struct client_context *context, int ack,
                            int syn_flag, int fin_flag);
void packet_cleanup(struct packet *current);

#endif
