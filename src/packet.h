#ifndef PACKET_H
#define PACKET_H

typedef struct {
   struct ethhdr* eth;
   struct iphdr* ip;
   struct tcphdr* tcp;
   int payload_size;
   unsigned char* payload;
} packet;

void print_raw_bits(unsigned char* buffer, int size);
void print_built_in(const packet* current_packet);
void print_range(unsigned char* buffer, int from, int to);
unsigned long range_hex_to_decimal(unsigned char* buffer, int from, int to);
unsigned short calculate_checksum(unsigned short *buf, int len);
void print_sections(unsigned char* buffer, int size);
int parse_packet(unsigned char* buffer, packet* current_packet);
unsigned char* init_syn_ack(const packet* current_packet, int seq, int ack, int syn_flag, int fin_flag);

#endif
