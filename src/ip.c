#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "packet.h"

void print_bits(unsigned char *buffer, int from, int to) {
  for (int i = from; i < to; i++) {
    for (int j = 7; j >= 0; j--) {
      printf("%d", (buffer[i] >> j) & 1);
    }
    printf(" ");
  }
  printf("\n");
}

void print_ip(unsigned char *buffer, int from) {
  printf("%d.%d.%d.%d\n", buffer[from], buffer[from + 1], buffer[from + 2],
         buffer[from + 3]);
}

int parse_ip_header(unsigned char *buffer, int from) {
  int version_ihl_size = 1;
  int ecn_size = 1;
  int total_length_size = 2;
  int identification_size = 2;
  int flags_fragment_offset_size = 2;
  int ttl_size = 1;
  int protocol_size = 1;
  int checksum_size = 2;
  int source_ip_size = 4;
  int destination_ip_size = 4;
  int ihl_word_size = 4;

  int version_ihl = buffer[from];
  int version = (version_ihl >> 4);
  int ihl = (version_ihl & 0x0F) * ihl_word_size;

  int ecn_start = from + version_ihl_size;
  int total_length_start = ecn_start + ecn_size;
  int identification_start = total_length_start + total_length_size;
  int flags_fragment_offset_start = identification_start + identification_size;
  int ttl_start = flags_fragment_offset_start + flags_fragment_offset_size;
  int protocol_start = ttl_start + ttl_size;
  int checksum_start = protocol_start + protocol_size;
  int source_ip_start = checksum_start + checksum_size;
  int destination_ip_start = source_ip_start + source_ip_size;
  int options_start = destination_ip_start + destination_ip_size;

  printf("\n");
  printf("Version: %d\n", version);
  printf("Header Length: %d bytes\n", ihl);

  printf("ECN & DSCP: ");
  print_range(buffer, ecn_start, total_length_start);

  unsigned long total_length =
      range_hex_to_decimal(buffer, total_length_start, identification_start);
  printf("Total Length: %ld bytes\n", total_length);

  printf("Identification: ");
  print_range(buffer, identification_start, flags_fragment_offset_start);

  printf("Flags & Fragment Offset: ");
  print_bits(buffer, flags_fragment_offset_start, ttl_start);

  unsigned long ttl = range_hex_to_decimal(buffer, ttl_start, protocol_start);
  printf("Time to Live: %ld\n", ttl);

  unsigned long protocol =
      range_hex_to_decimal(buffer, protocol_start, checksum_start);
  printf("Protocol: %ld \n", protocol);

  printf("Header Checksum: ");
  print_range(buffer, checksum_start, source_ip_start);

  printf("Source IP: ");
  print_ip(buffer, source_ip_start);

  printf("Destination IP: ");
  print_ip(buffer, destination_ip_start);

  printf("Options IP: ");
  if (from + ihl - options_start <= 0) {
    printf("Empty");
  }
  print_range(buffer, options_start, from + ihl);

  return ihl;
}
