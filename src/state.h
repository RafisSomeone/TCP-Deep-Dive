#ifndef STATE_H
#define STATE_H

#include "context.h"
#include "options.h"
#include "packet.h"

enum state {
  LISTENING,
  HANDSHAKE_INITIATED,
  DATA_TRANSFER,
  CLOSING_CONNECTION
};

struct response {
  unsigned char *data;
  struct response *next;
};

struct state_transition {
  enum state next_state;
  struct response *response_head;
};

enum state handle_packet(enum state current_state,
                         struct packet *current_packet,
                         struct client_context *context, struct options opts);

#endif
