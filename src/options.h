#ifndef OPTIONS_H
#define OPTIONS_H

#include <getopt.h>
#include <stdbool.h>

struct options {
  bool verbose;
  bool help;
  bool debug;
  bool single_session;
};

static struct option long_options[] = {{"verbose", no_argument, 0, 'v'},
                                       {"help", no_argument, 0, 'h'},
                                       {"debug", no_argument, 0, 'd'},
                                       {"single-session", no_argument, 0, 's'},
                                       {0, 0, 0, 0}};

struct options parse_options(int argc, char *argv[]);

#endif
