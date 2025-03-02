#ifndef OPTIONS_H 
#define OPTIONS_H

#include <stdbool.h>
#include <getopt.h>

struct options {
   bool verbose;
   bool help;
   bool debug;
};

static struct option long_options[] = {
   {"verbose", no_argument, 0, 'v'},
   {"help", no_argument, 0, 'h'},
   {"debug", no_argument, 0, 'd'},
   {0, 0, 0, 0}
};

struct options parse_options(int argc, char* argv[]);

#endif
