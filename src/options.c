#include <unistd.h>
#include <stdio.h>

#include "options.h"

void print_command(char short_flag[], char long_flag[], char description[]) {
    printf("     %s, %-16s %s\n",short_flag, long_flag, description);
}
void print_help() {
    printf("Usage: tcp_server [options...]\n\n");
    printf("Options:\n");
    print_command("-v", "--verbose", "Make the operation more talkative");
    printf("\nNote: Run with sudo, elevated permissions are required.\n");
}

struct options parse_options(int argc, char* argv[]) {
    struct options opts = {false, false, false};
    char shortopts[] = "hvd";
    int opt;

    while ((opt = getopt_long(argc, argv, shortopts, long_options, NULL)) != -1) {
        switch(opt) {
            case 'h':
                print_help();
                opts.help = true;
            case 'v':
                opts.verbose = true;
            case 'd':
                opts.debug = true;
        }
    }
    
    return opts;
}

