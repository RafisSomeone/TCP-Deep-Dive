#include <unistd.h>
#include <stdio.h>

#include "options.h"

void print_command(char short_flag[], char long_flag[], char description[]) {
    printf("     %s, %-16s %s\n",short_flag, long_flag, description);
}
void print_help() {
    printf("Usage: tcp_server [options...]\n\n");
    printf("A raw TCP server using packet inspection.\n\n");
    printf("Options:\n");
    print_command("-h", "--help", "Display this help text and exit");
    print_command("-v", "--verbose", "Each incoming packet is displayed in detail");
    print_command("-d", "--debug", "Each packet sent and received is shown in a tcpdump-like format");
    print_command("-s", "--signle-session", "Server exits after one session");
    printf("\nNote: Run with sudo, elevated permissions are required.\n");
}

struct options parse_options(int argc, char* argv[]) {
    struct options opts = {false, false, false, false};
    char shortopts[] = "hvds";
    int opt;

    while ((opt = getopt_long(argc, argv, shortopts, long_options, NULL)) != -1) {
        switch(opt) {
            case 'h':
                print_help();
                opts.help = true;
                break;
            case 'v':
                opts.verbose = true;
                break;
            case 'd':
                opts.debug = true;
                break;
            case 's':
                opts.single_session = true;
                break;
        }
    }
    
    return opts;
}

