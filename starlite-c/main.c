#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "scanners/scanner.h"
#define OUT_FILE "ips.txt"

int main() {
    while (1) {
        printf("[starlite] Starting scan cycle...\n");
        scan_ips_from_file(OUT_FILE);
        printf("[starlite] Scan cycle finished. Sleeping for 1 second...\n");
        sleep(0.01);
    }
    scan_ips_from_file(OUT_FILE);
    return 0;
}