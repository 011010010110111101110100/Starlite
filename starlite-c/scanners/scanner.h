#ifndef SCANNER_H
#define SCANNER_H

int is_host_up(const char *ip);
int try_connect(const char *ip, int port, int timeout);
int scan_ip_multithreaded(const char *ip);
int is_host_up_tcp_fullscan(const char *ip);
int is_host_up_icmp(const char *ip);
void read_ips_from_file(const char *filename);
void scan_ip(const char *ip);
int scan_ips_from_file(const char *filename);

#endif
