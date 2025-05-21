#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#define TMP_FILE "urlhaus.txt"
#define OUT_FILE "ips.txt"
#define MAX_LINE 1024
#define MAX_IPS 10000

int extract_ip(const char *line, char *ip_out) {
    regex_t regex;
    regmatch_t matches[1];
    const char *pattern = "([0-9]{1,3}\\.){3}[0-9]{1,3}";
    int ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) return 0;

    ret = regexec(&regex, line, 1, matches, 0);
    if (!ret) {
        int start = matches[0].rm_so;
        int end = matches[0].rm_eo;
        snprintf(ip_out, end - start + 1, "%s", line + start);
        regfree(&regex);
        return 1;
    }

    regfree(&regex);
    return 0;
}

int compare_ips(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int fetch_and_extract_ips(char *output_file) {
    system("wget -q -O " TMP_FILE " https://urlhaus.abuse.ch/downloads/text/");

    FILE *file = fopen(TMP_FILE, "r");
    if (!file) {
        perror("Failed to open downloaded file");
        return 0;
    }

    char *ips[MAX_IPS];
    int ip_count = 0;
    char line[MAX_LINE], ip[64];

    while (fgets(line, sizeof(line), file)) {
        if (extract_ip(line, ip)) {
            if (ip_count < MAX_IPS) {
                ips[ip_count] = strdup(ip);
                ip_count++;
            }
        }
    }
    fclose(file);
    remove(TMP_FILE);

    qsort(ips, ip_count, sizeof(char *), compare_ips);

    FILE *out = fopen(output_file, "w");
    if (!out) {
        perror("Failed to open output file");
        return 0;
    }

    int unique_count = 0;
    for (int i = 0; i < ip_count; i++) {
        if (i == 0 || strcmp(ips[i], ips[i - 1]) != 0) {
            fprintf(out, "%s\n", ips[i]);
            unique_count++;
        }
        free(ips[i]);
    }
    fclose(out);

    printf("[+] Extracted %d unique IPs to %s\n", unique_count, output_file);
    return unique_count;
}