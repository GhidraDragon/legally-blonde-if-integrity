#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_BUF 1024

/*
 * For educational and authorized testing only.
 */

static int create_and_connect_socket(const char *host, unsigned short port) {
    int s;
    struct sockaddr_in addr;
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(s);
        return -2;
    }
    if(connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        return -3;
    }
    return s;
}

static int send_all(int s, const char *buf, size_t len) {
    size_t total_sent = 0;
    while(total_sent < len) {
        ssize_t sent = send(s, buf + total_sent, len - total_sent, 0);
        if(sent <= 0) return -1;
        total_sent += sent;
    }
    return 0;
}

int send_weak_imaps_data(const char *host, unsigned short port) {
    int sock;
    char buffer[MAX_BUF];
    int n;
    sock = create_and_connect_socket(host, port);
    if(sock < 0) return -1;
    strcpy(buffer, "STARTTLS IMAP");
    if(send_all(sock, buffer, strlen(buffer)) < 0) {
        close(sock);
        return -2;
    }
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("IMAPS response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

int detect_exploit(const char *host, unsigned short port) {
    int sock = create_and_connect_socket(host, port);
    if(sock < 0) return 0;
    close(sock);
    return 1;
}

char* capture_flag(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    char buffer[MAX_BUF];
    int n;
    memset(flag, 0, sizeof(flag));
    sock = create_and_connect_socket(host, port);
    if(sock < 0) return NULL;
    if(send_all(sock, "GET_FLAG", 8) < 0) {
        close(sock);
        return NULL;
    }
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        strncpy(flag, buffer, MAX_BUF - 1);
    }
    close(sock);
    return flag;
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive IMAPS Data";
    printf("Sending IMAPS data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);

    if(!detect_exploit(ip, port)) {
        printf("Port %d closed or unreachable on %s.\n", port, ip);
        return 0;
    }
    printf("Port %d open on %s.\n", port, ip);

    if(send_weak_imaps_data(ip, port) == 0) {
        printf("Weak IMAPS data sent.\n");
    } else {
        printf("Failed to send IMAPS data.\n");
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }
    return 0;
}