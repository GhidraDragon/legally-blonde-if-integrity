/* Usage: For educational and authorized testing only. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/select.h>

#define MAX_BUF 1024

static int create_connection(const char *host, unsigned short port) {
    struct addrinfo hints, *res, *p;
    char port_str[6];
    int sock = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", port);
    if(getaddrinfo(host, port_str, &hints, &res) != 0) return -1;
    for(p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(sock < 0) continue;
        struct timeval tv;
        tv.tv_sec = 5; tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if(connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            freeaddrinfo(res);
            return sock;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static int send_all(int sock, const char *buf, int len) {
    int total = 0;
    int sent;
    while(total < len) {
        sent = send(sock, buf + total, len - total, 0);
        if(sent < 0) return -1;
        total += sent;
    }
    return total;
}

int send_weak_pop3s_data(const char *host, unsigned short port) {
    int sock = create_connection(host, port);
    if(sock < 0) return -1;
    char buffer[MAX_BUF];
    strcpy(buffer, "STLS POP3");
    if(send_all(sock, buffer, strlen(buffer)) < 0) {
        close(sock);
        return -2;
    }
    memset(buffer, 0, sizeof(buffer));
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("POP3S response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

int detect_exploit(const char *host, unsigned short port) {
    int sock = create_connection(host, port);
    if(sock < 0) return 0;
    close(sock);
    return 1;
}

char* capture_flag(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock = create_connection(host, port);
    if(sock < 0) return NULL;
    if(send_all(sock, "GET_FLAG", 8) < 0) {
        close(sock);
        return NULL;
    }
    char buffer[MAX_BUF];
    memset(buffer, 0, sizeof(buffer));
    int n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        strncpy(flag, buffer, MAX_BUF - 1);
    } else {
        close(sock);
        return NULL;
    }
    close(sock);
    return flag;
}

static void persistent_portal(const char *host, unsigned short port) {
    char sendbuf[MAX_BUF], recvbuf[MAX_BUF];
    int sock = create_connection(host, port);
    if(sock < 0) {
        printf("Persistent portal failed to connect.\n");
        return;
    }
    printf("Persistent portal connected. Type 'exit' to quit.\n");
    while(1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock, &fds);
        int maxfd = (sock > STDIN_FILENO ? sock : STDIN_FILENO) + 1;
        if(select(maxfd, &fds, NULL, NULL, NULL) < 0) break;
        if(FD_ISSET(STDIN_FILENO, &fds)) {
            memset(sendbuf, 0, sizeof(sendbuf));
            if(!fgets(sendbuf, sizeof(sendbuf), stdin)) break;
            if(strncmp(sendbuf, "exit", 4) == 0) break;
            if(send_all(sock, sendbuf, strlen(sendbuf)) < 0) break;
        }
        if(FD_ISSET(sock, &fds)) {
            memset(recvbuf, 0, sizeof(recvbuf));
            int n = recv(sock, recvbuf, sizeof(recvbuf) - 1, 0);
            if(n <= 0) {
                printf("Server closed connection.\n");
                break;
            }
            recvbuf[n] = '\0';
            printf("%s", recvbuf);
        }
    }
    close(sock);
    printf("Persistent portal closed.\n");
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive POP3S Data";
    printf("Sending POP3S data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT> [persistent]\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);

    if(!detect_exploit(ip, port)) {
        printf("Port %d closed or unreachable on %s.\n", port, ip);
        return 0;
    }
    printf("Port %d open on %s.\n", port, ip);

    if(send_weak_pop3s_data(ip, port) == 0) {
        printf("Weak POP3S data sent.\n");
    } else {
        printf("Failed to send POP3S data.\n");
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }

    if(argc >= 4 && strcmp(argv[3], "persistent") == 0) {
        persistent_portal(ip, port);
    }
    return 0;
}