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

int send_weak_pop3s_data(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return -1;

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return -2;
    }
    if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -3;
    }
    strcpy(buffer, "STLS POP3");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("POP3S response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

int detect_exploit(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in target;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    if(connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

char* capture_flag(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    char buffer[MAX_BUF];
    int n;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return NULL;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    if(connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
        close(sock);
        return NULL;
    }
    send(sock, "GET_FLAG", 8, 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        strncpy(flag, buffer, MAX_BUF-1);
    }
    close(sock);
    return flag;
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive POP3S Data";
    printf("Sending POP3S data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = atoi(argv[2]);

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
    return 0;
}