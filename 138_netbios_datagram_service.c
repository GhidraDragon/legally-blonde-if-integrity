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

int send_weak_netbios_dgm_data(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return -1;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return -2;
    }
    strcpy(buffer, "NETBIOS_DGM_QUERY");
    sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("Received NetBIOS DGM response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

int detect_exploit(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in target;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return 0;
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    sendto(sock, "ping", 4, 0, (struct sockaddr*)&target, sizeof(target));
    close(sock);
    return 1;
}

char* capture_flag(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    socklen_t len = sizeof(srv);
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return NULL;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    sendto(sock, "GET_FLAG", 8, 0, (struct sockaddr*)&srv, sizeof(srv));
    memset(buffer, 0, sizeof(buffer));
    n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&srv, &len);
    if(n > 0) {
        buffer[n] = '\0';
        strncpy(flag, buffer, MAX_BUF-1);
    }
    close(sock);
    return flag;
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive NetBIOS DGM Data";
    printf("Sending NetBIOS DGM data in a weak way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = atoi(argv[2]);

    printf("UDP checks for port %d on %s.\n", port, ip);

    if(send_weak_netbios_dgm_data(ip, port) == 0) {
        printf("Weak NetBIOS DGM data sent.\n");
    } else {
        printf("Failed to send NetBIOS DGM data.\n");
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }
    return 0;
}