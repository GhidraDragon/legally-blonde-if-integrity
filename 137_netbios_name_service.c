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

int send_weak_netbios_ns_data(const char *host, unsigned short port) {
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
    if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -3;
    }
    strcpy(buffer, "NETBIOS_NS_QUERY");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("Received NetBIOS response: %s\n", buffer);
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
    /* UDP check is limited, just a quick attempt */
    sendto(sock, "ping", 4, 0, (struct sockaddr*)&target, sizeof(target));
    close(sock);
    return 1;
}

char* capture_flag(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    char buffer[MAX_BUF];
    socklen_t len = sizeof(srv);
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
    char data[] = "Sensitive NetBIOS NS Data";
    printf("Sending NetBIOS NS data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = atoi(argv[2]);

    if(!detect_exploit(ip, port)) {
        printf("Port %d closed/unreachable or UDP check not conclusive on %s.\n", port, ip);
    } else {
        printf("Attempted UDP check on port %d for %s.\n", port, ip);
    }

    if(send_weak_netbios_ns_data(ip, port) == 0) {
        printf("Weak NetBIOS NS data sent.\n");
    } else {
        printf("Failed to send NetBIOS NS data.\n");
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }
    return 0;
}