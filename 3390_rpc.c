#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>

#define MAX_BUF 1024
#define MSG_RPC "RPC_HELLO"
#define MSG_FLAG "GET_FLAG"

/*
 * For educational and authorized testing only.
 */

static int set_socket_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

static int connect_with_timeout(int sock, struct sockaddr_in *addr, int sec) {
    fd_set writefds;
    struct timeval tv;
    int rc, so_error;
    socklen_t len = sizeof(so_error);
    set_socket_nonblocking(sock);
    rc = connect(sock, (struct sockaddr*)addr, sizeof(*addr));
    if (rc < 0 && errno != EINPROGRESS) return -1;
    if (rc == 0) return 0;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    rc = select(sock + 1, NULL, &writefds, NULL, &tv);
    if (rc <= 0) return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) return -1;
    if (so_error != 0) return -1;
    return 0;
}

int send_weak_rpc_data(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return -2;
    }
    if (connect_with_timeout(sock, &server, 3) < 0) {
        close(sock);
        return -3;
    }
    memset(buffer, 0, sizeof(buffer));
    strncpy(buffer, MSG_RPC, sizeof(buffer) - 1);
    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        close(sock);
        return -4;
    }
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Received RPC response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

int detect_exploit(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in target;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    if (connect_with_timeout(sock, &target, 3) < 0) {
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
    if (sock < 0) return NULL;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    if (connect_with_timeout(sock, &srv, 3) < 0) {
        close(sock);
        return NULL;
    }
    if (send(sock, MSG_FLAG, strlen(MSG_FLAG), 0) < 0) {
        close(sock);
        return NULL;
    }
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        memset(flag, 0, sizeof(flag));
        strncpy(flag, buffer, MAX_BUF - 1);
    }
    close(sock);
    return flag;
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive RPC Data";
    printf("Sending RPC data in a weakly protected way: %s\n", data);

    if (argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);

    if (!detect_exploit(ip, port)) {
        printf("Port %d closed or unreachable on %s.\n", port, ip);
        return 0;
    }
    printf("Port %d open on %s.\n", port, ip);

    if (send_weak_rpc_data(ip, port) == 0) {
        printf("Weak RPC data sent successfully.\n");
    } else {
        printf("Failed to send weak RPC data.\n");
    }

    char *found_flag = capture_flag(ip, port);
    if (found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }
    return 0;
}