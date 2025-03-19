#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_BUF 1024

static SSL_CTX *ctx = NULL;

int initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) return 0;
    return 1;
}

void cleanup_openssl() {
    if(ctx) SSL_CTX_free(ctx);
    EVP_cleanup();
}

int secure_send_rdp_data(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;
    SSL *ssl = NULL;
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
    ssl = SSL_new(ctx);
    if(!ssl) {
        close(sock);
        return -4;
    }
    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        return -5;
    }
    strcpy(buffer, "RDP_SECURE_HELLO");
    SSL_write(ssl, buffer, strlen(buffer));
    memset(buffer, 0, sizeof(buffer));
    n = SSL_read(ssl, buffer, sizeof(buffer)-1);
    if(n > 0) {
        buffer[n] = '\0';
        printf("Received secure response: %s\n", buffer);
    }
    SSL_free(ssl);
    close(sock);
    return 0;
}

int send_weak_rdp_data(const char *host, unsigned short port) {
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
    strcpy(buffer, "RDP_HELLO");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("Received response: %s\n", buffer);
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
    char data[] = "Sensitive RDP Data";
    printf("Sending RDP data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP> <PORT> [secure]\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);
    int use_secure = 0;
    if(argc == 4 && strcmp(argv[3], "secure") == 0) use_secure = 1;

    if(!detect_exploit(ip, port)) {
        printf("Port %d closed or unreachable on %s.\n", port, ip);
        return 0;
    }
    printf("Port %d open on %s.\n", port, ip);

    if(use_secure) {
        if(!initialize_openssl()) {
            printf("Failed to initialize OpenSSL.\n");
            return 1;
        }
        if(secure_send_rdp_data(ip, port) == 0) {
            printf("Secure RDP data sent successfully.\n");
        } else {
            printf("Failed to send secure RDP data.\n");
        }
        cleanup_openssl();
    } else {
        if(send_weak_rdp_data(ip, port) == 0) {
            printf("Weak RDP data sent successfully.\n");
        } else {
            printf("Failed to send weak RDP data.\n");
        }
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
    }
    return 0;
}