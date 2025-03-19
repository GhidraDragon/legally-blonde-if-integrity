#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_BUF 1024

int detect_exploit_v4(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in target;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return 0;
    memset(&target, 0, sizeof(target));
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

int detect_exploit_v6(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in6 target;
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if(sock < 0) return 0;
    memset(&target, 0, sizeof(target));
    target.sin6_family = AF_INET6;
    target.sin6_port = htons(port);
    if(inet_pton(AF_INET6, host, &target.sin6_addr) <= 0) {
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

int detect_exploit_any(const char *host, unsigned short port) {
    if(detect_exploit_v4(host, port)) return 4;
    if(detect_exploit_v6(host, port)) return 6;
    return 0;
}

int send_weak_https_alt_data_v4(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return -1;
    memset(&server, 0, sizeof(server));
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
    strcpy(buffer, "GET / HTTP/1.0\r\n\r\n");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("HTTPS alt response (v4): %s\n", buffer);
    }
    close(sock);
    return 0;
}

int send_weak_https_alt_data_v6(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in6 server;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if(sock < 0) return -1;
    memset(&server, 0, sizeof(server));
    server.sin6_family = AF_INET6;
    server.sin6_port = htons(port);
    if(inet_pton(AF_INET6, host, &server.sin6_addr) <= 0) {
        close(sock);
        return -2;
    }
    if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        close(sock);
        return -3;
    }
    strcpy(buffer, "GET / HTTP/1.0\r\n\r\n");
    send(sock, buffer, strlen(buffer), 0);
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("HTTPS alt response (v6): %s\n", buffer);
    }
    close(sock);
    return 0;
}

int send_weak_https_alt_data(const char *host, unsigned short port, int ipver) {
    if(ipver == 4) return send_weak_https_alt_data_v4(host, port);
    else if(ipver == 6) return send_weak_https_alt_data_v6(host, port);
    return -1;
}

char* capture_flag_v4(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return NULL;
    memset(&srv, 0, sizeof(srv));
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
        strncpy(flag, buffer, MAX_BUF - 1);
    }
    close(sock);
    return flag;
}

char* capture_flag_v6(const char *host, unsigned short port) {
    static char flag[MAX_BUF];
    int sock;
    struct sockaddr_in6 srv;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET6, SOCK_STREAM, 0);
    if(sock < 0) return NULL;
    memset(&srv, 0, sizeof(srv));
    srv.sin6_family = AF_INET6;
    srv.sin6_port = htons(port);
    if(inet_pton(AF_INET6, host, &srv.sin6_addr) <= 0) {
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
        strncpy(flag, buffer, MAX_BUF - 1);
    }
    close(sock);
    return flag;
}

char* capture_flag(const char *host, unsigned short port, int ipver) {
    if(ipver == 4) return capture_flag_v4(host, port);
    if(ipver == 6) return capture_flag_v6(host, port);
    return NULL;
}

/* Additional enhancements below */
void retrieve_banner(const char *host, unsigned short port, int ipver) {
    int sock;
    char buf[MAX_BUF];
    int r;
    if(ipver == 4) {
        struct sockaddr_in addr;
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) return;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            close(sock);
            return;
        }
        if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            strcpy(buf, "HEAD / HTTP/1.0\r\n\r\n");
            send(sock, buf, strlen(buf), 0);
            memset(buf, 0, sizeof(buf));
            r = recv(sock, buf, MAX_BUF-1, 0);
            if(r > 0) {
                buf[r] = '\0';
                printf("Banner (v4): %s\n", buf);
            }
        }
        close(sock);
    } else {
        struct sockaddr_in6 addr6;
        sock = socket(AF_INET6, SOCK_STREAM, 0);
        if(sock < 0) return;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if(inet_pton(AF_INET6, host, &addr6.sin6_addr) <= 0) {
            close(sock);
            return;
        }
        if(connect(sock, (struct sockaddr*)&addr6, sizeof(addr6)) == 0) {
            strcpy(buf, "HEAD / HTTP/1.0\r\n\r\n");
            send(sock, buf, strlen(buf), 0);
            memset(buf, 0, sizeof(buf));
            r = recv(sock, buf, MAX_BUF-1, 0);
            if(r > 0) {
                buf[r] = '\0';
                printf("Banner (v6): %s\n", buf);
            }
        }
        close(sock);
    }
}

void send_lethal_payload(const char *host, unsigned short port, int ipver) {
    int sock;
    char buf[MAX_BUF];
    if(ipver == 4) {
        struct sockaddr_in addr;
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) return;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            close(sock);
            return;
        }
        if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            strcpy(buf, "LETHAL_PAYLOAD_V4");
            send(sock, buf, strlen(buf), 0);
            memset(buf, 0, sizeof(buf));
            if(recv(sock, buf, MAX_BUF-1, 0) > 0) {
                printf("Lethal payload response (v4): %s\n", buf);
            }
        }
        close(sock);
    } else {
        struct sockaddr_in6 addr6;
        sock = socket(AF_INET6, SOCK_STREAM, 0);
        if(sock < 0) return;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(port);
        if(inet_pton(AF_INET6, host, &addr6.sin6_addr) <= 0) {
            close(sock);
            return;
        }
        if(connect(sock, (struct sockaddr*)&addr6, sizeof(addr6)) == 0) {
            strcpy(buf, "LETHAL_PAYLOAD_V6");
            send(sock, buf, strlen(buf), 0);
            memset(buf, 0, sizeof(buf));
            if(recv(sock, buf, MAX_BUF-1, 0) > 0) {
                printf("Lethal payload response (v6): %s\n", buf);
            }
        }
        close(sock);
    }
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive HTTPS Alt Data";
    printf("Sending HTTPS alt data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("Usage: %s <IP/hostname> <PORT>\n", argv[0]);
        return 1;
    }

    const char *host = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);

    printf("Enhanced scanning enabled.\n");

    int ip_version = detect_exploit_any(host, port);
    if(!ip_version) {
        printf("Port %d closed or unreachable on %s.\n", port, host);
        return 0;
    }
    printf("Port %d open on %s (IPv%d).\n", port, host, ip_version);

    if(send_weak_https_alt_data(host, port, ip_version) == 0)
        printf("Weak HTTPS alt data sent.\n");
    else
        printf("Failed to send HTTPS alt data.\n");

    char *found_flag = capture_flag(host, port, ip_version);
    if(found_flag && strlen(found_flag) > 0)
        printf("Captured flag: %s\n", found_flag);
    else
        printf("No flag captured.\n");

    printf("Retrieving server banner:\n");
    retrieve_banner(host, port, ip_version);

    printf("Attempting lethal payload:\n");
    send_lethal_payload(host, port, ip_version);

    printf("Attempting additional communication:\n");
    if(ip_version == 4) {
        int sock_extra = socket(AF_INET, SOCK_STREAM, 0);
        if(sock_extra >= 0) {
            struct sockaddr_in extra;
            memset(&extra, 0, sizeof(extra));
            extra.sin_family = AF_INET;
            extra.sin_port = htons(port);
            if(inet_pton(AF_INET, host, &extra.sin_addr) > 0) {
                if(connect(sock_extra, (struct sockaddr*)&extra, sizeof(extra)) == 0) {
                    char buf[MAX_BUF];
                    strcpy(buf, "POST /exfil HTTP/1.1\r\nHost: v4\r\n\r\nExtraData");
                    send(sock_extra, buf, strlen(buf), 0);
                    memset(buf, 0, sizeof(buf));
                    int r = recv(sock_extra, buf, MAX_BUF-1, 0);
                    if(r > 0) {
                        buf[r] = '\0';
                        printf("Extra response (v4): %s\n", buf);
                    }
                }
            }
            close(sock_extra);
        }
    } else {
        int sock_extra = socket(AF_INET6, SOCK_STREAM, 0);
        if(sock_extra >= 0) {
            struct sockaddr_in6 extra6;
            memset(&extra6, 0, sizeof(extra6));
            extra6.sin6_family = AF_INET6;
            extra6.sin6_port = htons(port);
            if(inet_pton(AF_INET6, host, &extra6.sin6_addr) > 0) {
                if(connect(sock_extra, (struct sockaddr*)&extra6, sizeof(extra6)) == 0) {
                    char buf[MAX_BUF];
                    strcpy(buf, "POST /exfil HTTP/1.1\r\nHost: v6\r\n\r\nExtraData");
                    send(sock_extra, buf, strlen(buf), 0);
                    memset(buf, 0, sizeof(buf));
                    int r = recv(sock_extra, buf, MAX_BUF-1, 0);
                    if(r > 0) {
                        buf[r] = '\0';
                        printf("Extra response (v6): %s\n", buf);
                    }
                }
            }
            close(sock_extra);
        }
    }

    return 0;
}