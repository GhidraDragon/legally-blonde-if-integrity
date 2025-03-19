#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>

#define MAX_BUF 1024

int send_weak_nfs_data(const char *host, unsigned short port) {
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
    strcpy(buffer, "NFS_NULLPROC");
    sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer)-1, 0);
    if(n > 0) {
        buffer[n] = '\0';
        printf("./enhanced_nfs_tool %s %d: NFS response: %s\n", host, port, buffer);
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

int advanced_udp_scan(const char* ip, unsigned short start_port, unsigned short end_port) {
    int open_ports = 0;
    for(unsigned short p = start_port; p <= end_port; p++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if(sock < 0) continue;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(p);
        if(inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
            close(sock);
            continue;
        }
        sendto(sock, "scan", 4, 0, (struct sockaddr*)&addr, sizeof(addr));
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        char buf[16];
        if(recv(sock, buf, sizeof(buf), 0) > 0) {
            printf("./enhanced_nfs_tool %s scanning: Port %d responds.\n", ip, p);
            open_ports++;
        }
        close(sock);
    }
    return open_ports;
}

int advanced_tcp_scan(const char* ip, unsigned short start_port, unsigned short end_port) {
    int open_ports = 0;
    for(unsigned short p = start_port; p <= end_port; p++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) continue;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(p);
        if(inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
            close(sock);
            continue;
        }
        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        if(select(sock+1, NULL, &fdset, NULL, &tv) > 0) {
            int val; socklen_t lon = sizeof(val);
            if(getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&val), &lon) == 0 && val == 0) {
                printf("./enhanced_nfs_tool %s scanning: TCP Port %d open.\n", ip, p);
                open_ports++;
            }
        }
        close(sock);
    }
    return open_ports;
}

int attempt_remote_code_execution(const char *host, unsigned short port) {
    int sock;
    struct sockaddr_in server;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return 0;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    sendto(sock, "RCE_ATTEMPT", 11, 0, (struct sockaddr*)&server, sizeof(server));
    close(sock);
    return 1;
}

char* retrieve_system_info(const char* host, unsigned short port) {
    static char sys_info[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    socklen_t len = sizeof(srv);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return NULL;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    sendto(sock, "SYSINFO", 7, 0, (struct sockaddr*)&srv, sizeof(srv));
    memset(sys_info, 0, sizeof(sys_info));
    if(recvfrom(sock, sys_info, sizeof(sys_info)-1, 0, (struct sockaddr*)&srv, &len) > 0) {
        close(sock);
        return sys_info;
    }
    close(sock);
    return NULL;
}

char* dump_nfs_shares(const char* host, unsigned short port) {
    static char shares[MAX_BUF];
    int sock;
    struct sockaddr_in srv;
    socklen_t len = sizeof(srv);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return NULL;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    sendto(sock, "DUMP_SHARES", 11, 0, (struct sockaddr*)&srv, sizeof(srv));
    memset(shares, 0, sizeof(shares));
    if(recvfrom(sock, shares, sizeof(shares)-1, 0, (struct sockaddr*)&srv, &len) > 0) {
        close(sock);
        return shares;
    }
    close(sock);
    return NULL;
}

char* multi_capture_flags(const char* host, unsigned short port) {
    static char all_flags[MAX_BUF * 4];
    memset(all_flags, 0, sizeof(all_flags));
    const char* commands[] = {"GET_FLAG", "GET_SECRET_FLAG", "GET_HIDDEN_FLAG", "GET_TOKEN"};
    int sock;
    struct sockaddr_in srv;
    socklen_t len = sizeof(srv);
    char buffer[MAX_BUF];
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) return NULL;
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    for(int i=0; i<4; i++) {
        sendto(sock, commands[i], strlen(commands[i]), 0, (struct sockaddr*)&srv, sizeof(srv));
        memset(buffer, 0, sizeof(buffer));
        if(recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&srv, &len) > 0) {
            strcat(all_flags, commands[i]);
            strcat(all_flags, ": ");
            strcat(all_flags, buffer);
            strcat(all_flags, "\n");
        }
    }
    close(sock);
    return all_flags;
}

int main(int argc, char *argv[]) {
    char data[] = "Sensitive NFS Data";
    printf("./enhanced_nfs_tool: Sending NFS data in a weakly protected way: %s\n", data);

    if(argc < 3) {
        printf("./enhanced_nfs_tool [USAGE]: %s <IP> <PORT> [scan <START_PORT> <END_PORT>] [tcp_scan <START_PORT> <END_PORT>] [rce] [sysinfo] [dump_shares] [allflags]\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);
    printf("./enhanced_nfs_tool %s %d: Starting main.\n", ip, port);

    printf("./enhanced_nfs_tool %s %d: UDP check for NFS port.\n", ip, port);
    if(send_weak_nfs_data(ip, port) == 0) {
        printf("./enhanced_nfs_tool %s %d: Weak NFS data sent.\n", ip, port);
    } else {
        printf("./enhanced_nfs_tool %s %d: Failed to send NFS data.\n", ip, port);
    }

    if(detect_exploit(ip, port)) {
        printf("./enhanced_nfs_tool %s %d: Exploit detection attempt complete.\n", ip, port);
    } else {
        printf("./enhanced_nfs_tool %s %d: Could not attempt exploit detection.\n", ip, port);
    }

    char *found_flag = capture_flag(ip, port);
    if(found_flag && strlen(found_flag) > 0) {
        printf("./enhanced_nfs_tool %s %d: Captured flag: %s\n", ip, port, found_flag);
    } else {
        printf("./enhanced_nfs_tool %s %d: No flag captured.\n", ip, port);
    }

    if(argc == 6 && strcmp(argv[3], "scan") == 0) {
        unsigned short start_p = (unsigned short)atoi(argv[4]);
        unsigned short end_p = (unsigned short)atoi(argv[5]);
        printf("./enhanced_nfs_tool %s %d: Performing UDP scan on port range %d-%d.\n", ip, port, start_p, end_p);
        int count = advanced_udp_scan(ip, start_p, end_p);
        printf("./enhanced_nfs_tool %s %d: Scan complete. Total responsive UDP ports: %d\n", ip, port, count);
    }

    if(argc == 6 && strcmp(argv[3], "tcp_scan") == 0) {
        unsigned short start_p = (unsigned short)atoi(argv[4]);
        unsigned short end_p = (unsigned short)atoi(argv[5]);
        printf("./enhanced_nfs_tool %s %d: Performing TCP scan on port range %d-%d.\n", ip, port, start_p, end_p);
        int count = advanced_tcp_scan(ip, start_p, end_p);
        printf("./enhanced_nfs_tool %s %d: Scan complete. Total open TCP ports: %d\n", ip, port, count);
    }

    if(argc >= 4 && strcmp(argv[3], "rce") == 0) {
        printf("./enhanced_nfs_tool %s %d: Attempting remote code execution.\n", ip, port);
        if(attempt_remote_code_execution(ip, port)) {
            printf("./enhanced_nfs_tool %s %d: RCE attempt sent.\n", ip, port);
        } else {
            printf("./enhanced_nfs_tool %s %d: Failed to send RCE attempt.\n", ip, port);
        }
    }

    if(argc >= 4 && strcmp(argv[3], "sysinfo") == 0) {
        printf("./enhanced_nfs_tool %s %d: Retrieving system info.\n", ip, port);
        char* info = retrieve_system_info(ip, port);
        if(info && strlen(info) > 0) {
            printf("./enhanced_nfs_tool %s %d: System info: %s\n", ip, port, info);
        } else {
            printf("./enhanced_nfs_tool %s %d: No system info received.\n", ip, port);
        }
    }

    if(argc >= 4 && strcmp(argv[3], "dump_shares") == 0) {
        printf("./enhanced_nfs_tool %s %d: Dumping NFS shares.\n", ip, port);
        char* shares = dump_nfs_shares(ip, port);
        if(shares && strlen(shares) > 0) {
            printf("./enhanced_nfs_tool %s %d: NFS shares:\n%s\n", ip, port, shares);
        } else {
            printf("./enhanced_nfs_tool %s %d: No NFS shares received.\n", ip, port);
        }
    }

    if(argc >= 4 && strcmp(argv[3], "allflags") == 0) {
        printf("./enhanced_nfs_tool %s %d: Attempting to capture all possible flags.\n", ip, port);
        char* all_flags = multi_capture_flags(ip, port);
        if(all_flags && strlen(all_flags) > 0) {
            printf("./enhanced_nfs_tool %s %d: Flags:\n%s\n", ip, port, all_flags);
        } else {
            printf("./enhanced_nfs_tool %s %d: No additional flags captured.\n", ip, port);
        }
    }

    printf("./enhanced_nfs_tool %s %d: Explanation:\n", ip, port);
    printf("1. Sent mock NFS data.\n");
    printf("2. Attempted exploit detection.\n");
    printf("3. Captured potential flag data.\n");
    printf("4. Optional UDP scan.\n");
    printf("5. Optional TCP scan.\n");
    printf("6. Optional RCE attempt.\n");
    printf("7. Optional system info retrieval.\n");
    printf("8. Optional dump of NFS shares.\n");
    printf("9. Optional multi-flag capture.\n");

    return 0;
}