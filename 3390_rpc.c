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
#include <time.h>
#include <pthread.h>

#ifdef __APPLE__
#include <sys/select.h>
#endif

#define MAX_BUF 1024
#define MSG_RPC "RPC_HELLO"
#define MSG_FLAG "GET_FLAG"

static FILE *log_fp = NULL;
static int thread_count = 1;

typedef struct {
    const char *host;
    unsigned short start_port;
    unsigned short end_port;
    int timeout;
} ScanArgs;

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

int detect_exploit(const char *host, unsigned short port, int timeout) {
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
    if (connect_with_timeout(sock, &target, timeout) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

static int send_weak_rpc_data(const char *host, unsigned short port, int timeout) {
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
    if (connect_with_timeout(sock, &server, timeout) < 0) {
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
        if (log_fp) fprintf(log_fp, "Received RPC response: %s\n", buffer);
    }
    close(sock);
    return 0;
}

char* capture_flag(const char *host, unsigned short port, int timeout) {
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
    if (connect_with_timeout(sock, &srv, timeout) < 0) {
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

static int detect_tls(const char *host, unsigned short port, int timeout) {
    int sock;
    struct sockaddr_in server;
    unsigned char tls_client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x31, 0x01, 0x00, 0x00,
        0x2d, 0x03, 0x03, 0x5a, 0x1b, 0x1f, 0x53, 0x7b,
        0xfa, 0x21, 0xcc, 0x9c, 0x0e, 0x3f, 0x0a, 0x40,
        0x98, 0x0a, 0x71, 0xe3, 0xf8, 0x7d, 0x3e, 0xec,
        0x00, 0x00, 0x06, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0,
        0x2c, 0xc0, 0x30, 0x01, 0x00
    };
    char buffer[128];
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    if (connect_with_timeout(sock, &server, timeout) < 0) {
        close(sock);
        return 0;
    }
    if (send(sock, tls_client_hello, sizeof(tls_client_hello), 0) < 0) {
        close(sock);
        return 0;
    }
    if (recv(sock, buffer, sizeof(buffer) - 1, 0) > 0) {
        close(sock);
        return 1;
    }
    close(sock);
    return 0;
}

static void banner_grab(const char *host, unsigned short port, int timeout) {
    int sock;
    struct sockaddr_in server;
    char buffer[MAX_BUF];
    int n;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return;
    }
    if (connect_with_timeout(sock, &server, timeout) < 0) {
        close(sock);
        return;
    }
    memset(buffer, 0, sizeof(buffer));
    n = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Banner on port %d: %s\n", port, buffer);
        if (log_fp) fprintf(log_fp, "Banner on port %d: %s\n", port, buffer);
    }
    close(sock);
}

static void fuzz_target(const char *host, unsigned short port, int timeout) {
    int sock;
    struct sockaddr_in server;
    char fuzz_data[MAX_BUF];
    memset(fuzz_data, 'A', sizeof(fuzz_data) - 1);
    fuzz_data[sizeof(fuzz_data) - 1] = '\0';
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return;
    }
    if (connect_with_timeout(sock, &server, timeout) < 0) {
        close(sock);
        return;
    }
    send(sock, fuzz_data, strlen(fuzz_data), 0);
    close(sock);
}

static void *threaded_scan(void *args) {
    ScanArgs *s = (ScanArgs*)args;
    for (unsigned short p = s->start_port; p <= s->end_port; p++) {
        int open = detect_exploit(s->host, p, s->timeout);
        printf("Port %d on %s is %s\n", p, s->host, open ? "open" : "closed");
        if (log_fp) fprintf(log_fp, "Port %d on %s is %s\n", p, s->host, open ? "open" : "closed");
        if (open) {
            if (detect_tls(s->host, p, s->timeout)) {
                printf("TLS likely supported on port %d\n", p);
                if (log_fp) fprintf(log_fp, "TLS likely supported on port %d\n", p);
            }
            banner_grab(s->host, p, s->timeout);
        }
    }
    return NULL;
}

static void scan_port_range(const char *host, unsigned short start_port,
                            unsigned short end_port, int timeout) {
    if (thread_count < 2) {
        ScanArgs single = {host, start_port, end_port, timeout};
        threaded_scan(&single);
    } else {
        unsigned short range = end_port - start_port + 1;
        unsigned short chunk = range / thread_count;
        if (chunk == 0) chunk = 1;
        pthread_t *threads = malloc(sizeof(pthread_t) * thread_count);
        ScanArgs *targs = malloc(sizeof(ScanArgs) * thread_count);
        unsigned short current_start = start_port;
        for (int i = 0; i < thread_count; i++) {
            unsigned short calc_end = current_start + chunk - 1;
            if (i == thread_count - 1) calc_end = end_port;
            targs[i].host = host;
            targs[i].start_port = current_start;
            targs[i].end_port = calc_end;
            targs[i].timeout = timeout;
            pthread_create(&threads[i], NULL, threaded_scan, &targs[i]);
            current_start = calc_end + 1;
            if (current_start > end_port) break;
        }
        for (int i = 0; i < thread_count; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
        free(targs);
    }
}

int main(int argc, char *argv[]) {
    printf("Sending RPC data in a weakly protected way.\n");
    if (argc < 3) {
        printf("Usage: %s <IP> <PORT>\n", argv[0]);
        printf("Optional: --scan <START_PORT> <END_PORT> --timeout <SECONDS> --log <FILE>\n");
        printf("Optional: --threads <N> --tls-check --fuzz\n");
        return 1;
    }
    const char *ip = argv[1];
    unsigned short port = (unsigned short)atoi(argv[2]);
    int timeout = 3;
    int do_scan = 0;
    int do_tls_check = 0;
    int do_fuzz = 0;
    unsigned short scan_start = 0;
    unsigned short scan_end = 0;

    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--scan") && (i + 2 < argc)) {
            do_scan = 1;
            scan_start = (unsigned short)atoi(argv[i + 1]);
            scan_end = (unsigned short)atoi(argv[i + 2]);
            i += 2;
        } else if (!strcmp(argv[i], "--timeout") && (i + 1 < argc)) {
            timeout = atoi(argv[i + 1]);
            i++;
        } else if (!strcmp(argv[i], "--log") && (i + 1 < argc)) {
            log_fp = fopen(argv[i + 1], "a");
            if (!log_fp) {
                printf("Failed to open log file.\n");
            } else {
                time_t t = time(NULL);
                fprintf(log_fp, "\n--- Log started: %s", ctime(&t));
            }
            i++;
        } else if (!strcmp(argv[i], "--threads") && (i + 1 < argc)) {
            thread_count = atoi(argv[i + 1]);
            if (thread_count < 1) thread_count = 1;
            i++;
        } else if (!strcmp(argv[i], "--tls-check")) {
            do_tls_check = 1;
        } else if (!strcmp(argv[i], "--fuzz")) {
            do_fuzz = 1;
        }
    }

    if (!detect_exploit(ip, port, timeout)) {
        printf("Port %d closed or unreachable on %s.\n", port, ip);
        if (log_fp) fprintf(log_fp, "Port %d closed or unreachable on %s.\n", port, ip);
        if (do_scan) {
            printf("Scanning port range %d-%d on %s:\n", scan_start, scan_end, ip);
            scan_port_range(ip, scan_start, scan_end, timeout);
        }
        if (log_fp) fclose(log_fp);
        return 0;
    }

    printf("Port %d open on %s.\n", port, ip);
    if (log_fp) fprintf(log_fp, "Port %d open on %s.\n", port, ip);

    if (send_weak_rpc_data(ip, port, timeout) == 0) {
        printf("Weak RPC data sent successfully.\n");
        if (log_fp) fprintf(log_fp, "Weak RPC data sent successfully.\n");
    } else {
        printf("Failed to send weak RPC data.\n");
        if (log_fp) fprintf(log_fp, "Failed to send weak RPC data.\n");
    }

    if (do_tls_check) {
        int tls_supported = detect_tls(ip, port, timeout);
        printf("TLS check on %s:%d -> %s\n", ip, port, tls_supported ? "supported" : "not supported");
        if (log_fp) fprintf(log_fp, "TLS check on %s:%d -> %s\n", ip, port, tls_supported ? "supported" : "not supported");
    }

    char *found_flag = capture_flag(ip, port, timeout);
    if (found_flag && strlen(found_flag) > 0) {
        printf("Captured flag: %s\n", found_flag);
        if (log_fp) fprintf(log_fp, "Captured flag: %s\n", found_flag);
    } else {
        printf("No flag captured.\n");
        if (log_fp) fprintf(log_fp, "No flag captured.\n");
    }

    if (do_fuzz) {
        fuzz_target(ip, port, timeout);
        printf("Fuzz data sent to %s:%d.\n", ip, port);
        if (log_fp) fprintf(log_fp, "Fuzz data sent to %s:%d.\n", ip, port);
    }

    if (do_scan) {
        printf("Scanning port range %d-%d on %s with %d thread(s):\n", scan_start, scan_end, ip, thread_count);
        if (log_fp) fprintf(log_fp, "Scanning port range %d-%d on %s with %d thread(s):\n",
                            scan_start, scan_end, ip, thread_count);
        scan_port_range(ip, scan_start, scan_end, timeout);
    }

    if (log_fp) fclose(log_fp);

    printf("Explanation of results:\n");
    printf(" - detect_exploit tests basic TCP connectivity.\n");
    printf(" - send_weak_rpc_data sends RPC message and prints any response.\n");
    printf(" - capture_flag tries to retrieve a secret flag.\n");
    printf(" - detect_tls sends a TLS ClientHello to see if TLS is supported.\n");
    printf(" - banner_grab reads any initial banner from the server.\n");
    printf(" - fuzz_target sends large data to test stability.\n");
    printf(" - scan_port_range can run in multiple threads to speed port checks.\n");
    return 0;
}