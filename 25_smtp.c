/*
  25_smtp_enhanced.c
  Usage: 25_smtp_enhanced <target1> [<target2> ...] [-m <max_concurrency>]
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>

#define SMTP_PORT 25
#define MAX_INPUT 64
#define DEFAULT_MAX_THREADS 5

static const char *testCmds[] = {
    "EHLO test",
    "MAIL FROM:<test@example.com>",
    "RCPT TO:<root>",
    "VRFY root",
    "EXPN postmaster",
    "QUIT"
};
static const int numCmds = 6;

typedef struct {
    char *host;
} ThreadData;

static sem_t sem;
static int maxThreads = DEFAULT_MAX_THREADS;

static char *strcasestr_local(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    size_t len_h = strlen(haystack), len_n = strlen(needle);
    for (size_t i = 0; i + len_n <= len_h; i++) {
        if (strncasecmp(&haystack[i], needle, len_n) == 0) {
            return (char *)&haystack[i];
        }
    }
    return NULL;
}

int connectSMTP(const char *host) {
    struct addrinfo hints, *res, *p;
    int sock = -1;
    char portStr[8];
    snprintf(portStr, sizeof(portStr), "%d", SMTP_PORT);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portStr, &hints, &res) != 0) return -1;
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

int readResponse(int sock, char *buffer, int len) {
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int total = 0, n;
    while ((n = recv(sock, buffer + total, len - 1 - total, 0)) > 0) {
        total += n;
        if (total >= len - 1) break;
    }
    if (total > 0) buffer[total] = '\0';
    return total;
}

void sendCommand(int sock, const char *cmd) {
    send(sock, cmd, strlen(cmd), 0);
    send(sock, "\r\n", 2, 0);
}

void *scanHost(void *arg) {
    sem_wait(&sem);
    ThreadData *data = (ThreadData *)arg;
    char recvBuffer[4096];
    int sock = connectSMTP(data->host);
    if (sock < 0) {
        printf("Failed to connect to %s\n", data->host);
        sem_post(&sem);
        pthread_exit(NULL);
    }
    if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
        printf("\x1b[36mBanner [%s]:\x1b[0m %s\n", data->host, recvBuffer);
    }
    for (int c = 0; c < numCmds; c++) {
        sendCommand(sock, testCmds[c]);
        if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
            printf("[%s] %s\n", data->host, recvBuffer);
            if (strcasestr_local(recvBuffer, "flag{") ||
                strcasestr_local(recvBuffer, "ctf{")) {
                printf("\x1b[31mPotential flag on %s:\x1b[0m %s\n", data->host, recvBuffer);
            }
        }
    }
    close(sock);
    sem_post(&sem);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target1> [<target2> ...] [-m <max_concurrency>]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-m") && (i + 1 < argc)) {
            maxThreads = atoi(argv[++i]);
            if (maxThreads < 1) maxThreads = DEFAULT_MAX_THREADS;
        }
    }

    char userInput[MAX_INPUT];
    strcpy(userInput, "mail@example.com\r\nRCPT TO: | rm -rf /");
    char sanitizedInput[MAX_INPUT];
    int i, j = 0;
    for (i = 0; i < MAX_INPUT - 1 && userInput[i] != '\0'; i++) {
        if (strchr("|;&\r\n", userInput[i])) continue;
        sanitizedInput[j++] = userInput[i];
    }
    sanitizedInput[j] = '\0';
    FILE *fp = popen("/usr/sbin/sendmail -t", "w");
    if (fp) {
        fputs(sanitizedInput, fp);
        pclose(fp);
    }

    sem_init(&sem, 0, maxThreads);

    int targetsStart = 1;
    pthread_t *threads = malloc((argc - 1) * sizeof(pthread_t));
    ThreadData *td = malloc((argc - 1) * sizeof(ThreadData));
    int tCount = 0;
    for (int t = 1; t < argc; t++) {
        if (!strcmp(argv[t], "-m")) {
            t++; 
            continue;
        }
        td[tCount].host = argv[t];
        pthread_create(&threads[tCount], NULL, scanHost, &td[tCount]);
        tCount++;
    }
    for (int t = 0; t < tCount; t++) {
        pthread_join(threads[t], NULL);
    }

    free(threads);
    free(td);
    sem_destroy(&sem);

    printf("\nScan complete.\nExplanation:\n");
    printf("Connects to each host on port 25, sends SMTP commands, and looks for flags.\n");
    printf("Sanitizes user input to prevent injection and prints results.\n");
    printf("Use -m to limit maximum concurrency.\n");
    return 0;
}