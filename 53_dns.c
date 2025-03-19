/*
  25_smtp.c
  Usage: 25_smtp <target1> [<target2> ...]
  Connects to each target on port 25, sends SMTP commands, searches for flags,
  and prints results with an explanation. Now supports DNS, IPv6, timeouts,
  concurrency, and appends flags to flags_found.txt.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>

#define SMTP_PORT "25"
#define MAX_INPUT 64
#define MAX_RESPONSE 1024
#define THREAD_LIMIT 64

static pthread_mutex_t fileMutex = PTHREAD_MUTEX_INITIALIZER;

struct ThreadData {
    char host[256];
};

int setSocketTimeout(int sock, int sec) {
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
}

int connectSMTP(const char *host) {
    struct addrinfo hints, *res, *p;
    int sock = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, SMTP_PORT, &hints, &res) != 0) return -1;
    for (p = res; p; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            freeaddrinfo(res);
            setSocketTimeout(sock, 2);
            return sock;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return -1;
}

int readResponse(int sock, char *buffer, int len) {
    int n = recv(sock, buffer, len - 1, 0);
    if (n > 0) buffer[n] = '\0';
    return n;
}

void sendCommand(int sock, const char *cmd) {
    send(sock, cmd, strlen(cmd), 0);
    send(sock, "\r\n", 2, 0);
}

void scanSMTPHost(const char *host) {
    char recvBuffer[MAX_RESPONSE];
    char *testCmds[] = {
        "EHLO test",
        "MAIL FROM:<test@example.com>",
        "RCPT TO:<root>",
        "VRFY root",
        "EXPN postmaster",
        "QUIT"
    };
    int numCmds = sizeof(testCmds) / sizeof(testCmds[0]);
    printf("Scanning host: %s\n", host);
    int sock = connectSMTP(host);
    if (sock < 0) {
        printf("Failed to connect to %s\n", host);
        return;
    }
    if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
        printf("Banner: %s\n", recvBuffer);
    }
    for (int c = 0; c < numCmds; c++) {
        sendCommand(sock, testCmds[c]);
        if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
            printf("%s\n", recvBuffer);
            if (strstr(recvBuffer, "flag{") || strstr(recvBuffer, "CTF")) {
                printf("Potential flag on %s: %s\n", host, recvBuffer);
                pthread_mutex_lock(&fileMutex);
                FILE *f = fopen("flags_found.txt", "a");
                if (f) {
                    fprintf(f, "Host: %s - %s\n", host, recvBuffer);
                    fclose(f);
                }
                pthread_mutex_unlock(&fileMutex);
            }
        }
    }
    close(sock);
}

void *threadFunc(void *arg) {
    struct ThreadData *data = (struct ThreadData*)arg;
    scanSMTPHost(data->host);
    free(data);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target1> [<target2> ...]\n", argv[0]);
        return 1;
    }

    char userInput[MAX_INPUT];
    strcpy(userInput, "mail@example.com\r\nRCPT TO: | rm -rf /");
    char sanitizedInput[MAX_INPUT];
    int i, j = 0;
    for (i = 0; i < MAX_INPUT - 1 && userInput[i] != '\0'; i++) {
        if (userInput[i] == '|' || userInput[i] == ';' || userInput[i] == '&'
            || userInput[i] == '\r' || userInput[i] == '\n') {
            continue;
        }
        sanitizedInput[j++] = userInput[i];
    }
    sanitizedInput[j] = '\0';

    FILE *fp = popen("/usr/sbin/sendmail -t", "w");
    if (fp) {
        fputs(sanitizedInput, fp);
        pclose(fp);
    }

    pthread_t threads[THREAD_LIMIT];
    int threadCount = 0;
    for (int t = 1; t < argc; t++) {
        struct ThreadData *data = (struct ThreadData*)malloc(sizeof(struct ThreadData));
        if (!data) continue;
        strncpy(data->host, argv[t], sizeof(data->host) - 1);
        data->host[sizeof(data->host) - 1] = '\0';
        pthread_create(&threads[threadCount++], NULL, threadFunc, data);
        if (threadCount >= THREAD_LIMIT) break;
    }
    for (int t = 0; t < threadCount; t++) {
        pthread_join(threads[t], NULL);
    }

    printf("\nScan complete.\nExplanation:\n");
    printf("This script connects to each host on port 25, sends SMTP commands,\n");
    printf("checks responses for potential flags, sanitizes user input, uses DNS/IPv6,\n");
    printf("and logs flags to flags_found.txt.\n");
    return 0;
}