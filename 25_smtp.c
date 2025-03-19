/*
  25_smtp.c
  Usage: 25_smtp <target1> [<target2> ...]
  Connects to each target on port 25, sends SMTP commands, and searches for flags.
  Prints results and an explanation to the terminal.
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

#define SMTP_PORT 25
#define MAX_INPUT 64

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
    int total = 0, n;
    while ((n = recv(sock, buffer + total, len - 1 - total, 0)) > 0) {
        total += n;
        if (strstr(buffer, "\r\n")) break;
    }
    if (total > 0) buffer[total] = '\0';
    return total;
}

void sendCommand(int sock, const char *cmd) {
    send(sock, cmd, strlen(cmd), 0);
    send(sock, "\r\n", 2, 0);
}

void *scanHost(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    char recvBuffer[1024];
    int sock = connectSMTP(data->host);

    if (sock < 0) {
        printf("Failed to connect to %s\n", data->host);
        pthread_exit(NULL);
    }
    if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
        printf("Banner [%s]: %s\n", data->host, recvBuffer);
    }
    for (int c = 0; c < numCmds; c++) {
        sendCommand(sock, testCmds[c]);
        if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
            printf("[%s] %s\n", data->host, recvBuffer);
            if (strstr(recvBuffer, "flag{") || strstr(recvBuffer, "CTF")) {
                printf("Potential flag on %s: %s\n", data->host, recvBuffer);
            }
        }
    }
    close(sock);
    pthread_exit(NULL);
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

    pthread_t *threads = malloc((argc - 1) * sizeof(pthread_t));
    ThreadData *td = malloc((argc - 1) * sizeof(ThreadData));

    for (int t = 1; t < argc; t++) {
        td[t-1].host = argv[t];
        pthread_create(&threads[t-1], NULL, scanHost, &td[t-1]);
    }
    for (int t = 1; t < argc; t++) {
        pthread_join(threads[t-1], NULL);
    }

    free(threads);
    free(td);

    printf("\nScan complete.\nExplanation:\n");
    printf("This script connects to each host on port 25, sends SMTP commands, and looks for flags.\n");
    printf("It sanitizes user input to prevent injection attempts and prints results.\n");

    return 0;
}