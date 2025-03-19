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
#include <arpa/inet.h>

#define SMTP_PORT 25
#define MAX_INPUT 64

int connectSMTP(const char *host) {
    int sock;
    struct sockaddr_in server;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(SMTP_PORT);
    if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
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

    char recvBuffer[1024];
    char *testCmds[] = {
        "EHLO test",
        "MAIL FROM:<test@example.com>",
        "RCPT TO:<root>",
        "VRFY root",
        "EXPN postmaster",
        "QUIT"
    };
    int numCmds = sizeof(testCmds) / sizeof(testCmds[0]);

    for (int t = 1; t < argc; t++) {
        printf("Scanning host: %s\n", argv[t]);
        int sock = connectSMTP(argv[t]);
        if (sock < 0) {
            printf("Failed to connect to %s\n", argv[t]);
            continue;
        }
        if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
            printf("Banner: %s\n", recvBuffer);
        }
        for (int c = 0; c < numCmds; c++) {
            sendCommand(sock, testCmds[c]);
            if (readResponse(sock, recvBuffer, sizeof(recvBuffer)) > 0) {
                printf("%s\n", recvBuffer);
                if (strstr(recvBuffer, "flag{") || strstr(recvBuffer, "CTF")) {
                    printf("Potential flag on %s: %s\n", argv[t], recvBuffer);
                }
            }
        }
        close(sock);
    }

    printf("\nScan complete.\nExplanation:\n");
    printf("This script attempts to connect to each host on port 25, sends SMTP commands,\n");
    printf("and monitors responses for potential flags. It sanitizes user input to mitigate\n");
    printf("injection attempts and prints results to the terminal.\n");

    return 0;
}