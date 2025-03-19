#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

int try_telnet(char *ip, int port, char *user, char *pass) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(s);
        return 0;
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "USER %s\r\nPASS %s\r\n", user, pass);
    send(s, buf, strlen(buf), 0);
    memset(buf, 0, sizeof(buf));
    recv(s, buf, sizeof(buf)-1, 0);
    close(s);
    if (strstr(buf, "Flag{")) {
        printf("%s -> %s", ip, buf);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "scan") == 0) {
        if (argc < 5) {
            printf("Usage: %s scan <startIP> <endIP> <port>\n", argv[0]);
            return 1;
        }
        int port = atoi(argv[4]);
        unsigned int start, end;
        inet_pton(AF_INET, argv[2], &start);
        inet_pton(AF_INET, argv[3], &end);
        start = ntohl(start);
        end = ntohl(end);
        for (unsigned int ip = start; ip <= end; ip++) {
            struct in_addr in;
            in.s_addr = htonl(ip);
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in, ipstr, INET_ADDRSTRLEN);
            try_telnet(ipstr, port, "root", "root123");
        }
        return 0;
    }

    char msg[128];
    strcpy(msg, "USER root\nPASS root123\n");
    printf("Sending credentials in plaintext: %s", msg);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server, client;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(1337);
    bind(sockfd, (struct sockaddr*)&server, sizeof(server));
    listen(sockfd, 1);

    int c = sizeof(struct sockaddr_in);
    int client_sock = accept(sockfd, (struct sockaddr*)&client, (socklen_t*)&c);

    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    recv(client_sock, buffer, 127, 0);

    if (strstr(buffer, "USER root") && strstr(buffer, "PASS root123")) {
        send(client_sock, "Flag{telnet_is_insecure}\n", 26, 0);
    } else {
        send(client_sock, "Access Denied\n", 14, 0);
    }

    close(client_sock);
    close(sockfd);
    return 0;
}