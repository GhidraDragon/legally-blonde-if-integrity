#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    // Telnet-like cleartext send/receive
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