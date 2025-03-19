/*
 * Enhanced Telnet Scanner and Simple Telnet Server
 *
 * Usage:
 *   1) Compile:
 *        gcc -o telnet_tool telnet_tool.c
 *
 *   2) Scan mode (attempt "root:root123" against a range of IPs):
 *        ./telnet_tool scan <startIP> <endIP> <port>
 *      Example:
 *        ./telnet_tool scan 192.168.1.1 192.168.1.254 23
 *
 *   3) Server mode (listen on port 1337 for telnet credentials):
 *        ./telnet_tool
 *      If user enters "USER root\r\nPASS root123\r\n", the server returns
 *      "Flag{telnet_is_insecure}", otherwise "Access Denied".
 *
 * Note:
 *   This is a demonstration of how credentials sent via Telnet are
 *   transmitted in plaintext, which is insecure for real-world use.
 */

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
     if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
         close(s);
         return 0;
     }
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
         if (inet_pton(AF_INET, argv[2], &start) <= 0 ||
             inet_pton(AF_INET, argv[3], &end)   <= 0) {
             printf("Invalid IP address.\n");
             return 1;
         }
         start = ntohl(start);
         end   = ntohl(end);
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
     if (bind(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0) {
         perror("bind");
         return 1;
     }
     if (listen(sockfd, 1) < 0) {
         perror("listen");
         return 1;
     }
 
     int c = sizeof(struct sockaddr_in);
     int client_sock = accept(sockfd, (struct sockaddr*)&client, (socklen_t*)&c);
     if (client_sock < 0) {
         perror("accept");
         close(sockfd);
         return 1;
     }
 
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