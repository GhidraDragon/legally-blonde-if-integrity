/*
 * This program demonstrates how to send and receive data over a network using a simple
 * RPC-like approach, detect open ports, and retrieve a "flag" for educational and authorized 
 * penetration testing scenarios only.
 *
 * DISCLAIMER:
 *  - This code is provided for demonstration, testing, and learning purposes.
 *  - Use it only on systems and networks where you have explicit permission.
 *  - The author and providers of this code assume no responsibility for misuse.
 *
 * USAGE:
 *  1) Compile: 
 *       gcc -o weak_rpc weak_rpc.c
 *  2) Run:
 *       ./weak_rpc <IP> <PORT>
 *     If <IP> or <PORT> is not provided, it will default to 127.0.0.1 and 8080 respectively.
 *
 * EXAMPLE:
 *  - ./weak_rpc 192.168.1.10 5555
 *    This attempts to connect to 192.168.1.10 on port 5555, send weak RPC data, 
 *    detect if the port is open, and capture a sample flag string.
 *
 * For educational and authorized testing only.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 
 #define MAX_BUF 1024
 
 int send_weak_rpc_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
 
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return -1;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return -3;
     }
     strcpy(buffer, "RPC_HELLO");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer) - 1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("Received RPC response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int detect_exploit(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in target;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return 0;
     target.sin_family = AF_INET;
     target.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
         close(sock);
         return 0;
     }
     if(connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
         close(sock);
         return 0;
     }
     close(sock);
     return 1;
 }
 
 char* capture_flag(const char *host, unsigned short port) {
     static char flag[MAX_BUF];
     int sock;
     struct sockaddr_in srv;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return NULL;
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         close(sock);
         return NULL;
     }
     if(connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
         close(sock);
         return NULL;
     }
     send(sock, "GET_FLAG", 8, 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         strncpy(flag, buffer, MAX_BUF-1);
     }
     close(sock);
     return flag;
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive RPC Data";
     printf("Sending RPC data in a weakly protected way: %s\n", data);
 
     const char *ip = "127.0.0.1";
     unsigned short port = 8080;
 
     if(argc >= 2) {
         ip = argv[1];
     }
     if(argc >= 3) {
         port = (unsigned short)atoi(argv[2]);
     }
 
     if(!detect_exploit(ip, port)) {
         printf("Port %d closed or unreachable on %s.\n", port, ip);
         return 0;
     }
     printf("Port %d open on %s.\n", port, ip);
 
     if(send_weak_rpc_data(ip, port) == 0) {
         printf("Weak RPC data sent successfully.\n");
     } else {
         printf("Failed to send weak RPC data.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
     return 0;
 }