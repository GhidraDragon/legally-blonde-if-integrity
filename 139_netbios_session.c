/*
 * For educational and authorized security testing only.
 * Instructions:
 * 1. Compile with: gcc -o 139_netbios_session 139_netbios_session.c
 * 2. Run with: ./139_netbios_session <IP> <PORT>
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <sys/time.h>

 #define MAX_BUF 1024
 
 static int set_socket_timeout(int sock, int seconds) {
     struct timeval tv;
     tv.tv_sec = seconds;
     tv.tv_usec = 0;
     return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
 }
 
 static int send_all(int sock, const char *data, size_t len) {
     size_t total_sent = 0;
     while(total_sent < len) {
         ssize_t sent = send(sock, data + total_sent, len - total_sent, 0);
         if(sent <= 0) return -1;
         total_sent += sent;
     }
     return 0;
 }
 
 static int recv_all(int sock, char *buffer, size_t bufsize) {
     size_t received = 0;
     while(received < bufsize - 1) {
         ssize_t r = recv(sock, buffer + received, bufsize - 1 - received, 0);
         if(r <= 0) break;
         received += r;
     }
     buffer[received] = '\0';
     return (int)received;
 }
 
 int send_weak_netbios_session_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
 
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return -1;
     set_socket_timeout(sock, 5);
     memset(&server, 0, sizeof(server));
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
     if(send_all(sock, "NETBIOS_SESSION_INIT", strlen("NETBIOS_SESSION_INIT")) < 0) {
         close(sock);
         return -4;
     }
     memset(buffer, 0, sizeof(buffer));
     if(recv_all(sock, buffer, sizeof(buffer)) > 0) {
         printf("NetBIOS Session response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int detect_exploit(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in target;
 
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return 0;
     set_socket_timeout(sock, 5);
     memset(&target, 0, sizeof(target));
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
 
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return NULL;
     set_socket_timeout(sock, 5);
     memset(&srv, 0, sizeof(srv));
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
     if(send_all(sock, "GET_FLAG", 8) < 0) {
         close(sock);
         return NULL;
     }
     memset(buffer, 0, sizeof(buffer));
     if(recv_all(sock, buffer, sizeof(buffer)) > 0) {
         strncpy(flag, buffer, MAX_BUF - 1);
     }
     close(sock);
     return flag;
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive NetBIOS Session Data";
     printf("Sending NetBIOS session data: %s\n", data);
 
     if(argc < 3) {
         printf("Usage: %s <IP> <PORT>\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short port = (unsigned short)atoi(argv[2]);
 
     if(!detect_exploit(ip, port)) {
         printf("Port %d closed or unreachable on %s.\n", port, ip);
         return 0;
     }
     printf("Port %d open on %s.\n", port, ip);
 
     if(send_weak_netbios_session_data(ip, port) == 0) {
         printf("Weak NetBIOS session data sent.\n");
     } else {
         printf("Failed to send NetBIOS session data.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
     return 0;
 }