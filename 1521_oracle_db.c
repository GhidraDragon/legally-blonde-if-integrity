/*
 * Enhanced networking demonstration for authorized usage only.
 * Minimal comments as requested.
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
 
 int send_weak_oracle_data(const char *host, unsigned short port) {
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
     strcpy(buffer, "ORACLE_LOGIN scott tiger");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("[*] Oracle DB response: %s\n", buffer);
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
 
 /* New function: port scanning for demonstration */
 void perform_port_scan(const char *host, int start_port, int end_port) {
     printf("[*] Performing port scan from %d to %d on %s\n", start_port, end_port, host);
     for(int p = start_port; p <= end_port; p++) {
         int sock = socket(AF_INET, SOCK_STREAM, 0);
         if(sock < 0) continue;
         struct sockaddr_in addr;
         addr.sin_family = AF_INET;
         addr.sin_port = htons(p);
         if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
             printf("[*] Port %d is open.\n", p);
         }
         close(sock);
     }
     printf("[*] Port scan complete.\n");
 }
 
 /* New function: additional server interaction for demonstration */
 void get_server_banner(const char *host, unsigned short port) {
     printf("[*] Attempting to retrieve server banner on %s:%d\n", host, port);
     int sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) {
         printf("[!] Could not create socket.\n");
         return;
     }
     struct sockaddr_in srv;
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         printf("[!] Invalid IP.\n");
         close(sock);
         return;
     }
     if(connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
         printf("[!] Cannot connect to port %d.\n", port);
         close(sock);
         return;
     }
     send(sock, "HEAD / HTTP/1.0\r\n\r\n", 19, 0);
     char buffer[MAX_BUF];
     memset(buffer, 0, sizeof(buffer));
     int n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("[*] Server banner:\n%s\n", buffer);
     }
     close(sock);
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive Oracle DB Data";
     printf("[*] Sending Oracle DB data in a weakly protected way: %s\n", data);
 
     if(argc < 3) {
         printf("[!] Usage: %s <IP> <PORT> [scan-start scan-end]\n", argv[0]);
         return 1;
     }
 
     const char *ip = argv[1];
     unsigned short port = (unsigned short)atoi(argv[2]);
 
     if(argc == 5) {
         int start_port = atoi(argv[3]);
         int end_port = atoi(argv[4]);
         perform_port_scan(ip, start_port, end_port);
     }
 
     if(!detect_exploit(ip, port)) {
         printf("[!] Port %d closed or unreachable on %s.\n", port, ip);
         return 0;
     }
     printf("[*] Port %d open on %s.\n", port, ip);
 
     get_server_banner(ip, port);
 
     if(send_weak_oracle_data(ip, port) == 0) {
         printf("[*] Weak Oracle data sent.\n");
     } else {
         printf("[!] Failed to send Oracle data.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("[*] Captured flag: %s\n", found_flag);
     } else {
         printf("[!] No flag captured.\n");
     }
 
     printf("[*] Explanation:\n");
     printf(" - We scanned optional port ranges if provided.\n");
     printf(" - We checked if the specified port was reachable.\n");
     printf(" - We retrieved a banner for demonstration.\n");
     printf(" - We sent data to a mock Oracle DB.\n");
     printf(" - We attempted to capture a flag.\n");
     printf("[*] End of enhanced demonstration.\n");
 
     return 0;
 }