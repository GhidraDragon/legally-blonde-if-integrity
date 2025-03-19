/*
 * For educational and authorized testing only.
 * Compilation: gcc -o improved_snmp improved_snmp.c
 * Usage: ./improved_snmp <IP> <PORT>
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
 
 #define MAX_BUF 1024
 
 int send_weak_snmp_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if(sock < 0) return -1;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     strcpy(buffer, "SNMPv1_Community_Public");
     if(sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return -3;
     }
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("SNMP response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int detect_exploit(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in target;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if(sock < 0) return 0;
     target.sin_family = AF_INET;
     target.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
         close(sock);
         return 0;
     }
     if(sendto(sock, "ping", 4, 0, (struct sockaddr*)&target, sizeof(target)) < 0) {
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
     socklen_t len = sizeof(srv);
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if(sock < 0) return NULL;
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         close(sock);
         return NULL;
     }
     if(sendto(sock, "GET_FLAG", 8, 0, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
         close(sock);
         return NULL;
     }
     memset(buffer, 0, sizeof(buffer));
     n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&srv, &len);
     if(n > 0) {
         buffer[n] = '\0';
         strncpy(flag, buffer, MAX_BUF-1);
     }
     close(sock);
     return flag;
 }
 
 int send_strong_snmp_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if(sock < 0) return -1;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     srand(time(NULL));
     sprintf(buffer, "SNMPv2_Community_Secure_%d", rand() % 9999);
     if(sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return -3;
     }
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("SNMP (strong) response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 void capture_all_flags(const char *host, unsigned short port) {
     int i;
     for(i = 0; i < 3; i++) {
         char *f = capture_flag(host, port);
         if(f && strlen(f) > 0) {
             printf("Attempt %d captured flag: %s\n", i+1, f);
         } else {
             printf("Attempt %d captured no flag.\n", i+1);
         }
         usleep(300000);
     }
 }
 
 /* New function for multiple SNMP community checks */
 int extended_snmp_checks(const char *host, unsigned short port) {
     static const char *communities[] = {"private", "manager", "secret", "admin"};
     int sock, i, n;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     for(i = 0; i < 4; i++) {
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if(sock < 0) return -1;
         server.sin_family = AF_INET;
         server.sin_port = htons(port);
         if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
             close(sock);
             return -2;
         }
         memset(buffer, 0, sizeof(buffer));
         snprintf(buffer, sizeof(buffer), "SNMPv2_%s", communities[i]);
         if(sendto(sock, buffer, strlen(buffer), 0, (struct sockaddr*)&server, sizeof(server)) < 0) {
             close(sock);
             return -3;
         }
         memset(buffer, 0, sizeof(buffer));
         n = recv(sock, buffer, sizeof(buffer)-1, 0);
         if(n > 0) {
             buffer[n] = '\0';
             printf("Extended check (%s) response: %s\n", communities[i], buffer);
         }
         close(sock);
         usleep(200000);
     }
     return 0;
 }
 
 /* New function to attempt multiple flag variations */
 void capture_extended_flags(const char *host, unsigned short port) {
     static const char* requests[] = {"GET_FLAG2", "GET_FLAG3", "GET_FLAG4"};
     int i, sock, n;
     struct sockaddr_in srv;
     socklen_t len = sizeof(srv);
     char buffer[MAX_BUF];
     for(i = 0; i < 3; i++) {
         sock = socket(AF_INET, SOCK_DGRAM, 0);
         if(sock < 0) continue;
         srv.sin_family = AF_INET;
         srv.sin_port = htons(port);
         if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         sendto(sock, requests[i], strlen(requests[i]), 0, (struct sockaddr*)&srv, sizeof(srv));
         memset(buffer, 0, sizeof(buffer));
         n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&srv, &len);
         if(n > 0) {
             buffer[n] = '\0';
             printf("Extended flag attempt (%s): %s\n", requests[i], buffer);
         } else {
             printf("No extended flag for request: %s\n", requests[i]);
         }
         close(sock);
         usleep(300000);
     }
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive SNMP Data";
     printf("Sending SNMP data in a weakly protected way: %s\n", data);
     if(argc < 3) {
         printf("Usage: %s <IP> <PORT>\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short port = (unsigned short)atoi(argv[2]);
 
     printf("UDP check for SNMP port %d on %s.\n", port, ip);
 
     if(!detect_exploit(ip, port)) {
         printf("No exploit detected or port unreachable.\n");
     } else {
         printf("Potential exploit path or open port detected.\n");
     }
 
     if(send_weak_snmp_data(ip, port) == 0) {
         printf("Weak SNMP data sent.\n");
     } else {
         printf("Failed to send SNMP data.\n");
     }
 
     if(send_strong_snmp_data(ip, port) == 0) {
         printf("Stronger SNMP data sent.\n");
     } else {
         printf("Failed to send stronger SNMP data.\n");
     }
 
     if(extended_snmp_checks(ip, port) == 0) {
         printf("Extended SNMP checks complete.\n");
     } else {
         printf("Extended SNMP checks failed.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured single flag: %s\n", found_flag);
     } else {
         printf("No single flag captured.\n");
     }
 
     capture_all_flags(ip, port);
     capture_extended_flags(ip, port);
 
     return 0;
 }