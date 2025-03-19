/*
 * Usage:
 *   This program attempts to connect to a specified host and port, send weak RDP data,
 *   capture a flag, and includes additional capabilities like port scanning and basic
 *   encrypted data sending for demonstration. For educational and authorized testing only.
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
 
 int send_weak_rdp_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) {
         printf("Explanation: Unable to create socket for weak RDP data.\n");
         return -1;
     }
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         printf("Explanation: Invalid IP address for weak RDP data.\n");
         return -2;
     }
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         printf("Explanation: Failed to connect for weak RDP data.\n");
         return -3;
     }
     strcpy(buffer, "RDP_GREETING");
     send(sock, buffer, strlen(buffer), 0);
     printf("Explanation: Sent unencrypted RDP greeting.\n");
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("RDP response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int detect_exploit(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in target;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) {
         printf("Explanation: Socket creation failed during exploit detection.\n");
         return 0;
     }
     target.sin_family = AF_INET;
     target.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &target.sin_addr) <= 0) {
         close(sock);
         printf("Explanation: Invalid IP address in exploit detection.\n");
         return 0;
     }
     if(connect(sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
         close(sock);
         printf("Explanation: Connection failed in exploit detection.\n");
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
     if(sock < 0) {
         printf("Explanation: Unable to create socket for flag capture.\n");
         return NULL;
     }
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         close(sock);
         printf("Explanation: Invalid IP address for flag capture.\n");
         return NULL;
     }
     if(connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
         close(sock);
         printf("Explanation: Connection failed for flag capture.\n");
         return NULL;
     }
     send(sock, "GET_FLAG", 8, 0);
     printf("Explanation: Requested flag from server.\n");
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         strncpy(flag, buffer, MAX_BUF-1);
     }
     close(sock);
     return flag;
 }
 
 /* New function: persists a flag on the server if possible. */
 int plant_flag_on_server(const char *host, unsigned short port, const char *flag_content) {
     int sock;
     struct sockaddr_in srv;
     char buffer[MAX_BUF];
     int n;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) {
         return -1;
     }
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     if(connect(sock, (struct sockaddr*)&srv, sizeof(srv)) < 0) {
         close(sock);
         return -3;
     }
     snprintf(buffer, sizeof(buffer), "PLANT_FLAG:%s", flag_content);
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("Flag planting response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 /* New function: attempts multiple captures until a flag is retrieved or attempts are exhausted. */
 char* capture_flag_persistent(const char *host, unsigned short port) {
     static char persistent_flag[MAX_BUF];
     memset(persistent_flag, 0, sizeof(persistent_flag));
     for(int i = 0; i < 5; i++) {
         char *f = capture_flag(host, port);
         if(f && strlen(f) > 0) {
             strncpy(persistent_flag, f, MAX_BUF-1);
             break;
         }
         sleep(1);
     }
     if(strlen(persistent_flag) == 0) {
         return NULL;
     }
     return persistent_flag;
 }
 
 void scan_ports(const char *host, int start, int end) {
     int sock;
     struct sockaddr_in saddr;
     int port;
     printf("Explanation: Starting port scan from %d to %d.\n", start, end);
     for(port = start; port <= end; port++) {
         sock = socket(AF_INET, SOCK_STREAM, 0);
         if(sock < 0) {
             continue;
         }
         saddr.sin_family = AF_INET;
         saddr.sin_port = htons(port);
         if(inet_pton(AF_INET, host, &saddr.sin_addr) <= 0) {
             close(sock);
             continue;
         }
         if(connect(sock, (struct sockaddr*)&saddr, sizeof(saddr)) == 0) {
             printf("Explanation: Port %d is open.\n", port);
         }
         close(sock);
     }
 }
 
 int secure_send_rdp_data(const char *host, unsigned short port, const char *data) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int i, n, len;
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) {
         printf("Explanation: Unable to create socket for secure RDP data.\n");
         return -1;
     }
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         printf("Explanation: Invalid IP address for secure RDP data.\n");
         return -2;
     }
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         printf("Explanation: Failed to connect for secure RDP data.\n");
         return -3;
     }
     memset(buffer, 0, sizeof(buffer));
     strncpy(buffer, data, MAX_BUF-1);
     len = strlen(buffer);
     for(i = 0; i < len; i++) {
         buffer[i] ^= 0xAA;
     }
     send(sock, buffer, len, 0);
     printf("Explanation: Sent XOR-encrypted data.\n");
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         for(i = 0; i < n; i++) {
             buffer[i] ^= 0xAA;
         }
         buffer[n] = '\0';
         printf("Secure RDP response: %s\n", buffer);
     }
     close(sock);
     return 0;
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive RDP Data (3389)";
     printf("Sending RDP data in a weakly protected way: %s\n", data);
 
     if(argc < 3) {
         printf("Usage: %s <IP> <PORT> [scan|secure|plant|persistent]\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short port = atoi(argv[2]);
 
     if(argc > 3 && strcmp(argv[3], "scan") == 0) {
         scan_ports(ip, 1, 1024);
         return 0;
     }
 
     if(argc > 3 && strcmp(argv[3], "secure") == 0) {
         printf("Explanation: Attempting to securely send RDP data.\n");
         if(secure_send_rdp_data(ip, port, "HelloRDP") == 0) {
             printf("Secure RDP data sent successfully.\n");
         } else {
             printf("Failed to send secure RDP data.\n");
         }
     }
 
     if(argc > 3 && strcmp(argv[3], "plant") == 0) {
         if(plant_flag_on_server(ip, port, "MY_PERSISTENT_FLAG") == 0) {
             printf("Flag planted successfully.\n");
         } else {
             printf("Failed to plant flag.\n");
         }
     }
 
     if(argc > 3 && strcmp(argv[3], "persistent") == 0) {
         char *persistent_result = capture_flag_persistent(ip, port);
         if(persistent_result && strlen(persistent_result) > 0) {
             printf("Captured persistent flag: %s\n", persistent_result);
         } else {
             printf("No flag captured after persistent attempts.\n");
         }
         return 0;
     }
 
     if(!detect_exploit(ip, port)) {
         printf("Port %d closed or unreachable on %s.\n", port, ip);
         return 0;
     }
     printf("Port %d open on %s.\n", port, ip);
 
     if(send_weak_rdp_data(ip, port) == 0) {
         printf("Weak RDP data sent successfully.\n");
     } else {
         printf("Failed to send weak RDP data.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
     return 0;
 }