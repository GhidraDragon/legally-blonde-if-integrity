/*
 * Usage:
 *   ./enhanced_vnc_tool <IP> <START_PORT> <END_PORT> [THREAD_COUNT]
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
 #include <pthread.h>
 
 #define MAX_BUF 1024
 
 int send_weak_vnc_data(const char *host, unsigned short port) {
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
     strcpy(buffer, "RFB 003.008\n");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("VNC response: %s\n", buffer);
         printf("Explanation: This shows the server's response to a weak handshake.\n");
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
 
 typedef struct {
     const char *host;
     unsigned short port;
 } thread_args_t;
 
 void *thread_scan(void *arg) {
     thread_args_t *args = (thread_args_t*)arg;
     if(detect_exploit(args->host, args->port)) {
         printf("Port %d open on %s.\n", args->port, args->host);
         if(send_weak_vnc_data(args->host, args->port) == 0) {
             printf("Weak VNC data sent.\n");
             printf("Explanation: Data was sent to attempt a handshake.\n");
         } else {
             printf("Failed to send VNC data.\n");
         }
         char *found_flag = capture_flag(args->host, args->port);
         if(found_flag && strlen(found_flag) > 0) {
             printf("Captured flag: %s\n", found_flag);
             printf("Explanation: This flag was returned by the server.\n");
         } else {
             printf("No flag captured.\n");
         }
     } else {
         printf("Port %d closed or unreachable on %s.\n", args->port, args->host);
     }
     return NULL;
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive VNC Data";
     printf("Sending VNC data in a weakly protected way: %s\n", data);
     if(argc < 3) {
         printf("Usage: %s <IP> <START_PORT> <END_PORT> [THREAD_COUNT]\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short startPort = atoi(argv[2]);
     unsigned short endPort = (argc > 3) ? atoi(argv[3]) : startPort;
     int threadCount = (argc > 4) ? atoi(argv[4]) : 1;
     if(startPort == 0) startPort = 1;
     if(endPort == 0) endPort = startPort;
 
     int totalPorts = endPort - startPort + 1;
     if(totalPorts < 1) {
         printf("Invalid port range.\n");
         return 1;
     }
     if(threadCount < 1) threadCount = 1;
     pthread_t *threads = malloc(sizeof(pthread_t) * totalPorts);
     thread_args_t *targs = malloc(sizeof(thread_args_t) * totalPorts);
 
     int i;
     for(i = 0; i < totalPorts; i++) {
         targs[i].host = ip;
         targs[i].port = startPort + i;
         pthread_create(&threads[i], NULL, thread_scan, &targs[i]);
         if((i+1) % threadCount == 0) {
             int j;
             for(j = i - (threadCount - 1); j <= i; j++) {
                 pthread_join(threads[j], NULL);
             }
         }
     }
     int remaining = totalPorts % threadCount;
     if(remaining != 0) {
         int startIndex = totalPorts - remaining;
         for(i = startIndex; i < totalPorts; i++) {
             pthread_join(threads[i], NULL);
         }
     }
     free(threads);
     free(targs);
     return 0;
 }