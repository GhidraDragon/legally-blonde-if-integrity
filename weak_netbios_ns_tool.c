/*
 * Program Name: weak_netbios_ns_tool.c
 *
 * Description:
 *   This program demonstrates sending weakly protected NetBIOS Name Service (NS)
 *   data over UDP, performing a simple UDP port check (detect_exploit), and 
 *   attempting to capture a "flag" from the target via UDP (capture_flag).
 *   Additionally, it can retrieve a persistent flag via SSH credentials if provided.
 *
 * Usage:
 *   1. Compile:
 *        gcc -o weak_netbios_ns_tool weak_netbios_ns_tool.c
 *   2. Run:
 *        ./weak_netbios_ns_tool <IP> <PORT> [SSH_USER] [SSH_PASS] [FLAG_PATH]
 *      If SSH parameters are provided, it attempts to retrieve a persistent flag.
 *   3. Example:
 *        ./weak_netbios_ns_tool 192.168.0.10 137
 *        ./weak_netbios_ns_tool 192.168.0.10 22 root toor /root/persistent_flag.txt
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
 
 int send_weak_netbios_ns_data(const char *host, unsigned short port) {
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
     if(connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
         close(sock);
         return -3;
     }
     strcpy(buffer, "NETBIOS_NS_QUERY");
     send(sock, buffer, strlen(buffer), 0);
     memset(buffer, 0, sizeof(buffer));
     n = recv(sock, buffer, sizeof(buffer) - 1, 0);
     if(n > 0) {
         buffer[n] = '\0';
         printf("Received NetBIOS response: %s\n", buffer);
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
     sendto(sock, "ping", 4, 0, (struct sockaddr*)&target, sizeof(target));
     close(sock);
     return 1;
 }
 
 char* capture_flag(const char *host, unsigned short port) {
     static char flag[MAX_BUF];
     int sock;
     struct sockaddr_in srv;
     char buffer[MAX_BUF];
     socklen_t len = sizeof(srv);
     int n;
     sock = socket(AF_INET, SOCK_DGRAM, 0);
     if(sock < 0) return NULL;
     srv.sin_family = AF_INET;
     srv.sin_port = htons(port);
     if(inet_pton(AF_INET, host, &srv.sin_addr) <= 0) {
         close(sock);
         return NULL;
     }
     sendto(sock, "GET_FLAG", 8, 0, (struct sockaddr*)&srv, sizeof(srv));
     memset(buffer, 0, sizeof(buffer));
     n = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&srv, &len);
     if(n > 0) {
         buffer[n] = '\0';
         strncpy(flag, buffer, MAX_BUF-1);
     }
     close(sock);
     return flag;
 }
 
 /* Minimal SSH retrieval using system calls. */
 int capture_persistent_flag_ssh(const char *ip, const char *user, const char *pass, const char *path) {
     char cmd[512];
     snprintf(cmd, sizeof(cmd),
              "sshpass -p '%s' ssh -o StrictHostKeyChecking=no %s@%s 'cat %s' 2>/dev/null",
              pass, user, ip, path);
     FILE *fp = popen(cmd, "r");
     if(!fp) return 0;
     char out[MAX_BUF];
     memset(out, 0, sizeof(out));
     fread(out, 1, sizeof(out)-1, fp);
     pclose(fp);
     if(strlen(out) > 0) {
         printf("Captured persistent flag via SSH: %s\n", out);
         printf("Commands to access persistent flag:\n");
         printf("ssh %s@%s 'cat %s'\n", user, ip, path);
         return 1;
     }
     return 0;
 }
 
 int main(int argc, char *argv[]) {
     char data[] = "Sensitive NetBIOS NS Data";
     printf("Sending NetBIOS NS data in a weakly protected way: %s\n", data);
 
     if(argc < 3) {
         printf("Usage: %s <IP> <PORT> [SSH_USER] [SSH_PASS] [FLAG_PATH]\n", argv[0]);
         return 1;
     }
     const char *ip = argv[1];
     unsigned short port = atoi(argv[2]);
 
     if(!detect_exploit(ip, port)) {
         printf("Port %d closed/unreachable or UDP check not conclusive on %s.\n", port, ip);
     } else {
         printf("Attempted UDP check on port %d for %s.\n", port, ip);
     }
 
     if(send_weak_netbios_ns_data(ip, port) == 0) {
         printf("Weak NetBIOS NS data sent.\n");
     } else {
         printf("Failed to send NetBIOS NS data.\n");
     }
 
     char *found_flag = capture_flag(ip, port);
     if(found_flag && strlen(found_flag) > 0) {
         printf("Captured flag: %s\n", found_flag);
     } else {
         printf("No flag captured.\n");
     }
 
     if(argc > 5) {
         const char *ssh_user = argv[3];
         const char *ssh_pass = argv[4];
         const char *flag_path = argv[5];
         if(!capture_persistent_flag_ssh(ip, ssh_user, ssh_pass, flag_path)) {
             printf("SSH-based persistent flag not captured.\n");
         }
     }
 
     return 0;
 }