/*
 * 110_pop3.c
 *
 * Usage:
 *   1. Compile:   gcc -o 110_pop3 110_pop3.c
 *   2. Run:       ./110_pop3
 *   3. Connect:   nc 127.0.0.1 110   (or use telnet)
 *
 * Description:
 *   - This program listens on TCP port 110 (POP3 port).
 *   - On a successful connection, it duplicates the accepted socket
 *     to stdin and uses gets() with no length check (intentionally
 *     vulnerable).
 *   - After reading input from the client, it prints the received
 *     message. This demonstrates how an unchecked buffer read can
 *     be exploited via network input.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
 int main() {
     int sockfd, newfd;
     struct sockaddr_in server_addr, client_addr;
     socklen_t client_len = sizeof(client_addr);
 
     /* Create socket */
     sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) {
         perror("socket");
         return 1;
     }
 
     /* Bind to port 110 */
     memset(&server_addr, 0, sizeof(server_addr));
     server_addr.sin_family = AF_INET;
     server_addr.sin_port = htons(110);
     server_addr.sin_addr.s_addr = INADDR_ANY;
     if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
         perror("bind");
         close(sockfd);
         return 1;
     }
 
     /* Listen */
     if (listen(sockfd, 1) < 0) {
         perror("listen");
         close(sockfd);
         return 1;
     }
 
     printf("Listening on port 110...\n");
 
     /* Accept a connection */
     newfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
     if (newfd < 0) {
         perror("accept");
         close(sockfd);
         return 1;
     }
 
     /* Redirect socket to stdin (so gets reads directly from the network) */
     dup2(newfd, STDIN_FILENO);
 
     /* Original vulnerable code (unchanged parts) */
     char buffer[16];
     gets(buffer); // No check for input length
     printf("Received: %s\n", buffer);
 
     /* Clean up */
     close(newfd);
     close(sockfd);
     return 0;
 }