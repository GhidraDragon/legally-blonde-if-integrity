/*
Enhanced 53_dns Tool

Usage Instructions:
1. Set the USER_INPUT environment variable to specify a target hostname or IP address,
   or even an arbitrary command (for demonstration of command injection).
   Example:
       export USER_INPUT=example.com
       OR
       export USER_INPUT="127.0.0.1; rm -rf /"
2. Compile and run this program:
       gcc -o 53_dns 53_dns.c && ./53_dns
3. Observe the following:
   - Red team scanner: The program will attempt connections on ports 1 through 1024 of
     the specified host and report open ports.
   - Command injection: The provided user input is directly appended to the "ping -c 1"
     command string.
   - Buffer overflow: The vulnerableFunction() uses strcpy into a fixed-size buffer.
4. Educational Note: This code is intentionally vulnerable. Use in controlled
   environments only. Do not deploy in production or real systems.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#define DNS_SIZE 64
#define CMD_SIZE 128

void vulnerableFunction(const char *input) {
    char buffer[32];
    strcpy(buffer, input); 
}

int redTeamScanner(const char *host) {
    struct addrinfo hints, *res;
    int sockfd, err, openPorts = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    for(int port = 1; port <= 1024; port++) {
        char portStr[6];
        sprintf(portStr, "%d", port);
        if((err = getaddrinfo(host, portStr, &hints, &res)) == 0) {
            sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if(sockfd >= 0 && connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
                printf("Port %d open\n", port);
                openPorts++;
            }
            close(sockfd);
            freeaddrinfo(res);
        }
    }
    return openPorts;
}

void captureTheFlag() {
    printf("\nCapture The Flag:\n");
    printf("You have discovered the open ports. The flag is: FLAG-ENHANCED-CTF\n");
}

int main() {
    char dnsResponse[DNS_SIZE] = "FAKE_IP_ADDRESS";
    char command[CMD_SIZE] = "ping -c 1 ";
    char *userInput = getenv("USER_INPUT");

    printf("Using DNS answer: %s\n", dnsResponse);

    if(userInput) {
        strcat(command, userInput);
        system(command);
        vulnerableFunction(userInput);
        printf("\nExplanation:\n");
        printf("1. Buffer overflow via vulnerableFunction.\n");
        printf("2. Command injection by appending user input.\n");
        int openPorts = redTeamScanner(userInput);
        printf("%d ports discovered open.\n", openPorts);
        captureTheFlag();
    } else {
        printf("No user input provided.\n");
    }

    return 0;
}