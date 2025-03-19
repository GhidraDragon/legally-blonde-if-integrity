#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_SIZE 64
#define CMD_SIZE 128

void vulnerableFunction(const char *input) {
    char buffer[32];
    strcpy(buffer, input); // Intentional overflow
}

int main() {
    char dnsResponse[DNS_SIZE] = "FAKE_IP_ADDRESS";
    char command[CMD_SIZE] = "ping -c 1 ";
    char *userInput = getenv("USER_INPUT"); // Arbitrary input

    // Vulnerable: blindly trusts the response
    printf("Using DNS answer: %s\n", dnsResponse);

    if(userInput) {
        // Command injection vulnerability
        strcat(command, userInput);
        system(command);

        // Buffer overflow vulnerability
        vulnerableFunction(userInput);
    } else {
        printf("No user input provided.\n");
    }

    return 0;
}