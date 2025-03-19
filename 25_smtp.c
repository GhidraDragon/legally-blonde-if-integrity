#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char userInput[64];
    strcpy(userInput, "mail@example.com\r\nRCPT TO: | rm -rf /"); 
    // A malicious SMTP command injection
    
    char command[128];
    sprintf(command, "echo \"%s\" | sendmail -t", userInput);
    system(command); // Vulnerable approach
    return 0;
}