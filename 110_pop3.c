#include <stdio.h>

int main() {
    char buffer[16];
    gets(buffer); // No check for input length
    printf("Received: %s\n", buffer);
    return 0;
}