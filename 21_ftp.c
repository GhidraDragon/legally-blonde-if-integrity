#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void hidden() {
    printf("Secret function reached.\n");
    system("/bin/sh");
}

int checkPassword() {
    char pass[16];
    char secret[] = "CTFSecret";
    gets(pass); // no boundary check
    if (strcmp(pass, secret) == 0) {
        printf("Access granted.\n");
        hidden();
    } else {
        printf("Access denied.\n");
    }
    return 0;
}

int main() {
    char buf[32];
    gets(buf); // Vulnerable: no boundary check
    printf("Data: %s\n", buf);
    printf("Guess the password:\n");
    checkPassword();
    return 0;
}