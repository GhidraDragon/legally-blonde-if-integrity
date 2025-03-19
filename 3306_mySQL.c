#include <stdio.h>
#include <string.h>

int main() {
    const char* user = "root";
    const char* pass = "password";
    printf("Connecting to MySQL with credentials: %s / %s\n", user, pass);
    // Hardcoded creds are a typical misconfiguration
    return 0;
}