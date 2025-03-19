#include <stdio.h>
#include <string.h>

int main() {
    char data[] = "Sensitive RDP Data";
    // Vulnerable: no encryption used
    printf("Sending RDP data in a weakly protected way: %s\n", data);
    return 0;
}