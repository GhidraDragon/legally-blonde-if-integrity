#include <stdio.h>
#include <string.h>

int main() {
    char input[64];
    strcpy(input, "anything' OR '1'='1");
    
    char query[128];
    sprintf(query, "SELECT * FROM users WHERE name='%s'", input);
    printf("Vulnerable query: %s\n", query);
    return 0;
}