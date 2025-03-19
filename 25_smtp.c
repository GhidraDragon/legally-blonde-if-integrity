#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char userInput[64];
    strcpy(userInput, "mail@example.com\r\nRCPT TO: | rm -rf /");

    char sanitizedInput[64];
    int i, j = 0;
    for (i = 0; i < 63 && userInput[i] != '\0'; i++) {
        if (userInput[i] == '|' || userInput[i] == ';' || userInput[i] == '&'
            || userInput[i] == '\r' || userInput[i] == '\n') {
            continue;
        }
        sanitizedInput[j++] = userInput[i];
    }
    sanitizedInput[j] = '\0';

    FILE *fp = popen("/usr/sbin/sendmail -t", "w");
    if (fp) {
        fputs(sanitizedInput, fp);
        pclose(fp);
    }
    return 0;
}