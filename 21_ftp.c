#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_BUFFER 2048

void hidden() {
    printf("Secret function reached.\n");
    system("/bin/sh");
}

int checkPassword() {
    char pass[16];
    char secret[] = "CTFSecret";
    fgets(pass, sizeof(pass), stdin);
    pass[strcspn(pass, "\n")] = 0;
    if (strcmp(pass, secret) == 0) {
        printf("Access granted.\n");
        hidden();
    } else {
        printf("Access denied.\n");
    }
    return 0;
}

int bannerCheck(const char *banner) {
    if (strstr(banner, "vsFTPd 2.3.4")) {
        printf("[!] Potential vsFTPd 2.3.4 backdoor vulnerability.\n");
        // Additional checks or exploit attempts would go here.
    } else if (strstr(banner, "ProFTPD")) {
        printf("[!] Potential ProFTPD vulnerabilities.\n");
    } else if (strstr(banner, "FileZilla")) {
        printf("[!] FileZilla server detected.\n");
    }
    return 0;
}

int attemptAnonymousLogin(int sock) {
    char buffer[MAX_BUFFER];
    char userCmd[] = "USER anonymous\r\n";
    char passCmd[] = "PASS test\r\n";
    memset(buffer, 0, sizeof(buffer));
    write(sock, userCmd, strlen(userCmd));
    read(sock, buffer, sizeof(buffer) - 1);
    memset(buffer, 0, sizeof(buffer));
    write(sock, passCmd, strlen(passCmd));
    int len = read(sock, buffer, sizeof(buffer) - 1);
    buffer[len] = '\0';
    if (strstr(buffer, "230")) {
        printf("[+] Anonymous login successful.\n");
        return 1;
    }
    printf("[-] Anonymous login failed.\n");
    return 0;
}

int attemptFlagRetrieval(int sock) {
    char buffer[MAX_BUFFER];
    char retrCmd[] = "RETR flag.txt\r\n";
    memset(buffer, 0, sizeof(buffer));
    write(sock, retrCmd, strlen(retrCmd));
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("FTP Response: %s\n", buffer);
        if (!strstr(buffer, "550")) {
            printf("[+] Possible flag data received.\n");
            return 1;
        }
    }
    return 0;
}

int ftpScan(char *target) {
    int sock;
    struct sockaddr_in addr;
    char buffer[MAX_BUFFER];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(21);
    addr.sin_addr.s_addr = inet_addr(target);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    read(sock, buffer, sizeof(buffer) - 1);
    printf("[*] Banner: %s\n", buffer);
    bannerCheck(buffer);

    if (attemptAnonymousLogin(sock)) {
        attemptFlagRetrieval(sock);
    }

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    char buf[32];
    if (argc > 1) {
        ftpScan(argv[1]);
    }
    fgets(buf, sizeof(buf), stdin);
    buf[strcspn(buf, "\n")] = 0;
    printf("Data: %s\n", buf);
    printf("Guess the password:\n");
    checkPassword();
    return 0;
}