/* 
Usage:
  g++ 443_https_enhanced.cpp -lssl -lcrypto -o 443_https
  ./443_https <host> <port>
*/

#include <iostream>
#include <string>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

bool validatePeerCertificate(SSL* ssl, const std::string& host) {
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) return false;
    long res = SSL_get_verify_result(ssl);
    if (res != X509_V_OK) {
        X509_free(cert);
        return false;
    }
    bool match = false;
    STACK_OF(GENERAL_NAME)* san_names = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names) {
        int san_count = sk_GENERAL_NAME_num(san_names);
        for (int i = 0; i < san_count; i++) {
            const GENERAL_NAME* current_name = sk_GENERAL_NAME_value(san_names, i);
            if (current_name->type == GEN_DNS) {
                char* dns_name = (char*)ASN1_STRING_get0_data(current_name->d.dNSName);
                if (dns_name && strcasecmp(dns_name, host.c_str()) == 0) {
                    match = true;
                    break;
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
    if(!match) {
        X509_NAME* subj = X509_get_subject_name(cert);
        int cn_index = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
        if (cn_index >= 0) {
            X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subj, cn_index);
            ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
            if (cn_asn1) {
                char* cn_str = (char*)ASN1_STRING_get0_data(cn_asn1);
                if (cn_str && strcasecmp(cn_str, host.c_str()) == 0) {
                    match = true;
                }
            }
        }
    }
    X509_free(cert);
    return match;
}

bool connectAndCaptureFlag(const std::string& host, int port, std::string& flag) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) return false;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) { SSL_CTX_free(ctx); return false; }

    struct hostent* server = gethostbyname(host.c_str());
    if(!server) { close(sock); SSL_CTX_free(ctx); return false; }

    sockaddr_in serv_addr;
    std::memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    std::memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock); SSL_CTX_free(ctx); return false;
    }

    SSL* ssl = SSL_new(ctx);
    if(!ssl) {
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host.c_str());

    if(SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    if(!validatePeerCertificate(ssl, host)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
        return false;
    }

    const char* req1 = "GET /flag HTTP/1.1\r\nHost: ";
    SSL_write(ssl, req1, std::strlen(req1));
    SSL_write(ssl, host.c_str(), host.size());
    const char* req2 = "\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, req2, std::strlen(req2));

    char buffer[4096];
    std::string response;
    int bytes;
    while((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = 0;
        response += buffer;
    }
    if(!response.empty()) flag = response;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return !flag.empty();
}

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    int port = 443;
    if(argc > 1) host = argv[1];
    if(argc > 2) port = std::stoi(argv[2]);

    std::cout << "Starting red team scanner (enhanced with minimal certificate checks).\n";
    std::cout << "Scanning " << host << " at port " << port << "...\n";
    std::cout << "Attempting to capture the flag.\n";

    std::string flag;
    if(connectAndCaptureFlag(host, port, flag)) {
        std::cout << "Flag captured: " << flag << "\n";
    } else {
        std::cout << "Failed to capture flag.\n";
    }

    std::cout << "Explanation: This scanner does enhanced certificate validation.\n";
    return 0;
}