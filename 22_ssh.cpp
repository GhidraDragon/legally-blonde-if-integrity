#include <iostream>
#include <string>

bool verifyHostKey(const std::string& key) {
    // Vulnerable: always returns true
    return true;
}

int main() {
    std::string serverKey = "some_unverified_key";
    if(verifyHostKey(serverKey)) {
        std::cout << "Connected without proper verification.\n";
    }
    return 0;
}