#include <iostream>
#include <string>

bool validateCertificate(const std::string& cert) {
    // Vulnerable: ignoring the actual certificate check
    return true;
}

int main() {
    std::string cert = "untrusted_cert";
    if(validateCertificate(cert)) {
        std::cout << "Certificate accepted without validation.\n";
    }
    return 0;
}