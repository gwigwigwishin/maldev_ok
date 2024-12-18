#include <iostream>

#include "DynamicInvoke.h"

HMODULE LoadDynamicModule(const char* moduleName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        hModule = LoadLibraryA(moduleName);
        if (!hModule) {
            std::cerr << "Erreur : Impossible de charger ou récupérer le module " << moduleName << std::endl;
        }
    }
    return hModule;
}

FARPROC GetDynamicFunction(HMODULE moduleHandle, const char* functionName) {
    if (!moduleHandle) {
        std::cerr << "Erreur : Module handle invalide pour la fonction " << functionName << std::endl;
        return nullptr;
    }
    FARPROC funcAddress = GetProcAddress(moduleHandle, functionName);
    if (!funcAddress) {
        std::cerr << "Erreur : Fonction " << functionName << " introuvable dans le module" << std::endl;
    }
    return funcAddress;
}

FARPROC GetDynamicFunctionFromModule(const char* moduleName, const char* functionName) {
    HMODULE hModule = LoadDynamicModule(moduleName);
    return GetDynamicFunction(hModule, functionName);
}
