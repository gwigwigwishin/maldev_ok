#ifndef DYNAMIC_INVOKE_H
#define DYNAMIC_INVOKE_H

#include <windows.h>

// Charge une DLL ou retourne le handle si elle est déjà chargée
HMODULE LoadDynamicModule(const char* moduleName);

// Récupère une fonction depuis une DLL
FARPROC GetDynamicFunction(HMODULE moduleHandle, const char* functionName);

// Version combinée : Charge la DLL si nécessaire et retourne l'adresse de la fonction
FARPROC GetDynamicFunctionFromModule(const char* moduleName, const char* functionName);

#endif
