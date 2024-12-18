#ifndef DYNAMIC_INVOKE_H
#define DYNAMIC_INVOKE_H

#include <windows.h>

// Charge une DLL ou retourne le handle si elle est d�j� charg�e
HMODULE LoadDynamicModule(const char* moduleName);

// R�cup�re une fonction depuis une DLL
FARPROC GetDynamicFunction(HMODULE moduleHandle, const char* functionName);

// Version combin�e : Charge la DLL si n�cessaire et retourne l'adresse de la fonction
FARPROC GetDynamicFunctionFromModule(const char* moduleName, const char* functionName);

#endif
