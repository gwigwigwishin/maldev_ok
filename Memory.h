#ifndef INJECTION_H
#define INJECTION_H

#include <windows.h>

// D�claration de la fonction InjectShellcode
bool injectShellcode(LPVOID shellcode, SIZE_T shellcodeSize, DWORD targetPid);

#endif // INJECTION_H
