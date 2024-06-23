#include <Windows.h>
#include <stdio.h>

const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";

DWORD PID, TID;
HANDLE hProcess, hThread = NULL;
HMODULE hKernel32 = NULL;
LPVOID rBuffer = NULL;

wchar_t dllPath[MAX_PATH] = L"Y:\\Cybersecurity\\Memory Injection\\test.dll";

int main(int argc, char* argv[]) {
    if(argc<2){
        printf("%s usage error", e);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    printf("%s opening handle to PID (%ld)\n", i,  PID);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if(hProcess==NULL){
        printf("%s handle could not be opened. error: (%ld)", e, GetLastError());
        return EXIT_FAILURE;
    }
    printf("%s handle opened -> 0x%p\n", i,  hProcess);
    
    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    printf("%s memory allocated: %zd bytes", k, sizeof(dllPath));

    WriteProcessMemory(hProcess, rBuffer, dllPath, sizeof(dllPath), NULL);
    printf("%s dll injected", k);

    hKernel32 = GetModuleHandleW(L"Kernel32");
    if(hKernel32==NULL){
        printf("%s kernel could not be opened. error: (%ld)", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    printf("%s got handle to Kernel32 -> 0x%p\n", i,  hKernel32);

    LPTHREAD_START_ROUTINE startAdrr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    
    hThread = CreateRemoteThread(hProcess, NULL, 0, startAdrr, rBuffer, 0, 0);
    if(hKernel32==NULL){
        printf("%s thread could not be opened. error: (%ld)", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }
    printf("%s thread started -> 0x%p\n", i,  hThread);

    WaitForSingleObject(hThread, INFINITE);
    printf("%s thread finished \n", k);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}