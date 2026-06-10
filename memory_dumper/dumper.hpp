#pragma once
#include <windows.h>

class PE_DUMPER {
    private:
        DWORD pid;
        HANDLE handle;
        uintptr_t baseAddress;
        DWORD imageSize;
        BYTE* dumpBuffer;

        NTSTATUS getModuleBase();
        DWORD getSizeOfImage();
        bool readProcess();
        bool reconstructPE();

    public:
        PE_DUMPER(DWORD pid);
        ~PE_DUMPER();
        bool dump();
};