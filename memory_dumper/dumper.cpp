#include "dumper.hpp"

#include <psapi.h>
#include <ntstatus.h>
#include <stdio.h>
#include <TlHelp32.h>

PE_DUMPER::PE_DUMPER(DWORD pid) : pid(pid), handle(NULL), baseAddress(0), imageSize(0), dumpBuffer(nullptr) {}

PE_DUMPER::~PE_DUMPER(){
    delete[] dumpBuffer;
    if(handle) CloseHandle(handle);
}

NTSTATUS PE_DUMPER::getModuleBase(){
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if(snapshot == INVALID_HANDLE_VALUE) return STATUS_UNSUCCESSFUL;

    MODULEENTRY32 m;
    m.dwSize = sizeof(MODULEENTRY32);

    if(!Module32First(snapshot, &m)){
        CloseHandle(snapshot);
        return STATUS_UNSUCCESSFUL;
    }

    baseAddress = (uintptr_t)m.modBaseAddr;
    CloseHandle(snapshot);
    return STATUS_SUCCESS;
}

DWORD PE_DUMPER::getSizeOfImage(){
    DWORD e_lfanew;
    ReadProcessMemory(handle, (LPCVOID)(baseAddress + 0x3C), &e_lfanew, sizeof(e_lfanew), 0);
    DWORD size;
    ReadProcessMemory(handle, (LPCVOID)(baseAddress + e_lfanew + 0x50), &size, sizeof(size), 0);
    return size;
}

bool PE_DUMPER::readProcess(){
    return ReadProcessMemory(handle, (LPCVOID)baseAddress, dumpBuffer, imageSize, 0);
}

bool PE_DUMPER::reconstructPE(){
    DWORD e_lfanew = *(DWORD*)(dumpBuffer + 0x3C);
    WORD numSections = *(WORD*)(dumpBuffer + e_lfanew + 0x06);
    WORD sizeOfOptionalHeader = *(WORD*)(dumpBuffer + e_lfanew + 0x14);
    DWORD sectionBase = e_lfanew + 0x18 + sizeOfOptionalHeader;

    for(int i = 0; i < numSections; i++){
        DWORD virtualAddress = *(DWORD*)(dumpBuffer + sectionBase + 0x0C);
        DWORD rawAddress     = *(DWORD*)(dumpBuffer + sectionBase + 0x14);
        DWORD rawSize        = *(DWORD*)(dumpBuffer + sectionBase + 0x10);

        if(rawAddress && rawSize)
            memcpy(dumpBuffer + rawAddress, dumpBuffer + virtualAddress, rawSize);

        sectionBase += 0x28;
    }
    return true;
}

bool PE_DUMPER::dump(){
    // 1. get handle
    handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(!handle) return false;

    // 2. get module base
    if(getModuleBase() != STATUS_SUCCESS) return false;

    // 3. get image size
    imageSize = getSizeOfImage();
    if(!imageSize) return false;

    // 4. read process memory
    dumpBuffer = new BYTE[imageSize];
    if(!readProcess()) return false;

    // 5. reconstruct PE
    reconstructPE();

    // 6. write file
    char fullPath[MAX_PATH];
    GetModuleFileNameExA(handle, NULL, fullPath, MAX_PATH);
    char* name = strrchr(fullPath, '\\');
    if(name) name++;

    FILE* f = fopen(name, "wb");
    if(!f) return false;
    fwrite(dumpBuffer, 1, imageSize, f);
    fclose(f);

    return true;
}