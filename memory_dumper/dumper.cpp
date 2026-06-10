#include "dumper.hpp"

#include <psapi.h>
#include <ntstatus.h>
#include <stdio.h>
#include <TlHelp32.h>

HANDLE getHandle(DWORD pid){
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

NTSTATUS getModuleBase(DWORD pid, uintptr_t& address){
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if(snapshot == INVALID_HANDLE_VALUE){
        CloseHandle(snapshot);
        return STATUS_UNSUCCESSFUL; 
    }

    MODULEENTRY32 m;
    m.dwSize = sizeof(MODULEENTRY32);

    if(!Module32First(snapshot, &m)){
        CloseHandle(snapshot);
        return STATUS_UNSUCCESSFUL; 
    } 
        
    address = (uintptr_t)m.modBaseAddr;
    CloseHandle(snapshot);

    return STATUS_SUCCESS;
}

DWORD getSizeOfImage(HANDLE handle, LPCVOID baseAddress){
    DWORD e_lfanew;
    ReadProcessMemory(handle, (LPCVOID)((uintptr_t)baseAddress + 0x3C), &e_lfanew, sizeof(e_lfanew), 0);

    DWORD sizeOfImage;
    ReadProcessMemory(handle, (LPCVOID)((uintptr_t)baseAddress + e_lfanew + 0x50), &sizeOfImage, sizeof(sizeOfImage), 0);

    return sizeOfImage;
}

bool readProcess(HANDLE handle, LPCVOID baseAddress, BYTE dump[], DWORD sizeOfImage){
    return ReadProcessMemory(handle, baseAddress, dump, sizeOfImage, 0);
}

bool writeFile(char fileName[], BYTE buffer[], DWORD sizeOfImage){
    FILE* f = fopen(fileName, "wb");

    if(!f) return false;

    else{
        if(!fwrite(buffer, 1, sizeOfImage, f)) return false;
        fclose(f);
    }

    return true;
}

bool dump(DWORD pid){
    // 1. get handle
    HANDLE handle = getHandle(pid);
    
    // 2. get module base
    uintptr_t address;
    if(getModuleBase(pid, address) != STATUS_SUCCESS) return false;

    // 3. get the image size
    DWORD imageSize = getSizeOfImage(handle, (LPCVOID)address);

    // 4. get the raw memory of the process
    BYTE* dumpBuffer = new BYTE[imageSize];
    readProcess(handle, (LPCVOID)address, dumpBuffer, imageSize);

    // 5. reconstruct pe

    // 6. write the reconstructed PE in a executable file 
    char fullPath[MAX_PATH];
    GetModuleFileNameExA(handle, NULL, fullPath, MAX_PATH);

    char* name = strrchr(fullPath, '\\');
    name++; // skip the path and get only the file name

    writeFile(name, dumpBuffer, imageSize);
}