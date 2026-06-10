#include "wrapper/wraper.hpp"
#include "PE_Parser/parser.hpp"
#include "memory_dumper/dumper.hpp"

#include <stdlib.h>
#include <iostream>
#include <psapi.h>

int main(int argc, char* argv[]){
    if(argc < 2){
        std::cout << "Usage: process_dumper.exe <PID>" << std::endl;
        return 1;
    }

    DWORD pid = atoi(argv[1]);

    // dump
    std::cout << "Dumping process " << pid << "..." << std::endl;
    PE_DUMPER dumper(pid);
    if(!dumper.dump()){
        std::cout << "Failed to dump process" << std::endl;
        return 1;
    }
    std::cout << "Dump successful" << std::endl;

    // parse
    // el dumper escribe <nombre>.exe, hay que conseguir el nombre
    char fullPath[MAX_PATH];
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    GetModuleFileNameExA(handle, NULL, fullPath, MAX_PATH);
    CloseHandle(handle);
    char* name = strrchr(fullPath, '\\');
    if(name) name++;

    PE_PARSER parser(name);
    if(parser.isPEFile()){
        parser.parse();
        parser.print();
    }
    else std::cout << "no es PE" << std::endl;

    return 0;
}