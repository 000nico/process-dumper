#include "parser.hpp"
#include "../wrapper/wraper.hpp"
#include "../sdk/sdk.hpp"

#include <iostream>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

bool PE_PARSER::isPEFile(){
    FILE* file = fopen(fileName.c_str(), "rb");
    bool flag = false;

    if(!file)
        flag = false;

    else{
        WORD magic;

        // check magic (e_magic)
        if(fread(&magic, sizeof(magic), 1, file)){
            if(magic == 0x5A4D){
                fseek(file, 0x3C, SEEK_SET);

                DWORD e_lfanew;
                if(fread(&e_lfanew, sizeof(e_lfanew), 1, file)){
                    fseek(file, e_lfanew, SEEK_SET); // jump to PE header

                    DWORD signature;

                    if(fread(&signature, sizeof(signature), 1, file)){
                        if(signature == 0x4550)
                            flag = true;
                    }
                }
            }
        }

        fclose(file);
    }

    return flag;
}

bool PE_PARSER::parse(){
    FILE* file = fopen(fileName.c_str(), "rb");

    if(!file) return false;

    else{
        // DOS MZ HEADER
        read_at(file, 0x00, pe.mz);
        read_at(file, 0x3C, pe.e_lfanew);
        read_at(file, pe.e_lfanew, pe.signature);

        // PE HEADER
        read_at(file, pe.e_lfanew + 0x04, pe.machine);
        read_at(file, pe.e_lfanew + 0x06, pe.number_of_sections);
        read_at(file, pe.e_lfanew + 0x0C, pe.pointer_to_symbol_table);
        read_at(file, pe.e_lfanew + 0x10, pe.number_of_symbols);
        read_at(file, pe.e_lfanew + 0x14, pe.size_of_optional_header);
        read_at(file, pe.e_lfanew + 0x16, pe.characteristics);

        // OPTIONAL HEADER
        read_at(file, pe.e_lfanew + 0x18, pe.magic_optional);
        read_at(file, pe.e_lfanew + 0x28, pe.entry_point);
        read_at(file, pe.e_lfanew + 0x50, pe.size_of_image);
        read_at(file, pe.e_lfanew + 0x54, pe.size_of_headers);
        if(pe.magic_optional == 0x20B) read_at(file, pe.e_lfanew + 0x5C, pe.subsystem); // x64
        else read_at(file, pe.e_lfanew + 0x44, pe.subsystem); // x86

        if(pe.magic_optional == 0x20B) read_at(file, pe.e_lfanew + 0x30, pe.image_base); // x64
        
        else{
            DWORD ib32;
            read_at(file, pe.e_lfanew + 0x1C, ib32);          // x86
            pe.image_base = ib32;
        }


        // SECTIONS
        long base = pe.e_lfanew + 0x18 + pe.size_of_optional_header;
        
        for(int i = 0; i < pe.number_of_sections; i++){
            SECTION s;

            read_at(file, base, s.name);
            read_at(file, base + 0x08, s.virtual_size);
            read_at(file, base + 0x0C, s.virtual_address);
            read_at(file, base + 0x10, s.raw_size);
            read_at(file, base + 0x14, s.raw_address);
            read_at(file, base + 0x18, s.relocations_address);
            read_at(file, base + 0x1C, s.line_numbers_address);
            read_at(file, base + 0x20, s.number_of_relocations);
            read_at(file, base + 0x22, s.number_of_line_numbers);
            read_at(file, base + 0x24, s.characteristics);

            base += 0x28;

            pe.sections.push_back(s);
        }

        fclose(file);
    }

    return true;
}

std::string PE_PARSER::getMachineStr(){
    switch(pe.machine){
        case 0x014C: return "x86";
        case 0x8664: return "x64 (AMD64)";
        case 0xAA64: return "ARM64";
        case 0x01C4: return "ARM";
        case 0x0200: return "IA-64";
        default:     return "Unknown (0x" + std::to_string(pe.machine) + ")";
    }
}

std::string PE_PARSER::getMagicOptionalStr(){
    switch(pe.magic_optional){
        case 0x10B: return "PE32 (x86)";
        case 0x20B: return "PE32+ (x64)";
        case 0x107: return "ROM";
        default:    return "Unknown (0x" + std::to_string(pe.magic_optional) + ")";
    }
}

std::string PE_PARSER::getSectionCharacteristicsStr(DWORD c){
    std::string result;
    if(c & 0x00000020) result += "CODE | ";
    if(c & 0x00000040) result += "INITIALIZED_DATA | ";
    if(c & 0x00000080) result += "UNINITIALIZED_DATA | ";
    if(c & 0x20000000) result += "EXECUTE | ";
    if(c & 0x40000000) result += "READ | ";
    if(c & 0x80000000) result += "WRITE | ";

    if(!result.empty())
        result = result.substr(0, result.size() - 3);
    return result;
}

std::string PE_PARSER::getSubsystemStr(){
    switch(pe.subsystem){
        case 0x02: return "GUI";
        case 0x03: return "Console";
        case 0x01: return "Native";
        case 0x05: return "OS/2";
        case 0x07: return "POSIX";
        case 0x09: return "Windows CE";
        case 0x0A: return "EFI Application";
        default:   return "Unknown (0x" + std::to_string(pe.subsystem) + ")";
    }
}

void PE_PARSER::print(){
    std::cout << "File: " << fileName << std::endl;

    // DOS MZ HEADER
    std::cout << "\nMZ: 0x" << std::hex << pe.mz << std::endl;
    std::cout << "e_lfanew: 0x" << pe.e_lfanew << std::endl;

    // PE HEADER
    std::cout << "\nMachine: " << getMachineStr() << std::endl;
    std::cout << "Signature: " << pe.signature << std::endl;
    std::cout << "Number of sections: " << std::dec << pe.number_of_sections << std::endl;
    std::cout << "Pointer to symbol table: 0x" << std::hex << pe.pointer_to_symbol_table << std::endl;
    std::cout << "Size of optional header: " << std::dec << pe.size_of_optional_header << std::endl;
    std::cout << "Characteristics: " << std::endl;
    if(pe.characteristics & 0x0002) std::cout << "  - Executable\n";
    if(pe.characteristics & 0x0020) std::cout << "  - Large address aware\n";
    if(pe.characteristics & 0x0100) std::cout << "  - 32-bit\n";
    if(pe.characteristics & 0x2000) std::cout << "  - DLL\n";
    if(pe.characteristics & 0x0001) std::cout << "  - No relocations\n";

    // OPTIONAL HEADER
    std::cout << "\nEntry point: " << std::hex << pe.entry_point << std::endl;
    std::cout << "Image base: 0x" << pe.image_base << std::endl;
    std::cout << "Size of image: " << std::dec << pe.size_of_image << std::endl;
    std::cout << "Size of headers: " << pe.size_of_headers << std::endl;
    std::cout << "Magic optional: " << getMagicOptionalStr() << std::endl;
    std::cout << "Subsystem: " << getSubsystemStr() << std::endl;;
 
    // SECTIONS
    std::cout << "\n=== SECTIONS ===\n";
    for(const SECTION& s : pe.sections){
        std::cout << "\n[" << (char*)s.name << "]\n";
        std::cout << "  Virtual size:    0x" << std::hex << s.virtual_size << '\n';
        std::cout << "  Virtual address: 0x" << s.virtual_address << '\n';
        std::cout << "  Raw size:        0x" << s.raw_size << '\n';
        std::cout << "  Raw address:     0x" << s.raw_address << '\n';
        std::cout << "  Characteristics: " << getSectionCharacteristicsStr(s.characteristics) << '\n';
    }
}