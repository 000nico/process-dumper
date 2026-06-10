#pragma once
#include <windows.h>
#include <vector>

class SECTION {
    public:
        BYTE name[8];

        DWORD virtual_size;
        DWORD virtual_address;

        DWORD raw_size;
        DWORD raw_address;

        DWORD relocations_address;
        DWORD line_numbers_address;
        WORD number_of_relocations;
        WORD number_of_line_numbers;

        DWORD characteristics;
};

class PE_FILE {
    public:
        // DOS MZ Header
        WORD mz;
        DWORD e_lfanew; // file address to PE Header

        // PE Header
        DWORD signature;
        WORD machine;
        WORD number_of_sections;
        DWORD pointer_to_symbol_table;
        WORD number_of_symbols;
        WORD size_of_optional_header;
        WORD characteristics;

        // Optional Header
        WORD magic_optional;
        DWORD entry_point;
        ULONGLONG image_base;
        DWORD size_of_image;
        DWORD size_of_headers;
        WORD subsystem;
        
        // Section header <- starts immediatly after the optional header (+F8 in the PE Header). The second header comes after the first header, there are so many sections as NumberOfSection gives.
        std::vector<SECTION> sections;

        void print();
};

