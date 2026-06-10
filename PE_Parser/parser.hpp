#pragma once

#include "../wrapper/wraper.hpp"

#include <string>

class PE_PARSER {
    private:
        std::string fileName;
        PE_FILE pe;

    public:
        PE_PARSER(std::string name)
        {
            fileName = name;
        }

        bool isPEFile();
        bool parse();
        void print();

        std::string getMachineStr();
        std::string getMagicOptionalStr();
        std::string getSectionCharacteristicsStr(DWORD c);
        std::string getSubsystemStr();
};