#include "wrapper/wraper.hpp"
#include "PE_Parser/parser.hpp"

#include <stdlib.h>
#include <iostream>

int main(){
    PE_PARSER parser("gamingchair.exe");
    if(parser.isPEFile()){
        parser.parse();
        parser.print();
    }

    else std::cout << "no es PE" << std::endl;
}