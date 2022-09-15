#include "crypto.hpp"
#include <iostream>
#include <openfhe.h>
#include "crypto-context-bfvrns.hpp"
#include "crypto-context-bgvrns.hpp"


using namespace lbcrypto;


void cryptoContextGen(const char* schemeName, const char* CRYPTOFOLDER, const char* filename, const char* sertype, int plaintextModulus, int multiplicativeDepth){
    std::cout << "This program requires the subdirectory `" << CRYPTOFOLDER << "' to exist, otherwise you will get "
              << "an error writing serializations." << std::endl;


    if (!strcmp(schemeName, "BGV")){
        cryptoContextBGVrnsGen(CRYPTOFOLDER, filename, sertype, plaintextModulus, multiplicativeDepth);
    }
    else if (!strcmp(schemeName, "BFV")){
        cryptoContextBFVrnsGen(CRYPTOFOLDER, filename, sertype, plaintextModulus, multiplicativeDepth);
    }
    else{
        std::cerr << "Scheme Error: Undefined scheme name"
                  << std::endl;
    }
}
