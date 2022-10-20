#include "crypto.hpp"
#include <iostream>
#include <openfhe.h>
#include "crypto-context-bfvrns.hpp"
#include "crypto-context-bgvrns.hpp"


using namespace lbcrypto;


void cryptoContextGen(const char* schemeName, const char* CRYPTOFOLDER, const char* filename, int plaintextModulus, int multiplicativeDepth){
    if (!strcmp(schemeName, "BGV")){
        cryptoContextBGVrnsGen(CRYPTOFOLDER, filename, plaintextModulus, multiplicativeDepth);
    }
    else if (!strcmp(schemeName, "BFV")){
        cryptoContextBFVrnsGen(CRYPTOFOLDER, filename, plaintextModulus, multiplicativeDepth);
    }
    else{
        std::cerr << "Scheme Error: Undefined scheme name"
                  << std::endl;
    }
}
