
#define PROFILE
#include "crypto-context-bgvrns.hpp"
#include <iostream>
#include <openfhe.h>
#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

using namespace lbcrypto;

void cryptoContextBGVrnsGen(const char* CRYPTOFOLDER, const char* filename, int plaintextModulus, int multiplicativeDepth){ 

    TimeVar t;

  //  Set CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    //parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetPlaintextModulus(plaintextModulus);
    parameters.SetSecurityLevel(HEStd_128_classic);


    TIC(t);
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    std::cout << "Cryptocontext generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    std::cout << "\nThe cryptocontext has been generated." << std::endl;
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(PRE);
    // Crypto Context parameters
    std::cout << "p = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    std::cout << "r = " << cryptoContext->GetCryptoParameters()->GetDigitSize() << std::endl;
    
    // Serialize CryptoContext
    char path[200];
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    if (!Serial::SerializeToFile(path, cryptoContext, SerType::JSON)) {
        std::cerr << "Error writing serialization of Cryptocontext to : "<< path<< std::endl;
        }
        else{
        std::cout << "Cryptocontext has been serialized to JSON in : " << path << std::endl;
        }
    
}