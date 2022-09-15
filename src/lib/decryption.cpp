#define PROFILE
#include <string>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "decryption.hpp"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;             // plaintext

using vecInt  = std::vector<int64_t>;  // vector of ints
using vecChar = std::vector<char>;     // vector of characters

const char* Decrypt(const char* secretKey, const char* ciphertext, const char* CCPATH, const char* sertype){

    TimeVar t;

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext  has been deserialized from : " << CCPATH << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized from : " << CCPATH << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    //  Deserialize the private key
    PrivateKey<DCRTPoly> sk;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(secretKey, sk, SerType::JSON)) {
        std::cerr << "I cannot read serialization of private key from : "<< secretKey << std::endl;
        }
        else{
        std::cout << "Private key has been deserialized from :  " << secretKey << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(secretKey, sk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of private key from : "<< secretKey << std::endl;
        }
        else{
        std::cout << "Private key has been deserialized from :  "<< secretKey << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    //  Deserialize the ciphertext
    CT ct;
    PT pt;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(ciphertext, ct, SerType::JSON)) {
        std::cerr << "I cannot read serialization of ciphertext from "<< ciphertext << std::endl;
        }
        else{
        std::cout << "Ciphertext has been deserialized from :  " << ciphertext << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(ciphertext, ct, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of ciphertetx from : "<< ciphertext << std::endl;
        }
        else{
        std::cout << "Ciphertext has been deserialized from : "<< ciphertext << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }


    //  Decryption
    TIC(t);
    cryptoContext->Decrypt(sk, ct, &pt);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    
    const char* result = pt->GetStringValue().c_str();
    return result;
    


}
