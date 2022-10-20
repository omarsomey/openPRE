#define PROFILE

#include <string>
#include <iostream>
#include <sstream>

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

char* Decrypt(const char* secretKey, const char* ciphertext, const char* CCPATH){

    TimeVar t;

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext  has been deserialized from : " << CCPATH << std::endl;
        }

    //  Deserialize the private key
    PrivateKey<DCRTPoly> sk;
    if (!Serial::DeserializeFromFile(secretKey, sk, SerType::JSON)) {
        std::cerr << "I cannot read serialization of private key from : "<< secretKey << std::endl;
        }
        else{
        std::cout << "Private key has been deserialized from :  " << secretKey << std::endl;
        }

    //  Deserialize the ciphertext
    CT ct;
    PT pt;
    std::string c =ciphertext; 
    std::stringstream ss(c);
    Serial::Deserialize(ct, ss, SerType::JSON);



    //  Decryption
    TIC(t);
    cryptoContext->Decrypt(sk, ct, &pt);
    std::cout << "Decryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    
    std::string plaintext = pt->GetStringValue();
    return strcpy(new char[plaintext.length() + 1], plaintext.c_str());
    

}

