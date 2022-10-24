#define PROFILE
#include "keygen.hpp"
#include <iostream>
#include <openfhe.h>
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

using namespace lbcrypto;


void keysGen(const char* CRYPTOFOLDER, const char* cryptoContextFileName, const char* filename){

    TimeVar t;

    char path[200];
    strcpy(path, CRYPTOFOLDER);
    strcat(path,cryptoContextFileName);
    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::JSON)) {
            std::cerr << "I cannot read serialization from "<< path << std::endl;
        }
        else{
            std::cout << "\n" << "Cryptocontext has been deserialized from : " << path << std::endl;
        }
    
    
    // Generate Key Pair

    // Initialize Key Pair Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair 
    TIC(t);
    keyPair = cryptoContext->KeyGen();
    std::cout << "Keys generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    std::cout << "The key pairs has been generated." << std::endl;

    // Serialize key pairs

    // Serialize the public key
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    strcat(path,"-public-key.json");
    if (!Serial::SerializeToFile(path, keyPair.publicKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of public key to :  "<< path<< std::endl;
        }
        else{
        std::cout << "Public key has been serialized to JSON in : " << path << std::endl;
        }
    
    // Serialize the secret key
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    strcat(path,"-private-key.json");
    if (!Serial::SerializeToFile(path, keyPair.secretKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of private key to :  "<< path<< std::endl;
        }
        else{
        std::cout << "Private key has been serialized to JSON in : " << path << std::endl;
        }
}