#define PROFILE
#include "keygen.hpp"
#include <iostream>
#include <openfhe.h>
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

using namespace lbcrypto;


void keysGen(const char* CRYPTOFOLDER, const char* filename, const char* sertype){

    TimeVar t;

    char path[200];
    strcpy(path, CRYPTOFOLDER);
    strcat(path,"cryptocontext.txt");

    // Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CRYPTOFOLDER << std::endl;
        }
        else{
        std::cout << "\n" << "Cryptocontext has been deserialized from : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from "<< CRYPTOFOLDER << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized from :  " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
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
    strcat(path,"public-key.txt");
    if (!strcmp(sertype, "JSON")){
        if (!Serial::SerializeToFile(path, keyPair.publicKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of public key to :  "<< path<< std::endl;
        }
        else{
        std::cout << "Public key has been serialized to JSON in : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::SerializeToFile(path, keyPair.publicKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of public key to : "<< path<< std::endl;
        }
        else{
        std::cout << "Public key has been serialized to BINARY in : " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    }
    
    // Serialize the secret key
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    strcat(path,"private-key.txt");
    if (!strcmp(sertype, "JSON")){
        if (!Serial::SerializeToFile(path, keyPair.secretKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of private key to :  "<< path<< std::endl;
        }
        else{
        std::cout << "Private key has been serialized to JSON in : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::SerializeToFile(path, keyPair.secretKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of private key ro :  "<< path<< std::endl;
        }
        else{
        std::cout << "Private key has been serialized to BINARY to : " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    }
}