#define PROFILE  // for TIC TOC

#include "re-keygen.hpp"
#include "openfhe.h"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;

void ReKeyGen(const char * secretKey, const char* publicKey, const char* CRYPTOFOLDER, const char* filename, const char* sertype){

    TimeVar t;
    char path[200];
    strcpy(path, CRYPTOFOLDER);
    strcat(path,"cryptocontext.txt");

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< path << std::endl;
        }
        else{
        std::cout << "Cryptocontext  has been deserialized from : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from "<< path << std::endl;
        }
        else{
        std::cout << " Cryptocontext has been deserialized from : " << path << std::endl;
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
        std::cout << " Private key has been deserialized from :  " << secretKey << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(secretKey, sk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of private key from : "<< secretKey << std::endl;
        }
        else{
        std::cout <<" Private key has been deserialized from :  "<< secretKey << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }
    
    // Deserialize the public key
    PublicKey<DCRTPoly> pk;
    std::cout << "this is the publickey path : "<<publicKey << std::endl;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(publicKey, pk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< publicKey << std::endl;
        }
        else{
        std::cout << " Public key has been deserialized from : " << publicKey << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(publicKey, pk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from : "<< publicKey << std::endl;
        }
        else{
        std::cout << "Public Key has been deserialized from : "<< publicKey << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    std::cout << "\n"
              << "Generating proxy re-encryption key..." << std::endl;

    EvalKey<DCRTPoly> reencryptionKey;

    TIC(t);
    reencryptionKey = cryptoContext->ReKeyGen(sk, pk);
    std::cout << "Re-encryption Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    // Serialize the re-encryption key
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    if (!strcmp(sertype, "JSON")){
        if (!Serial::SerializeToFile(path, reencryptionKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of re-encryption key to :  "<< path<< std::endl;
        }
        else{
        std::cout <<" re-encryption key has been serialized to JSON in : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::SerializeToFile(path, reencryptionKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of re-encryption key to : "<< path<< std::endl;
        }
        else{
        std::cout << " re-encryption key has been serialized to BINARY in : " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    }
}