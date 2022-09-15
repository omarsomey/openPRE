#define PROFILE
#include <string>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "re-encryption.hpp"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;             // plaintext

using vecInt  = std::vector<int64_t>;  // vector of ints
using vecChar = std::vector<char>;     // vector of characters

void ReEncrypt(const char* ciphertext, const char* reEncryptionKey, const char* CCPATH, const char* destinationPath, const char* filename, const char* sertype){

    TimeVar t;

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized from : " << CCPATH << std::endl;
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

    //  Deserialize the re-encryption key
    EvalKey<DCRTPoly> rk;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(reEncryptionKey, rk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< reEncryptionKey << std::endl;
        }
        else{
        std::cout << "Re-encryption key has been deserialized from : " << reEncryptionKey << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(reEncryptionKey, rk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from : "<< reEncryptionKey << std::endl;
        }
        else{
        std::cout << "Re-encryption key has been deserialized from : "<< reEncryptionKey << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }
    //  Deserialize the Ciphertext
    CT ct;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(ciphertext, ct, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< ciphertext << std::endl;
        }
        else{
        std::cout << "Re-encryption key has been deserialized from : " << ciphertext << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(ciphertext, ct, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from : "<< ciphertext << std::endl;
        }
        else{
        std::cout << "Re-encryption key has been deserialized from : "<< ciphertext << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    //  Re encrypt the ciphertext

    TIC(t);
    auto ct2 = cryptoContext->ReEncrypt(ct, rk);
    std::cout << "Re-Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    // Serialize the ciphertext reencrypted
    char path[200];
    strcpy(path, destinationPath);
    strcat(path,filename);
    if (!strcmp(sertype, "JSON")){
        if (!Serial::SerializeToFile(path, ct2, SerType::JSON)) {
        std::cerr << "Error writing serialization of re encrypted ciphertext from : "<< path<< std::endl;
        }
        else{
        std::cout << "Re encrypted Ciphertext has been serialized to JSON in : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
        std::cerr << "Error writing serialization of re encrypted ciphertext from : "<< path<< std::endl;
        }
        else{
        std::cout <<"Re encrypted Ciphertext has been serialized to BINARY in : " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    }
    


}
