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

char* ReEncrypt(const char* ciphertext, const char* reEncryptionKey, const char* CCPATH){

    TimeVar t;

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized from : " << CCPATH << std::endl;
        }

    //  Deserialize the re-encryption key
    EvalKey<DCRTPoly> rk;
    if (!Serial::DeserializeFromFile(reEncryptionKey, rk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< reEncryptionKey << std::endl;
        }
        else{
        std::cout << "Re-encryption key has been deserialized from : " << reEncryptionKey << std::endl;
        }
    //  Deserialize the Ciphertext
    CT ct;
    std::string c =ciphertext; 
    std::stringstream ss(c);
    Serial::Deserialize(ct, ss, SerType::JSON);

    //  Re encrypt the ciphertext

    TIC(t);
    auto ct2 = cryptoContext->ReEncrypt(ct, rk);
    std::cout << "Re-Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    std::string result  = Serial::SerializeToString(ct2);
    return strcpy(new char[result.length() + 1], result.c_str());

    // // Serialize the ciphertext reencrypted
    // char path[200];
    // strcpy(path, destinationPath);
    // strcat(path,filename);
    // if (!strcmp(sertype, "JSON")){
    //     if (!Serial::SerializeToFile(path, ct2, SerType::JSON)) {
    //     std::cerr << "Error writing serialization of re encrypted ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Re encrypted Ciphertext has been serialized to JSON in : " << path << std::endl;
    //     }
    // } else if (!strcmp(sertype, "BINARY")){
    //     if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of re encrypted ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout <<"Re encrypted Ciphertext has been serialized to BINARY in : " << path << std::endl;
    //     }
    // } else{
    //     std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    // }
    


}
