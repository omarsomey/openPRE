#define PROFILE
#include <string>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "encryption.hpp"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;             // plaintext

using vecInt  = std::vector<int64_t>;  // vector of ints
using vecChar = std::vector<char>;     // vector of characters

void Encrypt(const char* publickey, const char* plaintext, const char* CCPATH, const char* destinationPath, const char* filename, const char* sertype){

    TimeVar t;

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized " << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(CCPATH, cryptoContext, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from "<< CCPATH << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized " << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    //  Deserialize the publickey
    PublicKey<DCRTPoly> pk;
    if (!strcmp(sertype, "JSON")){
        if (!Serial::DeserializeFromFile(publickey, pk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< publickey << std::endl;
        }
        else{
        std::cout << "Public key has been deserialized from : " << publickey << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::DeserializeFromFile(publickey, pk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from : "<< publickey << std::endl;
        }
        else{
        std::cout << "Public Key has been deserialized from : "<< publickey << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<< sertype <<std::endl;
    }

    //  Create a plaintext object from string input
    std::string strplaintext = plaintext;
    
    Plaintext pt = cryptoContext->MakeStringPlaintext(strplaintext);

    //  Encryption
    TIC(t);
    auto ct = cryptoContext->Encrypt(pk, pt);
    std::cout << "Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    
    std::cout << "PLaintext is : "<< pt->GetStringValue() << std::endl;
    // std::string ciphertext  = Serial::SerializeToString(ct);
    
    // Serialize ciphertext
    char path[200];
    strcpy(path, destinationPath);
    strcat(path,filename);
    if (!strcmp(sertype, "JSON")){
        if (!Serial::SerializeToFile(path, ct, SerType::JSON)) {
        std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
        }
        else{
        std::cout << "Ciphertext has been serialized to JSON in : " << path << std::endl;
        }
    } else if (!strcmp(sertype, "BINARY")){
        if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
        }
        else{
        std::cout <<"Ciphertext has been serialized to BINARY in : " << path << std::endl;
        }
    } else{
        std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    }
    


}
