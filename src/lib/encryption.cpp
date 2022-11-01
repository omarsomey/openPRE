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

void Encrypt(const char* publickey, const char* plaintext, const char* destinationPath){

    TimeVar t;

    //  Deserialize the publickey
    PublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(publickey, pk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of Public key from : "<< publickey << std::endl;
        }
        else{
        std::cout << "Public key has been deserialized from : " << publickey << std::endl;
        }

    // Get the crypto context from pk
    CryptoContext<DCRTPoly> cryptoContext;
    cryptoContext = pk.get()->GetCryptoContext();


    //  Create a plaintext object from string input
    std::string strplaintext = plaintext;
    
    Plaintext pt = cryptoContext->MakeStringPlaintext(strplaintext);    

    //  Encryption
    TIC(t);
    auto ct = cryptoContext->Encrypt(pk, pt);
    std::cout << "Encryption time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;
    
    std::cout << "PLaintext is : "<< pt->GetStringValue() << std::endl;

    // Serialize ciphertext in BINARY

    if (!Serial::SerializeToFile(destinationPath, ct, SerType::BINARY)) {
        std::cerr << "Error writing serialization of ciphertext from : "<< destinationPath<< std::endl;
        }
        else{
        std::cout << "Ciphertext has been serialized to BINARY in : " << destinationPath << std::endl;
        }





   
    
    // Serialize ciphertext
    // char path[200];
    // strcpy(path, destinationPath);
    // strcat(path,filename);
    // if (!strcmp(sertype, "BINARY")){
    //     if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Ciphertext has been serialized to BINARY in : " << path << std::endl;
    //     }
    // } else if (!strcmp(sertype, "BINARY")){
    //     if (!Serial::SerializeToFile(path, ct, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Ciphertext has been serialized to BINARY in : " << path << std::endl;
    //     }
    // } else{
    //     std::cerr << "Error in the serialization type :"<<sertype<<std::endl;
    // }
    


}
