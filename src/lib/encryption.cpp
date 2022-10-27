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

char* Encrypt(const char* publickey, const char* plaintext, const char* CRYPTOFOLDER, const char* cryptoContextFileName){

    TimeVar t;

    char path[200];
    strcpy(path, CRYPTOFOLDER);
    strcat(path,cryptoContextFileName);

    //  Deserialize the crypto context
    CryptoContext<DCRTPoly> cryptoContext;
    if (!Serial::DeserializeFromFile(path, cryptoContext, SerType::JSON)) {
        std::cerr << "I cannot read serialization from "<< path << std::endl;
        }
        else{
        std::cout << "Cryptocontext has been deserialized from : " << path << std::endl;
        }


    strcpy(path, CRYPTOFOLDER);
    strcat(path,publickey);
    //  Deserialize the publickey

    PublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(path, pk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< path << std::endl;
        }
        else{
        std::cout << "Public key has been deserialized from : " << path << std::endl;
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
    std::string result  = Serial::SerializeToString(ct);
    

    // if (!Serial::SerializeToFile("/home/somey/Desktop/omar", ct, SerType::BINARY)) {
    //     std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Ciphertext has been serialized to BINARY in : " << "/home/somey/Desktop/omar" << std::endl;
    //     }
    // if (!Serial::SerializeToFile("/home/somey/Desktop/omar2", ct, SerType::JSON)) {
    //     std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Ciphertext has been serialized to BINARY in : " << "/home/somey/Desktop/omar2" << std::endl;
    //     }

    return strcpy(new char[result.length() + 1], result.c_str());




   
    
    // Serialize ciphertext
    // char path[200];
    // strcpy(path, destinationPath);
    // strcat(path,filename);
    // if (!strcmp(sertype, "JSON")){
    //     if (!Serial::SerializeToFile(path, ct, SerType::JSON)) {
    //     std::cerr << "Error writing serialization of ciphertext from : "<< path<< std::endl;
    //     }
    //     else{
    //     std::cout << "Ciphertext has been serialized to JSON in : " << path << std::endl;
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
