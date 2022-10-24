#define PROFILE  // for TIC TOC

#include "re-keygen.hpp"
#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;

void ReKeyGen(const char * secretKey, const char* publicKey, const char* CRYPTOFOLDER, const char* cryptoContextFileName, const char* filename){

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
        std::cout << "Cryptocontext  has been deserialized from : " << path << std::endl;
        }


    strcpy(path, CRYPTOFOLDER);
    strcat(path,secretKey);
    //  Deserialize the private key
    PrivateKey<DCRTPoly> sk;
    if (!Serial::DeserializeFromFile(path, sk, SerType::JSON)) {
        std::cerr << "I cannot read serialization of private key from : "<< path << std::endl;
        }
        else{
        std::cout << "Private key has been deserialized from :  " << path << std::endl;
        }
    

    strcpy(path, CRYPTOFOLDER);
    strcat(path,publicKey);
    // Deserialize the public key
    PublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(path, pk, SerType::JSON)) {
        std::cerr << "I cannot read serialization from : "<< path << std::endl;
        }
        else{
        std::cout << "Public key has been deserialized from : " << path << std::endl;
        }

    std::cout << "\n"
              << "Generating proxy re-encryption key..." << std::endl;

    EvalKey<DCRTPoly> reEncryptionKey;

    TIC(t);
    reEncryptionKey = cryptoContext->ReKeyGen(sk, pk);
    std::cout << "Re-encryption Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    // Serialize the re-encryption key
    strcpy(path, CRYPTOFOLDER);
    strcat(path,filename);
    strcat(path,"-re-enc-key.json");
    if (!Serial::SerializeToFile(path, reEncryptionKey, SerType::JSON)) {
        std::cerr << "Error writing serialization of re-encryption key to :  "<< path<< std::endl;
        }
        else{
        std::cout <<"Re-encryption key has been serialized to JSON in : " << path << std::endl;
        }
}