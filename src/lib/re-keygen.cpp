#define PROFILE  // for TIC TOC

#include "re-keygen.hpp"
#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"

using namespace lbcrypto;

using CT = Ciphertext<DCRTPoly>;  // ciphertext
using PT = Plaintext;

void ReKeyGen(const char * secretKey, const char* publicKey, const char* destinationPath){

    TimeVar t;
    char path[200];
    //  Deserialize the private key
    PrivateKey<DCRTPoly> sk;
    if (!Serial::DeserializeFromFile(secretKey, sk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of private key from : "<< secretKey << std::endl;
        }
        else{
        std::cout << "Private key has been deserialized from :  " << secretKey << std::endl;
        }
    // Get the crypto Context from secret key
    CryptoContext<DCRTPoly> cryptoContext;
    cryptoContext = sk.get()->GetCryptoContext();

    
    // Deserialize the public key
    PublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(publicKey, pk, SerType::BINARY)) {
        std::cerr << "I cannot read serialization of Public Key from : "<< publicKey << std::endl;
        }
        else{
        std::cout << "Public key has been deserialized from : " << publicKey << std::endl;
        }

    std::cout << "\n"
              << "Generating proxy re-encryption key..." << std::endl;

    EvalKey<DCRTPoly> reEncryptionKey;

    TIC(t);
    reEncryptionKey = cryptoContext->ReKeyGen(sk, pk);
    std::cout << "Re-encryption Key generation time: "
              << "\t" << TOC_MS(t) << " ms" << std::endl;

    // Serialize the re-encryption key

    strcpy(path, destinationPath);
    strcat(path,"-re-enc-key");
    if (!Serial::SerializeToFile(path, reEncryptionKey, SerType::BINARY)) {
        std::cerr << "Error writing serialization of re-encryption key to :  "<< path<< std::endl;
        }
        else{
        std::cout <<"Re-encryption key has been serialized to BINARY in : " << path << std::endl;
        }
}