#include <iostream>
extern "C"{
    void cryptoContextGen(const char* schemeName, const char* CRYPTOFOLDER, const char* filename, const char* sertype, int plaintextModulus, int multiplicativeDepth);
}