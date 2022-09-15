#include <iostream>

extern "C"{
    void cryptoContextBGVrnsGen(const char* CRYPTOFOLDER, const char* filename, const char* sertype, int plaintextModulus, int multiplicativeDepth);
}