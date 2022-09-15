#include <iostream>

extern "C"{
    void cryptoContextBFVrnsGen(const char* CRYPTOFOLDER, const char* filename, const char* sertype, int plaintextModulus, int multiplicativeDepth);
}