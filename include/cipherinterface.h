#pragma once
#include <cstdint>
#include <cstddef>

extern "C" {
    const char* cipherName();
    int keySize();
    int nonceSize();
    int encrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out);
    int decrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out);
    void generateKey(uint8_t* key);
}
