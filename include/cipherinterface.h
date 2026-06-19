#pragma once
#include <cstdint>
#include <cstddef>

#ifdef _WIN32
    #define CIPHER_EXPORT __declspec(dllexport)
#else
    #define CIPHER_EXPORT
#endif

extern "C" {
    CIPHER_EXPORT const char* cipherName();
    CIPHER_EXPORT int keySize();
    CIPHER_EXPORT int nonceSize();
    CIPHER_EXPORT int encrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out);
    CIPHER_EXPORT int decrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out);
    CIPHER_EXPORT void generateKey(uint8_t* key);
}
