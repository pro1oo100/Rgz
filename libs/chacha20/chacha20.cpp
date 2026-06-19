#include "cipher_interface.h"
#include <cstring>
#include <cstdlib>
#include <ctime>

static void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8)  | (d >> 24);
    c += d; b ^= c; b = (b << 7)  | (b >> 25);
}

extern "C" {

const char* cipherName() { return "ChaCha20"; }
int keySize() { return 32; }
int nonceSize() { return 12; }

int encrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++)
        state[4 + i] = key[4*i] | (key[4*i+1] << 8) | (key[4*i+2] << 16) | (key[4*i+3] << 24);

    state[12] = 0;
    for (int i = 0; i < 3; i++)
        state[13 + i] = nonce[4*i] | (nonce[4*i+1] << 8) | (nonce[4*i+2] << 16) | (nonce[4*i+3] << 24);

    size_t offset = 0;
    while (offset < inLen) {
        uint32_t working[16];
        for (int i = 0; i < 16; i++) working[i] = state[i];

        for (int i = 0; i < 10; i++) {
            quarterRound(working[0], working[4], working[8],  working[12]);
            quarterRound(working[1], working[5], working[9],  working[13]);
            quarterRound(working[2], working[6], working[10], working[14]);
            quarterRound(working[3], working[7], working[11], working[15]);
            quarterRound(working[0], working[5], working[10], working[15]);
            quarterRound(working[1], working[6], working[11], working[12]);
            quarterRound(working[2], working[7], working[8],  working[13]);
            quarterRound(working[3], working[4], working[9],  working[14]);
        }

        uint8_t block[64];
        for (int i = 0; i < 16; i++) {
            uint32_t val = working[i] + state[i];
            block[4*i]   = val & 0xFF;
            block[4*i+1] = (val >> 8) & 0xFF;
            block[4*i+2] = (val >> 16) & 0xFF;
            block[4*i+3] = (val >> 24) & 0xFF;
        }

        size_t blockLen = (inLen - offset > 64) ? 64 : inLen - offset;
        for (size_t i = 0; i < blockLen; i++)
            out[offset + i] = in[offset + i] ^ block[i];

        offset += blockLen;
        state[12]++;
    }
    return inLen;
}

int decrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    return encrypt(in, inLen, key, nonce, out);
}

void generateKey(uint8_t* key) {
    srand(time(0));
    for (int i = 0; i < 32; i++)
        key[i] = rand() % 256;
}

}
