#include "cipher_interface.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <stdexcept>
#include <iostream>

static const uint32_t DELTA = 0x9E3779B9;

static void toWords(const uint8_t* bytes, uint32_t* words, int n) {
    for (int i = 0; i < n; i++)
        words[i] = bytes[4*i] | (bytes[4*i+1] << 8) | (bytes[4*i+2] << 16) | (bytes[4*i+3] << 24);
}

static void fromWords(const uint32_t* words, uint8_t* bytes, int n) {
    for (int i = 0; i < n; i++) {
        bytes[4*i]   = words[i] & 0xFF;
        bytes[4*i+1] = (words[i] >> 8) & 0xFF;
        bytes[4*i+2] = (words[i] >> 16) & 0xFF;
        bytes[4*i+3] = (words[i] >> 24) & 0xFF;
    }
}

static void xteaEncryptBlock(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0;
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += DELTA;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

static void xteaDecryptBlock(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = DELTA * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= DELTA;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0;
    v[1] = v1;
}

extern "C" {

const char* cipherName() { return "XTEA"; }
int keySize() { return 16; }
int nonceSize() { return 0; }

int encrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    try {
        if (!in || !key || !out) {
            std::cerr << "XTEA: ошибка — нулевой указатель" << std::endl;
            return -1;
        }
        if (inLen == 0) {
            std::cerr << "XTEA: ошибка — пустой вход" << std::endl;
            return -1;
        }

        uint32_t k[4];
        toWords(key, k, 4);

        int pad = 8 - (inLen % 8);
        size_t paddedLen = inLen + pad;

        uint8_t* padded = new uint8_t[paddedLen];
        memcpy(padded, in, inLen);
        memset(padded + inLen, pad, pad);

        for (size_t i = 0; i < paddedLen; i += 8) {
            uint32_t block[2];
            toWords(padded + i, block, 2);
            xteaEncryptBlock(block, k);
            fromWords(block, out + i, 2);
        }

        delete[] padded;
        return paddedLen;
    } catch (const std::exception& e) {
        std::cerr << "XTEA encrypt: " << e.what() << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "XTEA encrypt: неизвестная ошибка" << std::endl;
        return -1;
    }
}

int decrypt(const uint8_t* in, size_t inLen, const uint8_t* key, const uint8_t* nonce, uint8_t* out) {
    try {
        if (!in || !key || !out) {
            std::cerr << "XTEA: ошибка — нулевой указатель" << std::endl;
            return -1;
        }
        if (inLen == 0) {
            std::cerr << "XTEA: ошибка — пустой вход" << std::endl;
            return 0;
        }

        uint32_t k[4];
        toWords(key, k, 4);

        for (size_t i = 0; i < inLen; i += 8) {
            uint32_t block[2];
            toWords(in + i, block, 2);
            xteaDecryptBlock(block, k);
            fromWords(block, out + i, 2);
        }

        uint8_t pad = out[inLen - 1];
        if (pad >= 1 && pad <= 8) {
            bool ok = true;
            for (size_t i = inLen - pad; i < inLen; i++)
                if (out[i] != pad) ok = false;
            if (ok) return inLen - pad;
        }
        return inLen;
    } catch (const std::exception& e) {
        std::cerr << "XTEA decrypt: " << e.what() << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "XTEA decrypt: неизвестная ошибка" << std::endl;
        return -1;
    }
}

void generateKey(uint8_t* key) {
    try {
        if (!key) {
            std::cerr << "XTEA: ошибка — нулевой указатель ключа" << std::endl;
            return;
        }
        srand(time(0));
        for (int i = 0; i < 16; i++)
            key[i] = rand() % 256;
    } catch (const std::exception& e) {
        std::cerr << "XTEA generateKey: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "XTEA generateKey: неизвестная ошибка" << std::endl;
    }
}

}
