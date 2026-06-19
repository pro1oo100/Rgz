#include "chacha20.h"
#include <stdexcept>
#include <iostream>
#include <random>

static void quarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8)  | (d >> 24);
    c += d; b ^= c; b = (b << 7)  | (b >> 25);
}

static void chachaBlock(uint32_t output[16], const uint32_t input[16]) {
    uint32_t working[16];
    for (int i = 0; i < 16; i++) working[i] = input[i];

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

    for (int i = 0; i < 16; i++)
        output[i] = working[i] + input[i];
}

static void chachaCrypt(std::vector<uint8_t>& out, const std::vector<uint8_t>& in,
                         const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++)
        state[4 + i] = key[4*i] | (key[4*i+1] << 8) | (key[4*i+2] << 16) | (key[4*i+3] << 24);

    state[12] = counter;
    for (int i = 0; i < 3; i++)
        state[13 + i] = nonce[4*i] | (nonce[4*i+1] << 8) | (nonce[4*i+2] << 16) | (nonce[4*i+3] << 24);

    size_t offset = 0;
    while (offset < in.size()) {
        uint32_t keystream[16];
        chachaBlock(keystream, state);

        uint8_t block[64];
        for (int i = 0; i < 16; i++) {
            block[4*i]   = keystream[i] & 0xFF;
            block[4*i+1] = (keystream[i] >> 8) & 0xFF;
            block[4*i+2] = (keystream[i] >> 16) & 0xFF;
            block[4*i+3] = (keystream[i] >> 24) & 0xFF;
        }

        size_t blockLen = (in.size() - offset > 64) ? 64 : in.size() - offset;
        for (size_t i = 0; i < blockLen; i++)
            out[offset + i] = in[offset + i] ^ block[i];

        offset += blockLen;
        state[12]++;
    }
}

std::vector<uint8_t> ChaCha20::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    try {
        if (key.size() != 32) {
            std::cerr << "ChaCha20: неверный размер ключа (нужно 32, получено " << key.size() << ")" << std::endl;
            return {};
        }
        if (nonce.size() != 12) {
            std::cerr << "ChaCha20: неверный размер nonce (нужно 12, получено " << nonce.size() << ")" << std::endl;
            return {};
        }
        if (data.empty()) {
            std::cerr << "ChaCha20: пустой вход" << std::endl;
            return {};
        }

        std::vector<uint8_t> result(data.size());
        chachaCrypt(result, data, key.data(), nonce.data(), 0);
        return result;
    } catch (const std::exception& e) {
        std::cerr << "ChaCha20 encrypt: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "ChaCha20 encrypt: неизвестная ошибка" << std::endl;
        return {};
    }
}

std::vector<uint8_t> ChaCha20::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    try {
        if (key.size() != 32) {
            std::cerr << "ChaCha20: неверный размер ключа (нужно 32, получено " << key.size() << ")" << std::endl;
            return {};
        }
        if (nonce.size() != 12) {
            std::cerr << "ChaCha20: неверный размер nonce (нужно 12, получено " << nonce.size() << ")" << std::endl;
            return {};
        }
        if (data.empty()) {
            std::cerr << "ChaCha20: пустой вход" << std::endl;
            return {};
        }

        std::vector<uint8_t> result(data.size());
        chachaCrypt(result, data, key.data(), nonce.data(), 0);
        return result;
    } catch (const std::exception& e) {
        std::cerr << "ChaCha20 decrypt: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "ChaCha20 decrypt: неизвестная ошибка" << std::endl;
        return {};
    }
}

std::vector<uint8_t> ChaCha20::generateKey(size_t length) const {
    try {
        std::vector<uint8_t> key(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < length; i++)
            key[i] = dist(gen);
        return key;
    } catch (const std::exception& e) {
        std::cerr << "ChaCha20 generateKey: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "ChaCha20 generateKey: неизвестная ошибка" << std::endl;
        return {};
    }
}

ICipher* createCipher() { return new ChaCha20(); }
