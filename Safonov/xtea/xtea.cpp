#include "xtea.h"
#include <stdexcept>
#include <iostream>
#include <random>
#include <cstring>

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

std::vector<uint8_t> Xtea::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    try {
        if (key.size() != 16) {
            std::cerr << "XTEA: неверный размер ключа (нужно 16, получено " << key.size() << ")" << std::endl;
            return {};
        }
        if (data.empty()) {
            std::cerr << "XTEA: пустой вход" << std::endl;
            return {};
        }

        uint32_t k[4];
        toWords(key.data(), k, 4);

        int pad = 8 - (data.size() % 8);
        size_t paddedLen = data.size() + pad;

        std::vector<uint8_t> padded(paddedLen);
        memcpy(padded.data(), data.data(), data.size());
        memset(padded.data() + data.size(), pad, pad);

        std::vector<uint8_t> result(paddedLen);
        for (size_t i = 0; i < paddedLen; i += 8) {
            uint32_t block[2];
            toWords(padded.data() + i, block, 2);
            xteaEncryptBlock(block, k);
            fromWords(block, result.data() + i, 2);
        }

        return result;
    } catch (const std::exception& e) {
        std::cerr << "XTEA encrypt: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "XTEA encrypt: неизвестная ошибка" << std::endl;
        return {};
    }
}

std::vector<uint8_t> Xtea::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    try {
        if (key.size() != 16) {
            std::cerr << "XTEA: неверный размер ключа (нужно 16, получено " << key.size() << ")" << std::endl;
            return {};
        }
        if (data.empty()) {
            std::cerr << "XTEA: пустой вход" << std::endl;
            return {};
        }

        uint32_t k[4];
        toWords(key.data(), k, 4);

        std::vector<uint8_t> result(data.size());
        for (size_t i = 0; i < data.size(); i += 8) {
            uint32_t block[2];
            toWords(data.data() + i, block, 2);
            xteaDecryptBlock(block, k);
            fromWords(block, result.data() + i, 2);
        }

        uint8_t pad = result.back();
        if (pad >= 1 && pad <= 8) {
            bool ok = true;
            for (size_t i = result.size() - pad; i < result.size(); i++)
                if (result[i] != pad) ok = false;
            if (ok) result.resize(result.size() - pad);
        }

        return result;
    } catch (const std::exception& e) {
        std::cerr << "XTEA decrypt: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "XTEA decrypt: неизвестная ошибка" << std::endl;
        return {};
    }
}

std::vector<uint8_t> Xtea::generateKey(size_t length) const {
    try {
        std::vector<uint8_t> key(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (size_t i = 0; i < length; i++)
            key[i] = dist(gen);
        return key;
    } catch (const std::exception& e) {
        std::cerr << "XTEA generateKey: " << e.what() << std::endl;
        return {};
    } catch (...) {
        std::cerr << "XTEA generateKey: неизвестная ошибка" << std::endl;
        return {};
    }
}

ICipher* createCipher() { return new Xtea(); }
