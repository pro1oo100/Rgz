#include "rc4.h"
#include <stdexcept>
#include <iostream>
#include <random>
#include <cstring>

static uint8_t s_box[256];
static uint8_t s_i;
static uint8_t s_j;

static void rc4_ksa(const uint8_t* key, std::size_t keyLen) {
    for (std::size_t idx = 0; idx < 256; idx++) {
        s_box[idx] = (uint8_t)idx;
    }

    uint8_t j = 0;
    for (std::size_t idx = 0; idx < 256; idx++) {
        j = (uint8_t)(j + s_box[idx] + key[idx % keyLen]);
        uint8_t tmp = s_box[idx];
        s_box[idx] = s_box[j];
        s_box[j] = tmp;
    }

    s_i = 0;
    s_j = 0;
}

static uint8_t rc4_next_byte() {
    s_i = (uint8_t)(s_i + 1);
    s_j = (uint8_t)(s_j + s_box[s_i]);

    uint8_t tmp = s_box[s_i];
    s_box[s_i] = s_box[s_j];
    s_box[s_j] = tmp;

    uint8_t k = s_box[(uint8_t)(s_box[s_i] + s_box[s_j])];
    return k;
}

static std::vector<uint8_t> rc4_transform(const std::vector<uint8_t>& data, const uint8_t* key, std::size_t keyLen) {
    rc4_ksa(key, keyLen);

    std::vector<uint8_t> result(data.size());
    for (std::size_t idx = 0; idx < data.size(); idx++) {
        result[idx] = data[idx] ^ rc4_next_byte();
    }

    memset(s_box, 0, sizeof(s_box));
    s_i = 0;
    s_j = 0;

    return result;
}

std::vector<uint8_t> Rc4::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    (void)nonce;
    try {
        if (key.size() != 16) {
            std::cerr << "RC4: неверный размер ключа (нужно 16, получено " << key.size() << ")" << std::endl;
            return {};
        }
        if (data.empty()) {
            std::cerr << "RC4: пустой вход" << std::endl;
            return {};
        }
        return rc4_transform(data, key.data(), key.size());
    } catch (const std::exception& e) {
        std::cerr << "RC4 encrypt: " << e.what() << std::endl;
        return {};
    }
}

std::vector<uint8_t> Rc4::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    return encrypt(data, key, nonce);
}

std::vector<uint8_t> Rc4::generateKey(std::size_t length) const {
    try {
        std::vector<uint8_t> key(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (std::size_t i = 0; i < length; i++)
            key[i] = dist(gen);
        return key;
    } catch (const std::exception& e) {
        std::cerr << "RC4 generateKey: " << e.what() << std::endl;
        return {};
    }
}

ICipher* createCipher() { return new Rc4(); }
