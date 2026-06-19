#include "atbash.h"
#include <stdexcept>
#include <iostream>
#include <random>

static std::vector<uint8_t> atbash_transform(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    for (std::size_t i = 0; i < data.size(); i++) {
        result[i] = (uint8_t)(255u - data[i]);
    }
    return result;
}

std::vector<uint8_t> Atbash::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    (void)key;
    (void)nonce;
    try {
        if (data.empty()) {
            std::cerr << "Atbash: пустой вход" << std::endl;
            return {};
        }
        return atbash_transform(data);
    } catch (const std::exception& e) {
        std::cerr << "Atbash encrypt: " << e.what() << std::endl;
        return {};
    }
}

std::vector<uint8_t> Atbash::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) {
    (void)key;
    (void)nonce;
    try {
        if (data.empty()) {
            std::cerr << "Atbash: пустой вход" << std::endl;
            return {};
        }
        return atbash_transform(data);
    } catch (const std::exception& e) {
        std::cerr << "Atbash decrypt: " << e.what() << std::endl;
        return {};
    }
}

std::vector<uint8_t> Atbash::generateKey(std::size_t length) const {
    (void)length;
    return {};
}

ICipher* createCipher() { return new Atbash(); }
