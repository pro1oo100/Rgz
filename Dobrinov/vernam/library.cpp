#include "library.h"

#include <iostream>
#include <ostream>
#include <random>
#include <stdexcept>

std::vector<std::uint8_t> Vernam::encrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) {
    (void)nonce; // nonce не нужен

    if (data.empty())
        return {};

    if (key.size() < data.size())
        throw std::invalid_argument("Ключ должен быть не короче данных (нужно " +
            std::to_string(data.size()) + " байт, передано " + std::to_string(key.size()) + ")");

    std::vector<std::uint8_t> result(data.size());
    for (std::size_t i = 0; i < data.size(); ++i)
        result[i] = static_cast<std::uint8_t>(data[i] ^ key[i]);
    return result;
}

std::vector<std::uint8_t> Vernam::decrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) {
    return encrypt(data, key, nonce); // XOR обратим
}

std::vector<std::uint8_t> Vernam::generateKey(std::size_t length) const {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::uint8_t> key(length);
    for (auto& byte : key)
        byte = static_cast<std::uint8_t>(dist(rd));

    return key;
}

ICipher* createCipher() { return new Vernam(); }
