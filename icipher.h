#pragma once
#include <string>
#include <cstdint>
#include <vector>

class ICipher {
public:
    virtual ~ICipher() = default;

    virtual std::string name() const = 0;
    virtual std::size_t keySize() const = 0;
    virtual std::size_t nonceSize() const = 0; // 0 = nonce не нужен
    
    virtual std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce = {}) = 0;
    virtual std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce = {}) = 0;

    virtual std::vector<std::uint8_t> generateKey(size_t length) const = 0;
};