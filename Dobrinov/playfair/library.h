#pragma once
#include "playfair_export.h"
#include "../../icipher.h"
#include <string>
#include <fstream>
#include <vector>

class PLAYFAIR_EXPORT Playfair : public ICipher {
public:
    std::string name() const override { return "Playfair"; }
    std::size_t keySize() const override { return 0; } // ключевое слово, переменная длина
    std::size_t nonceSize() const override { return 0; } // nonce не нужен

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;

    std::vector<uint8_t> generateKey(size_t length) const override;
};

extern "C" PLAYFAIR_EXPORT ICipher* createCipher();