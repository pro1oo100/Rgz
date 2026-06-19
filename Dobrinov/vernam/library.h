#pragma once
#include "vernam_export.h"
#include "../../icipher.h"
#include <string>
#include <vector>

class VERNAM_EXPORT Vernam : public ICipher {
public:
    std::string name() const override { return "Vernam"; }
    std::size_t keySize() const override { return 0; } // = длине данных, задаётся при генерации
    std::size_t nonceSize() const override { return 0; }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;

    std::vector<uint8_t> generateKey(size_t length) const override;
};

extern "C" VERNAM_EXPORT ICipher* createCipher();