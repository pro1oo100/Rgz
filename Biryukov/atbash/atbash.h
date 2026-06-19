#pragma once
#include "../../icipher.h"
#include <string>
#include <vector>

class Atbash : public ICipher {
public:
    std::string name() const override { return "Atbash"; }
    std::size_t keySize() const override { return 0; }
    std::size_t nonceSize() const override { return 0; }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;

    std::vector<uint8_t> generateKey(std::size_t length) const override;
};

extern "C" ICipher* createCipher();
