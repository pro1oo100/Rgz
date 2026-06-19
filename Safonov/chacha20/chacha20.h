#pragma once
#include "chacha20_export.h"
#include "../../icipher.h"
#include <string>
#include <vector>

class CHACHA20_EXPORT ChaCha20 : public ICipher {
public:
    std::string name() const override { return "ChaCha20"; }
    std::size_t keySize() const override { return 32; }
    std::size_t nonceSize() const override { return 12; }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;

    std::vector<uint8_t> generateKey(size_t length) const override;
};

extern "C" CHACHA20_EXPORT ICipher* createCipher();
