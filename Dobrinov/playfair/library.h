#pragma once
#include "playfair_export.h"
#include "../../icipher.h"
#include <string>
#include <vector>
#include <array>
#include <cstdint>

class PLAYFAIR_EXPORT Playfair : public ICipher {
public:
    std::string name() const override { return "Playfair"; }
    std::size_t keySize() const override { return 0; }
    std::size_t nonceSize() const override { return 0; } // nonce не нужен

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce) override;

    std::vector<uint8_t> generateKey(size_t length) const override;
private:
    struct Matrix {
        std::array<std::uint8_t, 256> grid; // grid[row*16 + col]
        std::array<std::uint8_t, 256> row; // row[байт]
        std::array<std::uint8_t, 256> col; // col[байт]
    };

    static Matrix buildMatrix(const std::vector<std::uint8_t>& key); // матрица из ключа

    static std::uint8_t at(const Matrix& m, int r, int c);
};

extern "C" PLAYFAIR_EXPORT ICipher* createCipher();