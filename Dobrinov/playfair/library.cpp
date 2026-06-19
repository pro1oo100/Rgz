#include "library.h"

#include <random>

Playfair::Matrix Playfair::buildMatrix(const std::vector<std::uint8_t>& key) {
    Matrix m{};
    std::array<bool, 256> used{};
    std::size_t idx = 0;

    for (std::uint8_t b : key)
        if (!used[b]) {
            used[b] = true; m.grid[idx++] = b;
        }

    for (int b = 0; b < 256; ++b)
        if (!used[b]) {
            used[b] = true;
            m.grid[idx++] = static_cast<std::uint8_t>(b);
        }

    for (std::size_t i = 0; i < 256; ++i) {
        std::uint8_t b = m.grid[i];
        m.row[b] = static_cast<std::uint8_t>(i / 16);
        m.col[b] = static_cast<std::uint8_t>(i % 16);
    }
    return m;
}

std::uint8_t Playfair::at(const Matrix& m, int r, int c) {
    return m.grid[(r & 15) * 16 + (c & 15)]; // & 15 = % 16 для неотрицательных
}

std::vector<std::uint8_t> Playfair::encrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) {
    (void)nonce; // nonce не нужен

    if (data.empty())
        return {};

    Matrix m = buildMatrix(key);

    std::uint8_t pad = (data.size() % 2 == 0) ? 0 : 1; // длина должна быть четной
    std::vector<std::uint8_t> buf = data;
    if (pad)
        buf.push_back(0x00);

    std::vector<std::uint8_t> out;
    out.reserve(buf.size() + 1);
    out.push_back(pad); // служебный байт

    for (std::size_t i = 0; i < buf.size(); i += 2) {
        std::uint8_t a = buf[i], b = buf[i + 1];
        int r1 = m.row[a], c1 = m.col[a];
        int r2 = m.row[b], c2 = m.col[b];

        if (r1 == r2) { // одна строка
            out.push_back(at(m, r1, c1 + 1));
            out.push_back(at(m, r2, c2 + 1));
        } else if (c1 == c2) { // один столбец вниз
            out.push_back(at(m, r1 + 1, c1));
            out.push_back(at(m, r2 + 1, c2));
        } else { // прямоугольник обмен столбцами
            out.push_back(at(m, r1, c2));
            out.push_back(at(m, r2, c1));
        }
    }
    return out;
}

std::vector<std::uint8_t> Playfair::decrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) {
    (void)nonce;
    if (data.empty())
        return {};

    Matrix m = buildMatrix(key);

    std::uint8_t pad = data[0]; // сколько байт было добито при шифровании
    std::vector<std::uint8_t> out;
    out.reserve(data.size());

    for (std::size_t i = 1; i + 1 < data.size(); i += 2) {
        std::uint8_t a = data[i], b = data[i + 1];
        int r1 = m.row[a], c1 = m.col[a];
        int r2 = m.row[b], c2 = m.col[b];

        if (r1 == r2) { // одна строка
            out.push_back(at(m, r1, c1 + 15));
            out.push_back(at(m, r2, c2 + 15));
        } else if (c1 == c2) { // один столбец
            out.push_back(at(m, r1 + 15, c1));
            out.push_back(at(m, r2 + 15, c2));
        } else { // прямоугольник
            out.push_back(at(m, r1, c2));
            out.push_back(at(m, r2, c1));
        }
    }

    if (pad && !out.empty())
        out.pop_back(); // снять добивку

    return out;
}

std::vector<std::uint8_t> Playfair::generateKey(std::size_t length) const {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<std::uint8_t> key(length ? length : 8);
    for (auto& byte : key)
        byte = static_cast<std::uint8_t>(dist(rd));
    return key;
}

ICipher* createCipher() { return new Playfair(); }
