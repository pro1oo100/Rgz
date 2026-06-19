#include "AffineCipher.h"

#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

static std::pair<int, int> parseKeyString(const std::string& s)
{
    size_t comma = s.find(',');

    if (comma == std::string::npos)
    {
        throw std::runtime_error("ключ Affine Cipher должен быть в формате \"a,b\"");
    }

    int a = std::stoi(s.substr(0, comma));
    int b = std::stoi(s.substr(comma + 1));

    if (a <= 0 || a >= 256 || a % 2 == 0)
    {
        throw std::runtime_error("a должно быть нечётным числом в диапазоне [1, 255]");
    }

    if (b < 0 || b >= 256)
    {
        throw std::runtime_error("b должно быть в диапазоне [0, 255]");
    }

    return {a, b};
}

static std::string keyToString(const std::vector<uint8_t>& key)
{
    return std::string(key.begin(), key.end());
}

static uint8_t modInverse(uint8_t a)
{
    int t = 0;
    int newT = 1;
    int r = 256;
    int newR = a;

    while (newR != 0)
    {
        int q = r / newR;
        int tmp = t - q * newT;
        t = newT;
        newT = tmp;

        tmp = r - q * newR;
        r = newR;
        newR = tmp;
    }

    if (r != 1)
    {
        throw std::runtime_error("a не имеет обратного элемента по модулю 256");
    }

    if (t < 0)
    {
        t += 256;
    }

    return (uint8_t)t;
}

std::vector<uint8_t> AffineCipher::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce)
{
    auto [a, b] = parseKeyString(keyToString(key));

    std::vector<uint8_t> result(data.size());

    for (size_t i = 0; i < data.size(); ++i)
    {
        result[i] = (uint8_t)((a * data[i] + b) % 256);
    }

    return result;
}

std::vector<uint8_t> AffineCipher::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce)
{
    auto [a, b] = parseKeyString(keyToString(key));
    uint8_t aInv = modInverse((uint8_t)a);

    std::vector<uint8_t> result(data.size());

    for (size_t i = 0; i < data.size(); ++i)
    {
        result[i] = (uint8_t)((aInv * (data[i] + 256 - b)) % 256);
    }

    return result;
}

std::vector<uint8_t> AffineCipher::generateKey(size_t length) const
{
    std::random_device rd;
    std::mt19937 gen(rd());

    std::vector<int> odds;
    for (int i = 1; i < 256; i += 2)
    {
        odds.push_back(i);
    }

    std::uniform_int_distribution<size_t> distA(0, odds.size() - 1);
    std::uniform_int_distribution<int> distB(0, 255);

    int a = odds[distA(gen)];
    int b = distB(gen);

    std::string s = std::to_string(a) + "," + std::to_string(b);

    return std::vector<uint8_t>(s.begin(), s.end());
}

ICipher* createCipher()
{
    return new AffineCipher();
}
