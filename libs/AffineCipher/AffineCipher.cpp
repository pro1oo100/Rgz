#include "../../include/cipher_interface.h"

#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

static std::pair<uint8_t, uint8_t> parseKey(const char* key)
{
    std::string s(key);
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

    return {uint8_t(a), uint8_t(b)};
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

    return uint8_t(t);
}

extern "C"
{
    CipherResult encrypt(const uint8_t* data, uint64_t size, const char* key)
    {
        auto [a, b] = parseKey(key);

        CipherResult result;
        result.size = size;
        result.data = new uint8_t[size];

        for (uint64_t i = 0; i < size; ++i)
        {
            result.data[i] = uint8_t((a * data[i] + b) % 256);
        }

        return result;
    }

    CipherResult decrypt(const uint8_t* data, uint64_t size, const char* key)
    {
        auto [a, b] = parseKey(key);
        uint8_t aInv = modInverse(a);

        CipherResult result;
        result.size = size;
        result.data = new uint8_t[size];

        for (uint64_t i = 0; i < size; ++i)
        {
            result.data[i] = uint8_t((aInv * (data[i] + 256 - b)) % 256);
        }

        return result;
    }

    CipherKey generateKey()
    {
        std::random_device rd;
        std::mt19937 gen(rd());

        std::vector<uint8_t> odds;

        for (int i = 1; i < 256; i += 2)
        {
            odds.push_back(uint8_t(i));
        }

        std::uniform_int_distribution<size_t> distA(0, odds.size() - 1);
        std::uniform_int_distribution<int> distB(0, 255);

        uint8_t a = odds[distA(gen)];
        uint8_t b = uint8_t(distB(gen));

        std::ostringstream out;
        out << int(a) << "," << int(b);

        std::string s = out.str();

        CipherKey result;
        result.size = s.size();
        result.value = new char[result.size + 1];
        std::memcpy(result.value, s.c_str(), result.size + 1);

        return result;
    }
}
