#include "TEA.h"

#include <array>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <vector>

static const uint32_t DELTA = 0x9E3779B9;
static const uint32_t ROUNDS = 32;

static uint32_t bytesToUint32(const uint8_t* bytes)
{
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

static void uint32ToBytes(uint32_t value, uint8_t* bytes)
{
    bytes[0] = value >> 24;
    bytes[1] = value >> 16;
    bytes[2] = value >> 8;
    bytes[3] = value;
}

static std::array<uint32_t, 4> parseKey(const std::string& s)
{
    if (s.size() != 32)
    {
        throw std::runtime_error("ключ TEA должен содержать 32 hex-символа");
    }

    for (size_t i = 0; i < s.size(); ++i)
    {
        if (!std::isxdigit((unsigned char)s[i]))
        {
            throw std::runtime_error("ключ TEA должен состоять только из hex-символов");
        }
    }

    std::array<uint32_t, 4> result;

    for (size_t i = 0; i < 4; ++i)
    {
        result[i] = std::stoul(s.substr(i * 8, 8), nullptr, 16);
    }

    return result;
}

static std::string keyToHex(const std::vector<uint8_t>& key)
{
    std::ostringstream out;
    for (auto b : key)
    {
        out << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return out.str();
}

static void encryptBlock(uint32_t& v0, uint32_t& v1, const std::array<uint32_t, 4>& key)
{
    uint32_t sum = 0;

    for (uint32_t i = 0; i < ROUNDS; ++i)
    {
        sum += DELTA;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }
}

static void decryptBlock(uint32_t& v0, uint32_t& v1, const std::array<uint32_t, 4>& key)
{
    uint32_t sum = DELTA * ROUNDS;

    for (uint32_t i = 0; i < ROUNDS; ++i)
    {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= DELTA;
    }
}

static std::vector<uint8_t> addPadding(const std::vector<uint8_t>& data)
{
    uint8_t pad = 8 - data.size() % 8;

    if (pad == 0)
    {
        pad = 8;
    }

    std::vector<uint8_t> result = data;

    for (uint8_t i = 0; i < pad; ++i)
    {
        result.push_back(pad);
    }

    return result;
}

static std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data)
{
    if (data.empty())
    {
        throw std::runtime_error("после дешифрования получены пустые данные");
    }

    uint8_t pad = data.back();

    if (pad == 0 || pad > 8 || pad > data.size())
    {
        throw std::runtime_error("неверный ключ или повреждённые данные");
    }

    return std::vector<uint8_t>(data.begin(), data.end() - pad);
}

std::vector<uint8_t> TEA::encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce)
{
    std::array<uint32_t, 4> teaKey = parseKey(keyToHex(key));
    std::vector<uint8_t> buf = addPadding(data);

    for (size_t i = 0; i < buf.size(); i += 8)
    {
        uint32_t v0 = bytesToUint32(&buf[i]);
        uint32_t v1 = bytesToUint32(&buf[i + 4]);

        encryptBlock(v0, v1, teaKey);

        uint32ToBytes(v0, &buf[i]);
        uint32ToBytes(v1, &buf[i + 4]);
    }

    return buf;
}

std::vector<uint8_t> TEA::decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce)
{
    if (data.size() % 8 != 0)
    {
        throw std::runtime_error("размер шифротекста должен быть кратен 8 байтам");
    }

    std::array<uint32_t, 4> teaKey = parseKey(keyToHex(key));
    std::vector<uint8_t> buf = data;

    for (size_t i = 0; i < buf.size(); i += 8)
    {
        uint32_t v0 = bytesToUint32(&buf[i]);
        uint32_t v1 = bytesToUint32(&buf[i + 4]);

        decryptBlock(v0, v1, teaKey);

        uint32ToBytes(v0, &buf[i]);
        uint32ToBytes(v1, &buf[i + 4]);
    }

    return removePadding(buf);
}

std::vector<uint8_t> TEA::generateKey(size_t length) const
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);

    std::vector<uint8_t> key(length);
    for (size_t i = 0; i < length; ++i)
    {
        key[i] = (uint8_t)dist(gen);
    }

    return key;
}

ICipher* createCipher()
{
    return new TEA();
}
