#include "../../include/cipher_interface.h"

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

static std::array<uint32_t, 4> parseKey(const char* key)
{
    std::string s(key);

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

static std::vector<uint8_t> addPadding(const uint8_t* data, uint64_t size)
{
    uint8_t pad = 8 - size % 8;

    if (pad == 0)
    {
        pad = 8;
    }

    std::vector<uint8_t> result(data, data + size);

    for (uint8_t i = 0; i < pad; ++i)
    {
        result.push_back(pad);
    }

    return result;
}

static std::vector<uint8_t> removePadding(const uint8_t* data, uint64_t size)
{
    if (size == 0)
    {
        throw std::runtime_error("после дешифрования получены пустые данные");
    }

    uint8_t pad = data[size - 1];

    if (pad == 0 || pad > 8 || pad > size)
    {
        throw std::runtime_error("неверный ключ или повреждённые данные");
    }

    return std::vector<uint8_t>(data, data + size - pad);
}

extern "C"
{
    CipherResult encrypt(const uint8_t* data, uint64_t size, const char* key)
    {
        std::array<uint32_t, 4> teaKey = parseKey(key);
        std::vector<uint8_t> buf = addPadding(data, size);

        for (size_t i = 0; i < buf.size(); i += 8)
        {
            uint32_t v0 = bytesToUint32(&buf[i]);
            uint32_t v1 = bytesToUint32(&buf[i + 4]);

            encryptBlock(v0, v1, teaKey);

            uint32ToBytes(v0, &buf[i]);
            uint32ToBytes(v1, &buf[i + 4]);
        }

        CipherResult result;
        result.size = buf.size();
        result.data = new uint8_t[result.size];
        std::memcpy(result.data, buf.data(), result.size);

        return result;
    }

    CipherResult decrypt(const uint8_t* data, uint64_t size, const char* key)
    {
        if (size % 8 != 0)
        {
            throw std::runtime_error("размер шифротекста должен быть кратен 8 байтам");
        }

        std::array<uint32_t, 4> teaKey = parseKey(key);
        std::vector<uint8_t> buf(data, data + size);

        for (size_t i = 0; i < buf.size(); i += 8)
        {
            uint32_t v0 = bytesToUint32(&buf[i]);
            uint32_t v1 = bytesToUint32(&buf[i + 4]);

            decryptBlock(v0, v1, teaKey);

            uint32ToBytes(v0, &buf[i]);
            uint32ToBytes(v1, &buf[i + 4]);
        }

        std::vector<uint8_t> unpadded = removePadding(buf.data(), buf.size());

        CipherResult result;
        result.size = unpadded.size();
        result.data = new uint8_t[result.size];
        std::memcpy(result.data, unpadded.data(), result.size);

        return result;
    }

    CipherKey generateKey()
    {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

        std::ostringstream out;

        for (int i = 0; i < 4; ++i)
        {
            out << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << dist(gen);
        }

        std::string s = out.str();

        CipherKey result;
        result.size = s.size();
        result.value = new char[result.size + 1];
        std::memcpy(result.value, s.c_str(), result.size + 1);

        return result;
    }
}
