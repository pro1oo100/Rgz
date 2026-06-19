#include "library.h"

std::vector<std::uint8_t> Vernam::encrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) { return {}; }
std::vector<std::uint8_t> Vernam::decrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) { return {}; }

std::vector<std::uint8_t> Vernam::generateKey(std::size_t length) const { return {}; }

ICipher* createCipher() { return new Vernam(); }
