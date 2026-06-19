#include "library.h"

std::vector<std::uint8_t> Playfair::encrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) { return {}; }
std::vector<std::uint8_t> Playfair::decrypt(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& nonce) { return {}; }

std::vector<std::uint8_t> Playfair::generateKey(std::size_t length) const { return {}; }

ICipher* createCipher() { return new Playfair(); }
