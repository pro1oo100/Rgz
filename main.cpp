#include "icipher.h"
#include "lib_loader.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <vector>

#define LIBRARIES_DIR "Libraries"

std::ostream& operator<<(std::ostream& os, const std::vector<std::uint8_t>& bytes) {
    for (std::uint8_t b : bytes)
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return os << std::dec;
}

std::vector<std::uint8_t> randomBytes(std::size_t n) {
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    std::vector<std::uint8_t> v(n);
    for (auto& b : v)
        b = static_cast<std::uint8_t>(dist(rd));
    return v;
}

std::vector<std::uint8_t> readFile(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Не удалось открыть файл: " + p.string());
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void writeFile(const std::filesystem::path& p, const std::vector<std::uint8_t>& data) {
    if (p.has_parent_path())
        std::filesystem::create_directories(p.parent_path());

    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Не удалось создать файл: " + p.string());
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
}

struct MKey {
    std::vector<std::uint8_t> key, nonce;
};
MKey makeKey(ICipher* cipher, std::size_t dataLen) {
    std::size_t keyLen = cipher->keySize() ? cipher->keySize() : dataLen;
    MKey m;
    m.key = cipher->generateKey(keyLen);
    if (cipher->nonceSize() > 0)
        m.nonce = randomBytes(cipher->nonceSize());
    return m;
}

void runText(ICipher* cipher) {
    std::cout << "Введите текст: ";
    std::string line;
    std::getline(std::cin >> std::ws, line);

    std::vector<std::uint8_t> data(line.begin(), line.end());
    MKey mat = makeKey(cipher, data.size());

    auto enc = cipher->encrypt(data, mat.key, mat.nonce);
    auto dec = cipher->decrypt(enc, mat.key, mat.nonce);
    std::string decStr(dec.begin(), dec.end());

    std::cout << "\nКлюч: " << mat.key << "\n";
    if (!mat.nonce.empty())
        std::cout << "Nonce: " << mat.nonce << "\n";
    std::cout << "Шифртекст: " << enc << "\n";
    std::cout << "Расшифровано: " << decStr << "\n";
}

void runFile(ICipher* cipher) {
    std::cout << "Рабочая директория: " << std::filesystem::current_path() << "\n";
    std::cout << "Путь к файлу: ";
    std::string inPath;
    std::getline(std::cin >> std::ws, inPath);

    if (!std::filesystem::exists(inPath)) {
        std::cout << "Файл не найден: " << inPath << "\n";
        return;
    }

    auto data = readFile(inPath);
    MKey mat = makeKey(cipher, data.size());

    auto enc = cipher->encrypt(data, mat.key, mat.nonce);
    auto dec = cipher->decrypt(enc, mat.key, mat.nonce);

    std::filesystem::path encPath = inPath + ".enc";
    std::filesystem::path decPath = inPath + ".dec";
    writeFile(encPath, enc);
    writeFile(decPath, dec);

    std::cout << "\nКлюч: " << mat.key << "\n";
    if (!mat.nonce.empty())
        std::cout << "Nonce: " << mat.nonce << "\n";
    std::cout << "Зашифрованный файл: " << std::filesystem::absolute(encPath).string() << "\n";
    std::cout << "Расшифрованный файл: " << std::filesystem::absolute(decPath).string() << "\n";
}


int main() {
    try {
        std::filesystem::path dir = LIBRARIES_DIR;
        if (!std::filesystem::exists(dir) || !std::filesystem::is_directory(dir)) {
            std::cout << "Папка с библиотеками не найдена: " << std::filesystem::absolute(dir).string() << "\n";
            return 1;
        }

        std::vector<std::unique_ptr<CipherLoader>> loaders;
        for (const auto& entry : std::filesystem::directory_iterator(dir)) {
            try {
                loaders.push_back(std::make_unique<CipherLoader>(entry.path().string()));
            } catch (const std::exception& ex) {
                std::cerr << "Пропущена " << entry.path().filename().string() << ": " << ex.what() << "\n";
            }
        }

        if (loaders.empty()) {
            std::cout << "В папке " << dir.string() << " не найдено ни одного шифра.\n";
            return 1;
        }

        std::cout << "Доступные шифры:\n";
        for (std::size_t i = 0; i < loaders.size(); ++i)
            std::cout << i + 1 << ") " << loaders[i]->get()->name() << "\n";
        std::cout << "Выберите шифр: ";

        std::size_t choice = 0;
        std::cin >> choice;
        if (choice < 1 || choice > loaders.size()) {
            std::cout << "Неверный выбор\n";
            return 1;
        }
        ICipher* cipher = loaders[choice - 1]->get();

        std::cout << "Режим:\n1) текст\n2) файл\n";
        int mode = 0;
        std::cin >> mode;

        if (mode == 1) runText(cipher);
        else if (mode == 2) runFile(cipher);
        else std::cout << "Неверный режим\n";

    } catch (const std::exception& e) {
        std::cerr << "Ошибка: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
