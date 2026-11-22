#include "crypto_guard_ctx.h"
#include <array>
#include <iomanip>
#include <ios>
#include <iostream>
#include <istream>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

class CryptoGuard::CryptoGuardCtx::Impl {
public:
    /*
     * https://docs.openssl.org/3.3/man3/OpenSSL_add_all_algorithms/#name
     * "OpenSSL_add_all_algorithms" and "EVP_cleanup" marked as DEPRECATED.
     * Я не знаю, должен ли я менять это, но оставляю как в примере
     */
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream) {
            throw std::invalid_argument("Invalid input stream!");
        }
        if (!outStream) {
            throw std::invalid_argument("Invalid output stream!");
        }

        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = 1;
        Encrypt(inStream, outStream, params);
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream) {
            throw std::invalid_argument("Invalid input stream!");
        }
        if (!outStream) {
            throw std::invalid_argument("Invalid output stream!");
        }

        AesCipherParams params = CreateCipherParamsFromPassword(password);
        params.encrypt = 0;
        Encrypt(inStream, outStream, params);
    }

    std::string CalculateChecksum(std::iostream &inStream) {
        if (!inStream) {
            throw std::invalid_argument("Invalid input stream!");
        }

        auto mdDeleter = [](EVP_MD_CTX *ptr) {
            if (ptr) {
                EVP_MD_CTX_free(ptr);
            }
        };
        std::unique_ptr<EVP_MD_CTX, decltype(mdDeleter)> ctx(EVP_MD_CTX_new(), mdDeleter);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_MD_CTX! " + GetError());
        }

        if (!EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) {
            throw std::runtime_error("EVP_DigestInit_ex failed! " + GetError());
        }

        std::vector<unsigned char> buffer(BUFFER_SIZE);
        while (inStream) {
            inStream.read(reinterpret_cast<char *>(buffer.data()), BUFFER_SIZE);
            std::streamsize bytesRead = inStream.gcount();
            if (bytesRead > 0) {
                if (!EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytesRead))) {
                    throw std::runtime_error("EVP_DigestUpdate failed! " + GetError());
                }
            }
        }

        if (inStream.bad()) {
            throw std::runtime_error("Error reading input stream during checksum calculation!");
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> hash{};
        unsigned int hashLen = 0;

        if (!EVP_DigestFinal_ex(ctx.get(), hash.data(), &hashLen)) {
            throw std::runtime_error("EVP_DigestFinal_ex failed! " + GetError());
        }

        // Hex converting
        std::stringstream hexStream;
        hexStream << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < hashLen; ++i) {
            hexStream << std::setw(2) << static_cast<int>(hash[i]);
        }

        return hexStream.str();
    }

private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    const size_t BUFFER_SIZE = 65536;

    AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

    void Encrypt(std::iostream &inStream, std::iostream &outStream, const AesCipherParams &params) {

        auto ctxDeleter = [](EVP_CIPHER_CTX *ptr) {
            if (ptr)
                EVP_CIPHER_CTX_free(ptr);
        };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(ctxDeleter)> ctx(EVP_CIPHER_CTX_new(), ctxDeleter);
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX_new! " + GetError());
        }

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("EVP Initialization failed! " + GetError());
        }

        std::vector<unsigned char> inBuffer(BUFFER_SIZE);
        std::vector<unsigned char> outBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        while (inStream) {
            int outLen = 0;
            inStream.read(reinterpret_cast<char *>(inBuffer.data()), BUFFER_SIZE);
            std::streamsize bytesRead = inStream.gcount();
            if (bytesRead <= 0) {
                break;
            }
            // EVP_EncryptUpdate
            if (!EVP_CipherUpdate(ctx.get(), outBuffer.data(), &outLen, inBuffer.data(), static_cast<int>(bytesRead))) {
                throw std::runtime_error("EVP Updating failed! " + GetError());
            }
            outStream.write(reinterpret_cast<char *>(outBuffer.data()), outLen);
            if (!outStream) {
                throw std::runtime_error("Writing encrypted data failed!");
            }
        }

        int finalLen = 0;
        if (!EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &finalLen)) {
            throw std::runtime_error("Encryption finalization failed! " + GetError());
        }
        if (finalLen > 0) {
            outStream.write(reinterpret_cast<const char *>(outBuffer.data()), finalLen);
            if (!outStream) {
                throw std::runtime_error("Writing final encryption block failed!");
            }
        }
    }

    std::string GetError() const {
        std::string message;
        unsigned long errCode;
        while ((errCode = ERR_get_error()) != 0) {
            char buf[256];
            ERR_error_string_n(errCode, buf, sizeof(buf));
            if (!message.empty()) {
                message += "; ";
            }
            message += buf;
        }

        return message;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<CryptoGuard::CryptoGuardCtx::Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}
void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
