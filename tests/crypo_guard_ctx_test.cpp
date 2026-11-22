#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

TEST(CryptoGuardTest, EncryptWrongInputStream) {
    std::stringstream input;
    input.setstate(std::ios::badbit);
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(input, out, "1234"), std::invalid_argument);
}

TEST(CryptoGuardTest, EncryptWrongOutputStream) {
    std::stringstream input;
    std::stringstream out;
    out.setstate(std::ios::failbit);
    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.EncryptFile(input, out, "1234"), std::invalid_argument);
}

TEST(CryptoGuardTest, EncryptSameString) {
    std::stringstream inputFirst;
    std::stringstream inputSecond;
    std::stringstream out;
    inputFirst << "Hello, world!";
    inputSecond << "Hello, world!";
    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(inputFirst, out, "1234");
    std::string encryptedFirst = out.str();

    // clear output stream
    out.str(std::string());

    ctx.EncryptFile(inputSecond, out, "1234");
    std::string encryptedSecond = out.str();
    ASSERT_EQ(encryptedFirst, encryptedSecond);
}

TEST(CryptoGuardTest, EncryptDiffString) {
    std::stringstream inputFirst;
    std::stringstream inputSecond;
    std::stringstream out;
    inputFirst << "Hello, world2!";
    inputSecond << "Hello, world!";
    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(inputFirst, out, "1234");
    std::string encryptedFirst = out.str();

    // clear output stream
    out.str(std::string());

    ctx.EncryptFile(inputSecond, out, "1234");
    std::string encryptedSecond = out.str();
    ASSERT_NE(encryptedFirst, encryptedSecond);
}

TEST(CryptoGuardTest, DecryptWrongInputStream) {
    std::stringstream input;
    input.setstate(std::ios::badbit);
    std::stringstream out;
    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.DecryptFile(input, out, "1234"), std::invalid_argument);
}

TEST(CryptoGuardTest, DecryptWithWrongPasswordThrows) {
    std::stringstream input("Hello, world!");
    std::stringstream encryptedOut;
    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(input, encryptedOut, "1234");
    std::string encrypted = encryptedOut.str();
    std::stringstream inputEncrypted(encrypted);
    std::stringstream decryptedOut;
    ASSERT_THROW(ctx.DecryptFile(inputEncrypted, decryptedOut, "12345"), std::runtime_error);
}

TEST(CryptoGuardTest, DecryptEncryptedString) {
    std::stringstream input;
    std::stringstream encryptedOut;
    input << "Hello, world!";
    CryptoGuard::CryptoGuardCtx ctx;
    ctx.EncryptFile(input, encryptedOut, "1234");
    std::string encrypted = encryptedOut.str();
    std::stringstream input_encrypted(encrypted);
    std::stringstream decryptedOut;
    ctx.DecryptFile(input_encrypted, decryptedOut, "1234");
    std::string decrypted = decryptedOut.str();
    ASSERT_EQ(decrypted, "Hello, world!");
}

TEST(CryptoGuardTest, HelloWorldCalculateChecksum) {
    std::stringstream input("Hello, world!");
    CryptoGuard::CryptoGuardCtx ctx;
    std::string checksum = ctx.CalculateChecksum(input);
    // SHA-256 for "Hello, world!"
    ASSERT_EQ(checksum, "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3");
}

TEST(CryptoGuardTest, CalculateChecksumWrongInputStream) {
    std::stringstream input;
    input.setstate(std::ios::badbit);
    CryptoGuard::CryptoGuardCtx ctx;
    ASSERT_THROW(ctx.CalculateChecksum(input), std::invalid_argument);
}
