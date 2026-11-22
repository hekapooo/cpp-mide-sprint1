#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <exception>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        if (options.IsHelpPassed()) {
            return 0;
        }

        std::fstream inFile(options.GetInputFile(), std::ios::in | std::ios::binary);
        if (!inFile.is_open()) {
            throw std::runtime_error("Failed to open input file: " + options.GetInputFile());
        }

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        switch (options.GetCommand()) {
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT: {
            std::fstream outFile(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                throw std::runtime_error("Failed to create output file: " + options.GetOutputFile());
            }
            cryptoCtx.EncryptFile(inFile, outFile, options.GetPassword());
            std::println("File encrypted successfully: {}\n", options.GetOutputFile());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT: {
            std::fstream outFile(options.GetOutputFile(), std::ios::out | std::ios::binary | std::ios::trunc);
            if (!outFile.is_open()) {
                throw std::runtime_error("Failed to create output file: " + options.GetOutputFile());
            }

            cryptoCtx.DecryptFile(inFile, outFile, options.GetPassword());
            std::println("File decrypted successfully: {}\n", options.GetOutputFile());
            break;
        }
        case CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM: {
            std::string checksum = cryptoCtx.CalculateChecksum(inFile);
            std::println("Checksum (SHA-256): {}\n", checksum);

            if (!options.GetOutputFile().empty()) {
                std::fstream outFile(options.GetOutputFile(), std::ios::out | std::ios::trunc);
                if (!outFile.is_open()) {
                    throw std::runtime_error("Failed to create output file: " + options.GetOutputFile());
                }
                outFile << checksum << '\n';
            }
            break;
        }
        }

        return 0;

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Error: Unknown unexpected error occurred.\n";
        return 1;
    }
}