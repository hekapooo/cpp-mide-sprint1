#include "boost/program_options/errors.hpp"
#include "cmd_options.h"
#include <gtest/gtest.h>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

struct ArgumentsWrapper {
    std::vector<std::string> arguments;
    std::vector<char *> pointers;

    ArgumentsWrapper(std::initializer_list<std::string> args) : arguments(args) {
        for (std::string &arg : arguments) {
            pointers.push_back(arg.data());
        }
        pointers.push_back(nullptr);
    }

    int argc() const { return static_cast<int>(arguments.size()); }
    char **argv() { return pointers.data(); }
};

TEST(OptionTest, HelpArgPassed) {
    ArgumentsWrapper args{"program?", "--help"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_TRUE(po.IsHelpPassed());
}

TEST(OptionTest, HArgPassed) {
    ArgumentsWrapper args{"program?", "-h"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_TRUE(po.IsHelpPassed());
}

TEST(OptionTest, NoArgPassed) {
    ArgumentsWrapper args{"program?"};
    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.argc(), args.argv()), boost::program_options::error);
}

TEST(OptionTest, WrongCommandArgPassed) {
    ArgumentsWrapper args{"program?", "-c", "test_command", "-i", "~/test.txt", "-p", "123", "-o", "~/test1.txt"};
    CryptoGuard::ProgramOptions po;
    ASSERT_THROW(po.Parse(args.argc(), args.argv()), std::invalid_argument);
}

TEST(OptionTest, EncryptCommandPassed) {
    ArgumentsWrapper args{"program?", "-c", "encrypt", "-i", "~/test.txt", "-p", "123", "-o", "~/test1.txt"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(OptionTest, DecryptCommandPassed) {
    ArgumentsWrapper args{"program?", "-c", "decrypt", "-i", "~/test.txt", "-p", "123", "-o", "~/test1.txt"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(OptionTest, ChecksumCommandPassed) {
    ArgumentsWrapper args{"program?", "-c", "checksum", "-i", "~/test.txt", "-p", "123", "-o", "~/test1.txt"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(OptionTest, AllArgumentsPassed) {
    ArgumentsWrapper args{"program?", "-c", "decrypt", "-i", "~/test.txt", "-p", "123", "-o", "~/test1.txt"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());
    ASSERT_EQ(po.GetInputFile(), "~/test.txt");
    ASSERT_EQ(po.GetOutputFile(), "~/test1.txt");
    ASSERT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    ASSERT_EQ(po.GetPassword(), "123");
}

TEST(OptionTest, LongOptionsPassed) {
    ArgumentsWrapper args{"program",  "--command", "encrypt",    "--input", "~/in.txt",
                          "--output", "~/out.txt", "--password", "1234"};
    CryptoGuard::ProgramOptions po;
    po.Parse(args.argc(), args.argv());

    ASSERT_FALSE(po.IsHelpPassed());
    ASSERT_EQ(po.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    ASSERT_EQ(po.GetInputFile(), "~/in.txt");
    ASSERT_EQ(po.GetOutputFile(), "~/out.txt");
    ASSERT_EQ(po.GetPassword(), "1234");
}