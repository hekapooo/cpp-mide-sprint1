#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/value_semantic.hpp>
#include <boost/program_options/variables_map.hpp>
#include <format>
#include <iostream>
#include <ostream>
#include <stdexcept>

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {

    desc_.add_options()("help,h", "Show help")("command,c", po::value<std::string>()->required(),
                                               "Command to perform: encrypt, decrypt, checksum")(
        "input,i", po::value<std::string>()->required(),
        "Input file path")("output,o", po::value<std::string>(),
                           "Output file path")("password,p", po::value<std::string>(), "Password for encrypt/decrypt");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    isHelpPassed_ = false;
    po::variables_map vm;
    po::parsed_options parsed = po::command_line_parser(argc, argv).options(desc_).run();
    po::store(parsed, vm);
    if (vm.contains("help")) {
        std::cout << desc_ << std::endl;
        isHelpPassed_ = true;
        return;
    }
    po::notify(vm);

    inputFile_ = vm["input"].as<std::string>();

    std::string command = vm["command"].as<std::string>();
    if (!commandMapping_.contains(command)) {
        throw std::invalid_argument(std::format("Command \"{}\" is not supported!", command));
    }
    command_ = commandMapping_.at(command);
    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (!vm.contains("output") || !vm.contains("password")) {
            throw std::invalid_argument("Options --output and --password are required for encrypt/decrypt!");
        }
        outputFile_ = vm["output"].as<std::string>();
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
