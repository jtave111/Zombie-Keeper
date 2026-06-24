#include "ZKOutput.h"
#include <iostream>

void ZKOutput::progress(const std::string& message) {
    std::cerr << "[ZK_PROGRESS] " << message << "\n";
    std::cerr.flush();
}

void ZKOutput::info(const std::string& message) {
    std::cerr << "[ZK_INFO] " << message << "\n";
    std::cerr.flush();
}

void ZKOutput::error(const std::string& message) {
    std::cerr << "[ZK_ERROR] " << message << "\n";
    std::cerr.flush();
}

void ZKOutput::warn(const std::string& message) {
    std::cerr << "[ZK_WARN] " << message << "\n";
    std::cerr.flush();
}

void ZKOutput::progressPercent(int percent, const std::string& message) {
    std::cerr << "[ZK_PROGRESS:" << percent << "] " << message << "\n";
    std::cerr.flush();
}

void ZKOutput::result(const std::string& json) {
    std::cout << "[ZK_JSON_START]\n";
    std::cout << json << "\n";
    std::cout << "[ZK_JSON_END]\n";
    std::cout.flush();
}
