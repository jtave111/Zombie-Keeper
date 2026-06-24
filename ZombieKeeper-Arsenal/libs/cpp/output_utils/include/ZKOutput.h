#pragma once
#include <string>

class ZKOutput
{
    public:

    static void progress(const std::string& message);

    static void info(const std::string& message);

    static void warn(const std::string& message);

    static void error(const std::string& message);

    static void progressPercent(int percent, const std::string& message);

    static void result(const std::string& json);
};