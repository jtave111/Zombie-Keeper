#pragma once
#include <string>
#include <nlohmann/json.hpp>
// Forward declarations — Port e Node vivem em local-fingerprint/include/model/
// O .cpp que implementar esses métodos deve incluir os headers completos.
class Port;
class Node;

class JsonSerializer
{
public:
   template<typename T>
   static std::string toJson(const T& obj, int indent = -1);
};

