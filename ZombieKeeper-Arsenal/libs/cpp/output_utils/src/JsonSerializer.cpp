#include "JsonSerializer.h"
#include <string>

// Port and Node full definitions needed for serialization.
// output_utils/CMakeLists must add local-fingerprint/include to include path.
#include "model/Port.h"
#include "model/Node.h"

std::string JsonSerializer::escapeString(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) {
                    // encode remaining control chars as \uXXXX
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

std::string JsonSerializer::portToJson(const Port &p) {
    return "{\"number\":"     + std::to_string(p.getNumber())          +
           ",\"protocol\":\"" + escapeString(p.getProtocol())  + "\"" +
           ",\"service\":\""  + escapeString(p.getService())   + "\"" +
           ",\"banner\":\""   + escapeString(p.getBanner())    + "\"" +
           ",\"status\":\""   + escapeString(p.getStatus())    + "\"}";
}

std::string JsonSerializer::nodeToJson(const Node &n) {
    std::string ports = "[";
    bool first = true;
    for (const Port &p : n.getOpenPorts()) {
        if (!first) ports += ',';
        ports += portToJson(p);
        first = false;
    }
    ports += ']';

    return "{\"ip\":\""               + escapeString(n.getIpAddress())               + "\"" +
           ",\"mac\":\""              + escapeString(n.getMacAddress())              + "\"" +
           ",\"hostname\":\""         + escapeString(n.getHostname())                + "\"" +
           ",\"vendor\":\""           + escapeString(n.getVendor())                  + "\"" +
           ",\"vulnerabilityScore\":" + std::to_string(n.getVulnerabilityScore())        +
           ",\"ports\":"              + ports                                            +
           "}";
}
