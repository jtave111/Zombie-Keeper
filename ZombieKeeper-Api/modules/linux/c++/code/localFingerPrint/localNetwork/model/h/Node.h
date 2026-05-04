#pragma once
#include <string>
#include <vector>
#include <sstream>

#include "Port.h"
#include "Vulnerability.h"

class Session; 

class Node
{
private:
    std::string ipAddress;
    std::string macAddress;
    std::string hostname;
    std::string vendor;
    int vulnerabilityScore; 

    std::vector<Port> openPorts;
    std::vector<Vulnerability> vulnerabilities;

    Session* session = nullptr; 
    

public:
    Node() = default;
    
    Node(std::string ip, std::string mac, std::string host, std::string vend, int score);

    ~Node();

    void addPort(const Port& port_num);
    void addVulnerability(const Vulnerability& vuln);
    std::string toJson() const;

    Port* getOneMutablePort(Node &node, int port);
    
    const std::string& getIpAddress() const { return ipAddress; }
    void setIpAddress(const std::string& ip) { this->ipAddress = ip; }

    const std::string& getMacAddress() const { return macAddress; }
    void setMacAddress(const std::string& mac) { this->macAddress = mac; }

    const std::string& getHostname() const { return hostname; }
    void setHostname(const std::string& host) { this->hostname = host; }

    const std::string& getVendor() const { return vendor; }
    void setVendor(const std::string& vendor) { this->vendor = vendor; }

    int getVulnerabilityScore() const { return vulnerabilityScore; }
    void setVulnerabilityScore(int score) { this->vulnerabilityScore = score; }

    Session* getSession() const { return session; }
    void setSession(Session* s) { this->session = s; }

    const std::vector<Port>& getOpenPorts() const { return openPorts; }
    std::vector<Port>& getmMutablesPorts() {return openPorts;}
    void setOpenPorts(const std::vector<Port>& ports) { this->openPorts = ports; }

    const std::vector<Vulnerability>& getVulnerabilities() const { return vulnerabilities; }
    void setVulnerabilities(const std::vector<Vulnerability>& vulns) { this->vulnerabilities = vulns; }
};