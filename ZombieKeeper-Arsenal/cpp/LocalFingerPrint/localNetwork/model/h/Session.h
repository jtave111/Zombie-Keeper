#pragma once
#include <string>
#include <vector>

class Node; 
class Port;

#include "Node.h"
#include "Port.h"

class Session
{
private:
    std::string networkIdentifier;
    std::string gatewayIp;
    std::string subnetMask;
    std::string cidr;
    
    std::vector<Node> nodes;
    

public:
    Session() = default;

    Session(std::string netId, std::string gateway, std::string mask, std::string cidr);

    ~Session();

    void addNode(const Node& node);
    void addNodes(const std::vector<Node>& nodes);
    
    std::string toJson() const;

    const std::string& getNetworkIdentifier() const { return networkIdentifier; }
    const std::string& getGatewayIp() const { return gatewayIp; }
    const std::string& getSubnetMask() const { return subnetMask; }
    const std::string& getCidr() const { return cidr; }
    
    const std::vector<Node>& getNodes() const { return nodes; }
    std::vector<Node>& getMutableNodes() {return nodes;}
    
    Node* getOneMutableNode(std::string ip);
    
    void setNetworkIdentifier(const std::string& id) { this->networkIdentifier = id; }
    void setGatewayIp(const std::string& ip) { this->gatewayIp = ip; }
    void setSubnetMask(const std::string& mask) { this->subnetMask = mask; }
    void setCidr(const std::string& cidr) { this->cidr = cidr; }
    
    void setNodes(const std::vector<Node>& nodes) { this->nodes = nodes; }
};