#include "h/Node.h"
#include "h/Session.h" 


Node::Node(std::string ip, std::string mac, std::string host, std::string vend, int score)
    : ipAddress(ip), macAddress(mac), hostname(host), vendor(vend), vulnerabilityScore(score)
{
}

Node::~Node()
{
}

Port * Node::getOneMutablePort(Node &node, int port_num){

    std::vector<Port> &ports = (node.getmMutablesPorts());

    for(size_t i = 0; i < ports.size();  i ++){

        if(ports[i].getNumber() == port_num ) {
            
            Port * port_ptr =  &ports[i];

            return port_ptr;
         
        }
    }

    return nullptr;
}

void Node::addPort(const Port& port) {
    this->openPorts.push_back(port);
}

void Node::addVulnerability(const Vulnerability& vuln) {
    this->vulnerabilities.push_back(vuln);
}
