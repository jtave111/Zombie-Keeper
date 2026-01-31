#include "h/Session.h"
#include <sstream>

Session::Session(std::string netId, std::string gateway, std::string mask, std::string cidr)
    : networkIdentifier(netId), gatewayIp(gateway), subnetMask(mask), cidr(cidr)
{
}

Session::~Session()
{
}

void Session::addNode(const Node& node) {
    this->nodes.push_back(node);
}

Node* Session::getOneMutableNode(std::string  ip){

    for(size_t i = 0; i < this->nodes.size(); i ++){

        if(this->nodes[i].getIpAddress() == ip){
            return &this->nodes[i];
        }
    }

    return nullptr;
}

