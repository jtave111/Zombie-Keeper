#include "h/App.h"
#include <iostream>
#include "Scanner.h"
#include <iomanip>
#include <cctype>
#include <algorithm>

void printSessionJson(Session * session){
   std::cout << "{"; 

    std::cout << "\"networkIdentifier\": \"" << session->getNetworkIdentifier() << "\",";
    std::cout << "\"gatewayIp\": \"" << session->getGatewayIp() << "\",";
    std::cout << "\"subnetMask\": \"" << session->getSubnetMask() << "\",";
    std::cout << "\"cidr\": \"" << session->getCidr() << "\",";

    std::cout << "\"nodes\": ["; 

    auto& nodes = session->getMutableNodes();
    bool firstNode = true;

    for (auto& node : nodes) {
        if (!firstNode) std::cout << ",";
        firstNode = false;
        
        std::cout << "{"; 
        std::cout << "\"ip\": \"" << node.getIpAddress() << "\",";
        
        std::string mac = node.getMacAddress();
        if(mac.empty()) mac = "unknown";
        std::cout << "\"mac\": \"" << mac << "\",";
        
        std::cout << "\"ports\": [";
        
        auto ports = node.getOpenPorts();
        bool firstPort = true;

        for (auto& p : ports) {
            if (!firstPort) std::cout << ",";
            firstPort = false;
    
            std::string banner = p.getBanner();
            std::replace(banner.begin(), banner.end(), '\n', ' ');
            std::replace(banner.begin(), banner.end(), '\r', ' ');
            std::replace(banner.begin(), banner.end(), '"', '\''); 
            std::replace(banner.begin(), banner.end(), '\\', '/');

            //TODO talvez retirar isso 
            banner.erase(std::remove_if(banner.begin(), banner.end(), 
                         [](unsigned char c){ return !std::isprint(c); }), banner.end());
            if(banner.empty()) banner = "unknown";

            std::string serviceName = p.getService();
            if(serviceName.empty()) serviceName = "unknown";
            std::string protocolName = p.getProtocol();
            if(protocolName.empty()) protocolName = "tcp"; 

            std::cout << "{"; 
            std::cout << "\"number\": " << p.getNumber() << ",";
            std::cout << "\"proto\": \"" << protocolName << "\",";  
            std::cout << "\"service\": \"" << serviceName << "\","; 
            std::cout << "\"banner\": \"" << banner << "\""; 
            std::cout << "}";
        }
        std::cout << "]"; 
        std::cout << "}"; 
    }
    std::cout << "]"; 
    std::cout << "}" << std::endl; 
}

void printNodeJson(Session *session, Node * node) {
std::cout << "{"; 

    std::cout << "\"networkIdentifier\": \"" << session->getNetworkIdentifier() << "\",";
    std::cout << "\"gatewayIp\": \"" << session->getGatewayIp() << "\",";
    std::cout << "\"subnetMask\": \"" << session->getSubnetMask() << "\","; 
    std::cout << "\"cidr\": \"" << session->getCidr() << "\",";

    
    std::cout << "\"nodes\": ["; 

   
    std::cout << "{"; 
    std::cout << "\"ip\": \"" << node->getIpAddress() << "\",";
    
    std::string mac = node->getMacAddress();
   
    std::cout << "\"mac\": \"" << mac << "\",";
    
    std::cout << "\"ports\": [";
    
    auto ports = node->getOpenPorts();
    bool firstPort = true;

    for (auto& p : ports) {
        if (!firstPort) std::cout << ",";
        firstPort = false;

        std::string banner = p.getBanner();
        
        std::replace(banner.begin(), banner.end(), '\n', ' ');
        std::replace(banner.begin(), banner.end(), '\r', ' ');
        std::replace(banner.begin(), banner.end(), '"', '\''); 
        std::replace(banner.begin(), banner.end(), '\\', '/');
        banner.erase(std::remove_if(banner.begin(), banner.end(), 
                        [](unsigned char c){ return !std::isprint(c); }), banner.end());
        
        if(banner.empty()) banner = "unknown";

        std::string serviceName = p.getService();
        if(serviceName.empty()) serviceName = "unknown";
        
        std::string protocolName = p.getProtocol();
      //  if(protocolName.empty()) protocolName = "tcp"; 

        std::cout << "{"; 
        std::cout << "\"number\": " << p.getNumber() << ",";
        std::cout << "\"proto\": \"" << protocolName << "\",";  
        std::cout << "\"service\": \"" << serviceName << "\","; 
        std::cout << "\"banner\": \"" << banner << "\""; 
        std::cout << "}";
    }
    std::cout << "]"; 
    std::cout << "}"; 

    std::cout << "]"; 
    std::cout << "}" << std::endl;
}

//sudo setcap cap_net_raw,cap_net_admin=eip ./"binar name"

int main(int argc, char* argv[]){
    App appInit;
    FingerprintSession auxFingerprint_session;
    Ping ping;

   // "./Binary --create_session '-all-ports' or '-any-ports' 0 200000 "
    std::string command = argv[1];

    if(command == "--create_session"){

        std::string scan_opt_flags = argv[2];

        int sec = std::stoi(argv[3]);
        int usec = std::stoi(argv[4]);

        Session session;

        Session *ptr_session = &session;

        appInit.createSession(ptr_session);

        appInit.scannSession(ptr_session, scan_opt_flags, sec, usec);

        printSessionJson(ptr_session);

    }

    // "./Binary --scan_node 'node-ip' + 'node-mac' + 'networkIdentfier' + ('-all-ports' or '-any-ports') + 0 + 200000 "
    if(command == "--scan_node"){

        std::string node_ip = argv[2];
        std::string node_mac = argv[3];
        std::string network_identfier = argv[4];
        std::string scan_opt_flags = argv[5];
        long sec = std::stoi(argv[6]);
        long usec = std::stoi(argv[7]);


        if(!ping.ping(node_ip.c_str())) return 0;

        if(auxFingerprint_session.getMacAddress_module1(node_ip) != node_mac) return 0;


        Session session_header;
        Session *ptr_session = &session_header;
        appInit.createSession(ptr_session);

        if(session_header.getNetworkIdentifier() != network_identfier ) return 0;

        Node target_node;

        Node *node_ptr = &target_node;
    
        target_node.setIpAddress(node_ip);  
        target_node.setMacAddress(node_mac);

        appInit.linkingNode_inPointer(session_header, node_ptr, node_ip, node_mac);

        appInit.scanNode(node_ptr, scan_opt_flags, sec, usec);

        printNodeJson(ptr_session, node_ptr);

    }

    return 0;
   
}

