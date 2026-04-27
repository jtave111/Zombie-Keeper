    #include "h/App.h"
    #include "Scanner.h"
    #include <iostream>
    #include <iomanip>
    #include <cctype>
    #include <algorithm>
    #include <string>
    #include <stdexcept>
    #include <sys/resource.h>

    // ---------------------------------------------------------
    // Helper: Sanitizes strings to ensure valid JSON format
    // ---------------------------------------------------------
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
                std::string port_status = p.getStatus();

                std::cout << "{"; 
                std::cout << "\"number\": " << p.getNumber() << ",";
                std::cout << "\"proto\": \"" << protocolName << "\","; 
                std::cout << "\"status\": \"" << port_status << "\",";  
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
   
    // MAIN EXECUTABLE (Requires cap_net_raw,cap_net_admin=eip)
   
    //TODO: criar resposta de scanner alem do json para integrar com a Ui javaFx
    int main(int argc, char* argv[]) {
        struct rlimit rl;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
            rl.rlim_cur = 100000;
            rl.rlim_max = 100000;
            setrlimit(RLIMIT_NOFILE, &rl);
        }
        if (argc < 2) {
            std::cerr << "[-] Error: No command provided.\n";
            std::cerr << "Usage: " << argv[0] << " <command> [args...]\n";
            return 1;
        }


    
        std::string command = argv[1];

        App appInit;
        FingerprintSession auxFingerprint_session;
        Ping ping;


        // ---------------------------------------------------------
        // EXECUTE: --force_scan <ip> <flag> <sec> <usec>
        // Ex: sudo ./LocalFingerPrint --force_scan 192.168.122.59 all 2 0
        // ---------------------------------------------------------
        if (command == "--force_scan") {
            if (argc < 6) {
                std::cerr << "[-] Erro: Argumentos insuficientes.\n";
                return 1;
            }

            try {
                std::string ip = argv[2];
                std::string flag = argv[3]; // "all" ou "any"
                long sec = std::stol(argv[4]);
                long usec = std::stol(argv[5]);

                Session dummySession;
                dummySession.setNetworkIdentifier("FORCE-SCAN-NETWORK"); // 
                
                Node dummyNode;
                dummyNode.setIpAddress(ip);
                dummyNode.setMacAddress("00:00:00:00:00:00"); // MAC fictício 
                dummyNode.setSession(&dummySession);

                std::cout << "[*] Alvo travado: " << ip << " (" << flag << " ports)\n";
                
                appInit.scanNode(&dummyNode, flag, sec, usec);

                printNodeJson(&dummySession, &dummyNode);

            } catch (const std::exception& e) {
                std::cerr << "[-] Erro no Sniper: " << e.what() << "\n";
                return 1;
            }
        }



        // ---------------------------------------------------------
        // Command: --create_session <scan_flags> <sec> <usec>
        // ---------------------------------------------------------
        else if (command == "--create_session") {
            if (argc < 5) {
                std::cerr << "[-] Error: Insufficient arguments for --create_session.\n";
                return 1;
            }

            try {
                std::cout << "[DEBUG] 1. Entrou no bloco e leu argumentos...\n";
                std::string scan_opt_flag_1 = argv[2];
                std::string scan_opt_flag_2 = argv[3];
                long sec = std::stol(argv[4]);
                long usec = std::stol(argv[5]);

                Session session;
                Session* ptr_session = &session;

                std::cout << "[DEBUG] 2. Chamando appInit.createSession()...\n";
                appInit.createSession(ptr_session);
                
                std::cout << "[DEBUG] 3. createSession() sobreviveu! Chamando appInit.scannSession()...\n";
                appInit.scannSession(ptr_session, scan_opt_flag_1, scan_opt_flag_2, sec, usec);
                
                std::cout << "[DEBUG] 4. scannSession() sobreviveu! Imprimindo JSON...\n";
                printSessionJson(ptr_session);

                std::cout << "[DEBUG] 5. Tudo finalizado com sucesso.\n";

            } catch (const std::exception& e) {
                std::cerr << "[-] Fatal error: " << e.what() << "\n";
                return 1;
            } catch (...) {
                std::cerr << "[-] Erro critico desconhecido pego no catch all!\n";
                return 1;
            }
            
        }
        /*
        if (command == "--create_session") {
            if (argc < 5) {
                std::cerr << "[-] Error: Insufficient arguments for --create_session.\n";
                return 1;
            }

            try {
                std::string scan_opt_flags = argv[2];
                long sec = std::stol(argv[3]);
                long usec = std::stol(argv[4]);

                Session session;
                Session* ptr_session = &session;

                appInit.createSession(ptr_session);
                appInit.scannSession(ptr_session, scan_opt_flags, sec, usec);

                // Print final JSON for C2 Server Integration
                printSessionJson(ptr_session);

            } catch (const std::exception& e) {
                std::cerr << "[-] Fatal error parsing time arguments: " << e.what() << "\n";
                return 1;
            }
        } 
        */
        // ---------------------------------------------------------
        // Command: --simple_scan <networkIdentfier> <mac> <ip> <port> <sec> <usec>
        // ---------------------------------------------------------
        else if (command == "--simple_scan") {
            if (argc < 8) {
                std::cerr << "[-] Error: Insufficient arguments for --simple_scan.\n";
                return 1;
            }

            try {
                std::string network_identfier = argv[2];
                std::string mac = argv[3];
                std::string ip = argv[4];
                int port = std::stoi(argv[5]);
                long sec = std::stol(argv[6]);
                long usec = std::stol(argv[7]);

                Session session;
                Session* ptr_session = &session;

                appInit.createSession(ptr_session);

                Node* node_ptr = nullptr;
                auto& nodeList = session.getMutableNodes();

                for (Node& n : nodeList) {
                    if (n.getMacAddress() == mac) {
                        if (n.getIpAddress() == ip) {
                            node_ptr = &n;
                            break;
                        } else {
                            return 1; // IP mismatch
                        }
                    }
                }

                if (node_ptr == nullptr) return 1;

                appInit.linkingNode_inPointer(session, node_ptr, ip, mac);
                
                if (appInit.scanPort(ip, port, sec, usec)) {
                    return 0; // Success
                } else {
                    return 2; // Port scan failed/closed
                }

            } catch (const std::exception& e) {
                std::cerr << "[-] Fatal error parsing numerical arguments: " << e.what() << "\n";
                return 1;
            }
        }

        // ---------------------------------------------------------
        // Command: --scan_node <node-mac> <networkIdentfier> <scan_flags> <sec> <usec>
        // ---------------------------------------------------------
        else if (command == "--scan_node") {
            if (argc < 7) {
                std::cerr << "[-] Error: Insufficient arguments for --scan_node.\n";
                return 1;
            }

            try {
                std::string node_mac = argv[2];
                std::string network_identfier = argv[3];
                std::string scan_opt_flags = argv[4];
                long sec = std::stol(argv[5]);
                long usec = std::stol(argv[6]);
            
                Session session_header;
                Session* ptr_session = &session_header;
                appInit.createSession(ptr_session);

                if (session_header.getNetworkIdentifier() != network_identfier) return 2;

                Node* node_ptr = nullptr;
                auto& nodeList = session_header.getMutableNodes();

                for (Node& n : nodeList) {
                    if (n.getMacAddress() == node_mac) {
                        node_ptr = &n;
                        break;
                    }
                }
            
                if (node_ptr == nullptr) return 1; 

                std::string node_ip = node_ptr->getIpAddress();

                appInit.linkingNode_inPointer(session_header, node_ptr, node_ip, node_mac);
                appInit.scanNode(node_ptr, scan_opt_flags, sec, usec);

                // Output JSON for the single node
                printNodeJson(ptr_session, node_ptr);

            } catch (const std::exception& e) {
                std::cerr << "[-] Fatal error parsing numerical arguments: " << e.what() << "\n";
                return 1;
            }
        }

        // ---------------------------------------------------------
        // Command: -test <ip> <sec> <usec>
        // ---------------------------------------------------------
        else if (command == "-test") {
            if (argc < 5) {
                std::cerr << "[-] Error: Insufficient arguments for -test.\n";
                return 1;
            }

            try {
                std::string ip = argv[2];
                long sec = std::stol(argv[3]);
                long usec = std::stol(argv[4]);

                appInit.test_scan_udp(ip, sec, usec);

            } catch (const std::exception& e) {
                std::cerr << "[-] Fatal error parsing numerical arguments: " << e.what() << "\n";
                return 1;
            }
        } 
        
        // ---------------------------------------------------------
        // Fallback: Command not recognized
        // ---------------------------------------------------------
        else {
            std::cerr << "[-] Error: Unknown command '" << command << "'.\n";
            return 1;
        }

        return 0;
    }