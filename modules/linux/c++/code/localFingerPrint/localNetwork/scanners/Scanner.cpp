#include "h/Scanner.h"
#include "localNetwork/model/h/Session.h"
#include <netdb.h>

/**
* UPD funcs  
*/ 

void Scanner::defineUDP_payload(int port, const char* &payload, int &payload_len){
    
    switch (port){
        
        case 123: // NTP
            payload = "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            payload_len = 48;
            break;
        
        case 53: // DNS
            payload = "\xdb\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f"
                      "\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
            payload_len = 28;
            break;

        case 161: // SNMP
            payload = "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02"
                      "\x04\x13\x12\x47\x69\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06"
                      "\x05\x2b\x06\x01\x02\x01\x05\x00";
            payload_len = 40;
            break;
        
        case 111: // RPCbind
            payload = "\x01\x09\x1f\x18\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0"
                      "\x00\x00\x00\x02\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00";
            payload_len = 40;
            break;
            
        case 137: // NetBIOS-NS (Assinatura agressiva baseada no Nmap)
            
            payload = "\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41"
                      "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                      "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00"
                      "\x00\x21\x00\x01";
            payload_len = 50;
            break;
        
        case 67:   
        case 68: // DHCP
            {
                static char dhcp_payload[300] = {0}; 
                dhcp_payload[0] = '\x01'; 
                dhcp_payload[1] = '\x01'; 
                dhcp_payload[2] = '\x06'; 
                dhcp_payload[3] = '\x00'; 
                
                dhcp_payload[236] = '\x63'; dhcp_payload[237] = '\x82';
                dhcp_payload[238] = '\x53'; dhcp_payload[239] = '\x63';
                dhcp_payload[240] = '\x35'; dhcp_payload[241] = '\x01'; dhcp_payload[242] = '\x01'; 
                dhcp_payload[243] = '\xff';

                payload = dhcp_payload;
                payload_len = 300;
            }
            break;

        case 1434: // MS-SQL Server
            payload = "\x02"; 
            payload_len = 1;
            break;
            
        case 1900: // SSDP / UPnP
            payload = "M-SEARCH * HTTP/1.1\r\n"
                      "Host: 239.255.255.250:1900\r\n"
                      "Man: \"ssdp:discover\"\r\n"
                      "MX: 2\r\n"
                      "ST: ssdp:all\r\n\r\n";
            payload_len = 104; 
            break;

        case 5353: // mDNS (Bonjour/Avahi)
            payload = "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5f\x73\x65"
                      "\x72\x76\x69\x63\x65\x73\x07\x5f\x64\x6e\x73\x2d\x73\x64\x04\x5f"
                      "\x75\x64\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01";
            payload_len = 46;
            break;

        case 500: // IKE / IPsec VPN
            payload = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x0c"
                      "\x00\x00\x00\x01\x01\x00\x00\x10";
            payload_len = 40;
            break;
        
        case 5060: // SIP (VoIP) 
            payload = "OPTIONS sip:nm SIP/2.0\r\n"
                      "To: <sip:nm@nm>\r\n"
                      "From: <sip:nm@nm>;tag=1\r\n"
                      "Call-ID: 1\r\n"
                      "CSeq: 1 OPTIONS\r\n"
                      "Via: SIP/2.0/UDP 127.0.0.1;branch=z9hG4bK1\r\n\r\n";
            payload_len = 127;
            break;

        case 623: // IPMI / RMCP
            payload = "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00";
            payload_len = 40;
            break;    
        
        case 1194: // OpenVPN
            payload = "\x38\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
            payload_len = 14;
            break;

        case 1645:
        case 1812: // RADIUS Authentication
            payload = "\x01\x18\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x01\x06\x61\x64\x6d\x69\x6e"; 
            payload_len = 26;
            break;
        case 2049: // NFSv3 (Network File System)
            payload = "\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa3"
                      "\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                      "\x00\x00\x00\x00\x00\x00\x00\x00";
            
            payload_len = 40;
            break;
        default:
           
            payload = "\x00";
            payload_len = 1;
            break;
    }
}

int Scanner::portScan_udp(std::string ip, int port, long timeout_sec, long timeout_usec){

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if(sock < 0) return 4;

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family =  AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);

    if (connect(sock, (struct sockaddr*)&target, sizeof(target)) < 0) {
        close(sock);
        return 4;
    }
    
    const char* payload  = "";
    int payload_len = 0;

    this->defineUDP_payload(port, payload, payload_len);
    
  
    if(send(sock, payload, payload_len, 0) < 0){
        close(sock);
        return 4;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = timeout_usec;


    int res = select(sock + 1, &read_fds, NULL, NULL, &tv);

    if(res > 0){

        char buffer[1024];
        // O socket tem algo para ler, pode ser dados ou um erro ICMP
        int recv_len = recv(sock, buffer, sizeof(buffer), 0);

        if(recv_len < 0){

            if(errno == ECONNREFUSED){
                close(sock);
                return 0;
            }

            close(sock);
            return 2;
        }

        //open
        close(sock);
        return 1;

    }else if(res == 0){
        //open/filt
        close(sock);
        return 3;
    }

    close(sock);
    return 4;
}

/*  Enum-
    CLOSED = 0,          
    OPEN = 1,            
    FILTERED = 2,        
    OPEN_FILTERED = 3,   
    INTERNAL_ERROR = 4
*/
port_status Scanner::portScan_udp(Port *port_ptr, std::string ip, int port, long timeout_sec, long timeout_usec){

    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock < 0){
        port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
        return port_status::INTERNAL_ERROR ;
    }

    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &target.sin_addr);

    struct servent *service_port = nullptr;
    service_port = getservbyport(htons(port), "udp");

    if(service_port != nullptr){
        port_ptr->setService(service_port->s_name);
        port_ptr->setProtocol(service_port->s_proto);
    }else{
        port_ptr->setService("unknown");
        port_ptr->setProtocol("udp");
    }

    if(connect(sock, (struct sockaddr*)&target, sizeof(target)) < 0){
        close(sock);
        port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
        return port_status::INTERNAL_ERROR;
    }

    const char* payload = nullptr;
    int payload_len = 0;

    this->defineUDP_payload(port, payload, payload_len);

    if(send(sock, payload, payload_len, 0) < 0){
        close(sock);
        port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
        return port_status::INTERNAL_ERROR;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = timeout_usec;

    int res = select(sock + 1, &read_fds, NULL, NULL, &tv);


    if(res > 0){
        
        char buffer[1024];
        memset(&buffer, 0, sizeof(buffer));

        ssize_t recv_len = recv(sock, buffer, sizeof(buffer) -1, 0);

        
        if(recv_len < 0){
           
            if(errno == ECONNREFUSED){

                close(sock); 
                port_ptr->setStatus(std::to_string(port_status::CLOSED));
                return port_status::CLOSED;
            }

            close(sock);
            port_ptr->setStatus(std::to_string(port_status::FILTERED));
            return port_status::FILTERED;
        }

        buffer[recv_len] = '\0';
        if(recv_len > 0) port_ptr->setBanner(std::string(buffer));


        close(sock);
        port_ptr->setStatus(std::to_string(port_status::OPEN));
        return port_status::OPEN;

    }else if(res == 0){

        close(sock);
        port_ptr->setStatus(std::to_string(port_status::OPEN_FILTERED));
        return port_status::OPEN_FILTERED;
    }

    close(sock);
    port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
    return port_status::INTERNAL_ERROR;

}


/**
* TCP funcs  
*/ 

/**
 * @brief Attempts to establish a TCP connection to a specific host and port using non-blocking I/O.
 * * This function initiates a TCP 3-Way Handshake without blocking the execution thread.
 * It uses 'select()' to multiplex the I/O and wait for the connection result within a specific timeout.
 */
bool Scanner::portScan_tcp(std::string ip, int port,long timeout_sec, long timeout_usec){

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0) return false;

    //Set Non-Blocking Mod
    // O_NONBLOCK: Operations like connect() will return immediately with EINPROGRESS
    // instead of blocking the process while waiting for the handshake.
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);


    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    if(inet_pton(AF_INET, ip.c_str(), &target.sin_addr) <= 0 ) {
        close(sock);
        return false;
    }

    //Send syn packet 
    int res = connect(sock, (sockaddr*)&target, sizeof(target));

    if(res < 0){
        
        
        //Connection in progress, It means the TCP Handshake SYN has been sent, but we are waiting for SYN-ACK.
        if(errno == EINPROGRESS){
            
            fd_set myset;
            FD_ZERO(&myset);
            FD_SET(sock, &myset);

            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = timeout_usec;
             // We monitor the socket for WRITABILITY.
            res = select(sock + 1, NULL, &myset, NULL, &tv);
    
            if(res > 0){

                int so_error;
                socklen_t len = sizeof(so_error);
                
                // select() returning > 0 only means the process finished.
                if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 ){

                    close(sock);
                    return false;

                } 

                //accept
                if(so_error == 0){

                    close(sock);
                    return true;
                }

            }

        }

    }else{
        
        close(sock);
        return true ;
    } 


    close(sock);
    return false;

}

//Overload 
bool Scanner::portScan_tcp(Port *port_ptr, std::string ip, int port, long timeout_sec, long timeout_usec){

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0) {
        close(sock);
        return false;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    if(inet_pton(AF_INET, ip.c_str(), &target.sin_addr) <= 0){
        close(sock);
        return false;
    }

    int res = connect(sock, (sockaddr*)&target, sizeof(target));

    if( res < 0 && errno == EINPROGRESS){

        fd_set myset;
        FD_ZERO(&myset);
        FD_SET(sock, &myset);

        struct timeval tv {timeout_sec, timeout_usec};

        res = select (sock + 1, NULL, &myset, NULL, &tv);

        if(res > 0){

            int so_error; 
            socklen_t len = sizeof(so_error);

            if(getsockopt(sock,SOL_SOCKET, SO_ERROR, &so_error, &len)  < 0){
                close(sock);
                return false;
            }   

            if(so_error != 0){
                close(sock);
                return false;
            }


            if(port == 80 || port == 443 || port == 8080){
                const char *req = "HEAD / HTTP/1.0\r\n\r\n";
                send(sock, req, strlen(req), 0);
            }
            
            FD_ZERO(&myset);
            FD_SET(sock, &myset);
            tv.tv_sec = 0; 
            tv.tv_usec = 500000;
            
            res = select(sock + 1, &myset, NULL, NULL, &tv);


            if(res > 0){

                char buffer[1024];
                memset(buffer, 0, sizeof(buffer));

                ssize_t bytes = recv(sock, buffer, sizeof(buffer) -1, 0);

                if(bytes > 0) port_ptr->setBanner(std::string (buffer));

            }

            close(sock);
            return true;
        
        }
    
    }
    else{

        close(sock);
        return false;
    }
    
    close(sock);
    return false;

}


//Make scan ALL ports --All ports all nodes
void Scanner::scan_all_TcpNodePorts(Session &session, long sec, long usec){
    
    /*
    long sec = 0;
    long usec = 300000;
    */
    std::vector<std::thread> threads;

    std::vector<Node> &nodes = session.getMutableNodes();
   

    for( int i = 0; i < nodes.size(); i ++ ){

        Node* node_ptr = &nodes[i];

        const std::string* ip_ptr = &node_ptr->getIpAddress();
      
        threads.emplace_back(&Scanner::aux_allNode_TcpPorts, this, ip_ptr, node_ptr, sec, usec);

    }

    for(auto& t: threads){
        if(t.joinable()) t.join();
    }

}
void Scanner::aux_allNode_TcpPorts(const std::string* ip, Node* node_ptr, long timeout_sec, long timeout_usec){
    
    for(int i = 1; i < 65536; i ++){

        Port actualPort;
        Port * port_ptr = &actualPort;
        if(Scanner::portScan_tcp(port_ptr, *ip, i,timeout_sec, timeout_usec)){
         
            actualPort.setNumber(i);

            struct servent *service;
            service = getservbyport(htons(i), "tcp");
        
            if(service != nullptr) { 
            
                actualPort.setService(service->s_name); 
                actualPort.setProtocol(service->s_proto); 
            } else { 
            
                actualPort.setService("unknown"); 
                actualPort.setProtocol("tcp"); 
            }
        
            node_ptr->addPort(actualPort);
        }
    }
}



//Make scan any ports --Any ports all nodes 
void Scanner::scan_any_TcpNodePorts(Session &session, long sec, long usec){
 

    std::vector<std::thread> threads;

    std::vector<Node> &nodes = session.getMutableNodes();

    for(int i = 0; i < nodes.size(); i ++){

        Node * node_ptr = &nodes[i];

        const std::string * ipPtr = &(node_ptr->getIpAddress());

        threads.emplace_back(&Scanner::aux_any_TcpNodePorts, this, ipPtr, node_ptr, sec, usec);
    }

    for(auto& t: threads){
        if(t.joinable() ) t.join();
    }

}
void Scanner::aux_any_TcpNodePorts(const std::string* ip, Node * node, long timeout_sec, long timeout_usec){

    std::vector <int> taticalPorts = Scanner::getTacticalTcpPorts();
    
    for(int i = 0; i < taticalPorts.size(); i ++){

        Port actualPort;
        Port * port_ptr = & actualPort;
        if(Scanner::portScan_tcp(port_ptr, *ip, taticalPorts[i], timeout_sec, timeout_usec )){


            actualPort.setNumber(taticalPorts[i]);

            struct servent *service;
            service = getservbyport(htons(taticalPorts[i]), "tcp");

          
            if(service != nullptr) { 
            
                actualPort.setService(service->s_name); 
                actualPort.setProtocol(service->s_proto); 
            } else { 
            
                actualPort.setService("unknown"); 
                actualPort.setProtocol("tcp"); 
            }
        

            node->addPort(actualPort);

        }

    }
}



//Make scan all or any --One node all ports or any ports - use flag ALL for all ports or use ANY for tatical tcp ports  
void Scanner::scan_OneNode_Tcp(Node &node, std::string flag, long sec, long usec){
    std::vector<std::thread> threads;
    std::string ip = node.getIpAddress();
    std::mutex mutex; 
    std::vector<int> targetPorts;

   
    if (flag == "all") {
        targetPorts.reserve(65536);
        for (int i = 0; i < 65536; i++) targetPorts.push_back(i);
    } else if (flag == "any") {
        targetPorts = Scanner::getTacticalTcpPorts();
    }

    int max_concurrent_threads = 100;

    for (int portInt : targetPorts) {

        if (threads.size() >= max_concurrent_threads) {
            for (auto &t : threads) {
                if (t.joinable()) {
                    t.join();
                }
            }
            threads.clear(); 
        }

       
        threads.emplace_back([this, &node, &mutex, ip, portInt, sec, usec]() {
            
            Port localPort;
            
            bool isOpen = this->portScan_tcp(&localPort, ip, portInt, sec, usec);

            if(isOpen){

                localPort.setNumber(portInt);
             
                if(localPort.getService().empty()){
                    struct servent *srv = getservbyport(htons(portInt), "tcp");
                    if (srv) localPort.setService(srv->s_name);
                    else localPort.setService("unknown");
                    
                    if(localPort.getProtocol().empty()) localPort.setProtocol("tcp");
                }

                std::lock_guard<std::mutex> lock(mutex);
                node.addPort(localPort);
            }
            

        });
    }

    for (auto &t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    
}



void Scanner::one_banner_grabbing( std::string ip, int port, long timeout_sec, long timeout_usec){
 
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0){
        close(sock);
        return;
    } 

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    
    Node *node_ptr = session->getOneMutableNode(ip);
    if(node_ptr == nullptr) {
        close(sock);
        return;
    }
    
    Port * port_ptr = node->getOneMutablePort(*node_ptr, port);
    if(port_ptr == nullptr){
        close(sock);
        return;
    }

    int port_int = port_ptr->getNumber();
    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port_int);

    
    if(inet_pton(AF_INET, ip.c_str(), &target.sin_addr) < 0){
        close(sock);
        return;
    }

    int res = connect(sock,(struct sockaddr*)&target, sizeof(target));

    if(res < 0 && res == EINPROGRESS){

        fd_set myset;
        FD_ZERO(&myset);
        FD_SET(sock, &myset);
        
        struct timeval tv{ timeout_sec,timeout_usec};

        res = select(sock + 1, NULL, &myset, NULL, &tv);

        if(res > 0){

            int so_error;
            socklen_t len = sizeof(so_error);

            if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0){
                close(sock);
                return;
            }

        
            if(so_error != 0){
                close(sock);
                return;
            }
            
            if(port_int == 80 || port_int == 443 || port_int == 8080){
            
                const char* req = "HEAD / HTTP/1.0\r\n\r\n";
                send(sock, req, strlen(req), 0);
            
            }
            
            FD_ZERO(&myset);
            FD_SET(sock, &myset);
            tv.tv_sec = 0; 
            tv.tv_usec = 500000;
            res = select(sock + 1, &myset, NULL, NULL, &tv);


            if(res > 0){
  
                char buffer[1024];
                memset(buffer, 0, sizeof(buffer));

                int bytes = recv(sock, buffer, 1023, 0);
                
                if(bytes > 0){

                    port_ptr->setBanner(std::string(buffer));
                    close(sock);
                    return;

                }else{
                    port_ptr->setBanner("Open(unknown)");
                    close(sock);
                    return;
                    
                }
            }
            
        }else{
            close(sock);
            return;
        }

    }else{

        close(sock);
        return;
    }


    close(sock);

}