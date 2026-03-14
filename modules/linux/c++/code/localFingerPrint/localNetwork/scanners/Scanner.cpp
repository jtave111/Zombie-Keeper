#include "h/Scanner.h"
#include "localNetwork/model/h/Session.h"
#include <netdb.h>
#include <poll.h>
#include <atomic>


static std::mutex getserv_mutex;
static std::mutex port_mutex;


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

        close(sock);
        return 1;

    }else if(res == 0){
        
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


/*
* TCP funcs  
*/ 


/**
 * @brief Attempts to establish a TCP connection to a specific host and port using non-blocking I/O.
 * This function initiates a TCP 3-Way Handshake without blocking the execution thread.
 * It uses 'select()' to multiplex the I/O and wait for the connection result within a specific timeout.
 */
port_status Scanner::portScan_tcp(std::string ip, int port, long timeout_sec, long timeout_usec) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        return port_status::INTERNAL_ERROR;
    } 

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &target.sin_addr) <= 0) {
        close(sock);
        return port_status::INTERNAL_ERROR;
    }

    // Send SYN packet 
    int res = connect(sock, (sockaddr*)&target, sizeof(target));

    if (res == 0) {
        close(sock);
        return port_status::OPEN;
    } 
    
    if (errno != EINPROGRESS) {
        close(sock);
        return port_status::CLOSED; 
    }

    fd_set myset;
    FD_ZERO(&myset);
    FD_SET(sock, &myset);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = timeout_usec;
    
    res = select(sock + 1, NULL, &myset, NULL, &tv);

    if (res < 0) {
        close(sock);
        return port_status::INTERNAL_ERROR;
    } 
    else if (res == 0) {
        close(sock);
        return port_status::FILTERED; 
    } 
    else {
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
            close(sock);
            return port_status::INTERNAL_ERROR;
        } 

        if (so_error == 0) {
            close(sock);
            return port_status::OPEN;
        } else {
            close(sock);
            return port_status::CLOSED;
        }
    }
}

/**
 * @brief Performs an asynchronous TCP port scan against a specified target.
 * * This method utilizes non-blocking sockets and the poll() system call to efficiently
 * determine the state of a port without hanging the executing thread. It also safely
 * performs banner grabbing and service identification.
 * @return port_status Enum representing the final state (OPEN, CLOSED, FILTERED, etc.).
 */
port_status Scanner::portScan_tcp(Port *port_ptr, std::string ip, int port, long timeout_sec, long timeout_usec) {

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
        return port_status::INTERNAL_ERROR;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_port = htons(port);

    if(inet_pton(AF_INET, ip.c_str(), &target.sin_addr) <= 0){
        close(sock);
        port_ptr->setStatus(std::to_string(port_status::INTERNAL_ERROR));
        return port_status::INTERNAL_ERROR;
    }

    int res = connect(sock, (sockaddr*)&target, sizeof(target));

    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return port_status::CLOSED;
    }

    port_status final_status = port_status::INTERNAL_ERROR;

    if (res == 0) {
        final_status = port_status::OPEN; 
    } else {
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLOUT; 

        int timeout_ms = (timeout_sec * 1000) + (timeout_usec / 1000);
        res = poll(&pfd, 1, timeout_ms);

        if(res < 0){
            final_status = port_status::INTERNAL_ERROR;
        }else if(res == 0){
            final_status = port_status::FILTERED; 
        }else{
            int so_error = 0; 
            socklen_t len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
                final_status = port_status::INTERNAL_ERROR;
            } else if(so_error != 0){ 
                final_status = port_status::CLOSED;
            } else { 
                final_status = port_status::OPEN;   
            }
        }
    }

    if(final_status == port_status::OPEN || final_status == port_status::OPEN_FILTERED) {
        
        if(port == 80 || port == 443 || port == 8080){
            const char *req = "HEAD / HTTP/1.0\r\n\r\n";
            send(sock, req, strlen(req), 0);
        }
        
        struct pollfd pfd_read;
        pfd_read.fd = sock;
        pfd_read.events = POLLIN; 
        
        res = poll(&pfd_read, 1, 500);

        if(res > 0){
            char buffer[1024] = {0};
            ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);

            if(bytes > 0) {
                port_ptr->setBanner(std::string(buffer));
            }
        }

        
    }

    close(sock);
    return final_status;
}

/**
 * @brief Performs a massive concurrent TCP port scan across all discovered nodes in the current session.
 * * @details 
 * This engine utilizes a thread pool and a lock-free global atomic counter to flatten 
 * the [Nodes x Ports] matrix into a 1D task queue. This ensures dynamic load balancing 
 * and zero thread starvation. 
 * * Thread Safety: Implements strict Mutex locking to prevent race conditions during 
 * legacy service name resolution (getservbyport) and when appending open ports 
 * to the target Node structure.
 * * @param session Reference to the active Session containing the target Nodes.
 * @param sec     Connection timeout in seconds for each TCP socket.
 * @param usec    Connection timeout in microseconds for each TCP socket.
 */
void Scanner::scan_all_TcpNodePorts(Session &session, long sec, long usec) {
    std::vector<Node> &nodes = session.getMutableNodes();
    if (nodes.empty()) return;

    const int GLOBAL_WORKERS = 5000; 
    std::vector<std::thread> workers;

    uint64_t total_nodes = nodes.size();
    uint64_t total_tasks = total_nodes * 65535; 

    std::atomic<uint64_t> current_task(0);

    for (int i = 0; i < GLOBAL_WORKERS; i++) {
        workers.emplace_back([this, &nodes, total_tasks, sec, usec, &current_task]() {
            
            while (true) {
                uint64_t task = current_task.fetch_add(1);
                
                if (task >= total_tasks) {
                    break;
                }

                int node_index = task / 65535;
                int port = (task % 65535) + 1; 

                Node* node_ptr = &nodes[node_index];
                std::string ip = node_ptr->getIpAddress();

                Port actualPort;
                Port* port_ptr = &actualPort;

                port_status result_scan = this->portScan_tcp(port_ptr, ip, port, sec, usec);
                
                if (result_scan == port_status::OPEN) {
                 
                    actualPort.setNumber(port);
                    actualPort.setStatus(Scanner::setStatusToString(result_scan));
                
                    {
                        std::lock_guard<std::mutex> serv_lock(getserv_mutex);
                        struct servent *service_port = getservbyport(htons(port), "tcp");

                        if(service_port != nullptr){
                            actualPort.setService(service_port->s_name);
                            actualPort.setProtocol(service_port->s_proto);
                        }else{
                            actualPort.setProtocol("tcp");
                            actualPort.setService("unknown");
                        }
                    }

                    std::lock_guard<std::mutex> lock(port_mutex);
                    node_ptr->addPort(actualPort);
                }
            }
        });
    }

    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }
}

// Refatorar para o memsmo metodo do all 
//Make scan any ports --Any ports all nodes 
void Scanner::scan_any_TcpNodePorts(Session &session, long sec, long usec) {
    std::vector<std::thread> threads;
    std::vector<Node> &nodes = session.getMutableNodes();

    for (int i = 0; i < nodes.size(); i++) {
        Node* node_ptr = &nodes[i];
        
        std::string ip_cpy = node_ptr->getIpAddress();

        threads.emplace_back(&Scanner::aux_any_TcpNodePorts, this, ip_cpy, node_ptr, sec, usec);
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

void Scanner::aux_any_TcpNodePorts(std::string ip, Node* node_ptr, long timeout_sec, long timeout_usec) {
    
    std::vector<int> taticalPorts = Scanner::getTacticalTcpPorts();
    std::vector<std::thread> port_threads;
    
    for (int i = 0; i < taticalPorts.size(); i++) {
        
        int target_port = taticalPorts[i]; 

        port_threads.emplace_back([this, ip, target_port, node_ptr, timeout_sec, timeout_usec]() {
            Port actualPort;
            Port* port_ptr = &actualPort;
            
            port_status result_scan = this->portScan_tcp(port_ptr, ip, target_port, timeout_sec, timeout_usec);
            
            if (result_scan == port_status::OPEN  ||
                result_scan == port_status::FILTERED ||
                result_scan == port_status::OPEN_FILTERED
                ) {
             
                actualPort.setNumber(target_port);
                actualPort.setStatus(Scanner::setStatusToString(result_scan));
                
                {
                    std::lock_guard<std::mutex> serv_lock(getserv_mutex);
                    struct servent *service_port = getservbyport(htons(target_port), "tcp");

                    if(service_port != nullptr){
                        actualPort.setService(service_port->s_name);
                        actualPort.setProtocol(service_port->s_proto);
                    }else{
                        actualPort.setProtocol("tcp");
                        actualPort.setService("unknown");
                    }
                }

                std::lock_guard<std::mutex> lock(port_mutex);
                node_ptr->addPort(actualPort);
            }
        });
    }

    for (auto& t : port_threads) {
        if (t.joinable()) t.join();
    }
}



// Make scan all or any --One node all ports or any ports 
void Scanner::scan_OneNode_Tcp(Node &node, std::string flag, long sec, long usec) {
    std::vector<std::thread> threads;
    std::string ip = node.getIpAddress();
    std::vector<int> targetPorts;
   
    if (flag == "all" || flag == "-all-ports") { 
        targetPorts.reserve(65536);
        for (int i = 1; i < 65536; i++) targetPorts.push_back(i); 
    } else if (flag == "any" || flag == "-any-ports") {
        targetPorts = Scanner::getTacticalTcpPorts();
    }

    int max_concurrent_threads = 1000; 

    for (int portInt : targetPorts) {

        if (threads.size() >= max_concurrent_threads) {
            for (auto &t : threads) {
                if (t.joinable()) {
                    t.join();
                }
            }
            threads.clear(); 
        }

        threads.emplace_back([this, &node, ip, portInt, sec, usec]() {
            
            Port localPort;
            port_status status_scan = this->portScan_tcp(&localPort, ip, portInt, sec, usec);

            if (status_scan == port_status::OPEN || 
                status_scan == port_status::FILTERED || 
                status_scan == port_status::OPEN_FILTERED) {

                localPort.setNumber(portInt);
                
                std::lock_guard<std::mutex> lock(port_mutex);
                node.addPort(localPort);
            }
        });
    }

    for (auto &t : threads) {
        if (t.joinable()) t.join();
    }
}





//TODO Refatorar para especificar uma forçada de obtenção de banner
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