#include "h/Scanner.h"
#include "localNetwork/model/h/Session.h"
#include <netdb.h>


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

                size_t bytes = recv(sock, buffer, sizeof(buffer) -1, 0);

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