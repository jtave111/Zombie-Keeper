#include "localNetwork/app/h/App.h"
#include <iostream>


void App::createSession(Session *session){builder.buildSession(*session);}

void App::createHeaderSession(Session *ptr_session){builder.buildSessionHeader(*ptr_session);}

void App::linkingNode_inPointer(Session &session, Node *node_ptr, std::string ip, std::string mac){builder.searchNode(session, node_ptr, ip, mac);}




void App::scannSession(Session *ptr_session, std::string flags, long sec, long usec){

    scanner.setSession(ptr_session);


    if(flags == "-all-ports"){
        
        scanner.scan_all_TcpNodePorts( *ptr_session,  sec,  usec);
       
    }else if(flags == "-any-ports"){

        scanner.scan_any_TcpNodePorts( *ptr_session, sec, usec);
    
    }

}


void App::scanNode(Node *ptr, std::string flags, long sec, long usec){


    scanner.setNode(ptr);

    scanner.scan_OneNode_Tcp(*ptr, flags, sec, usec);


}


bool App::scanPort(std::string ip, int port, long sec, long usec){
    
    return scanner.portScan_tcp(ip, port, sec, usec);
}



//test
std::mutex print_mtx;

void App::test_scan_udp(std::string ip, long timeout_sec, long timeout_usec){

    std::vector<std::thread> threads;
    const int MAX_THREADS = 200; 

    for(int i = 1; i <= 65535; i++){

       
        threads.emplace_back([this, ip, i, timeout_sec, timeout_usec]() {
            
            Port port_test;
            port_test.setNumber(i);
            Port *port_ptr = &port_test;

            int result = this->scanner.portScan_udp(port_ptr, ip, i, timeout_sec, timeout_usec);

            if(result == 1 || result == 2  ){ 
                
                std::lock_guard<std::mutex> lock(print_mtx); 
                
                std::cout << "=====================================" << std::endl;
                std::cout << "RESULT INFOS" << std::endl;
                std::cout << "Result port scan: " << result << std::endl;
                std::cout << "Port: " << port_test.getNumber() << std::endl;
                std::cout << "Banner: " << port_test.getBanner() << std::endl;
                std::cout << "Service: " << port_test.getService() << std::endl;
                std::cout << "Proto: " << port_test.getProtocol() << std::endl;
                std::cout << "Status: " << port_test.getStatus() << std::endl;
                std::cout << "=====================================" << std::endl;
            }
        });

        if(threads.size() >= MAX_THREADS){
            for(auto& t : threads){
                if(t.joinable()){
                    t.join();
                }
            }
            threads.clear();
        }
    }

    for(auto& t : threads){
        if(t.joinable()){
            t.join();
        }
    }

    std::cout << "[+] Complete test" << std::endl;
}