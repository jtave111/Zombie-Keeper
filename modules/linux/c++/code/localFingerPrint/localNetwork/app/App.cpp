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