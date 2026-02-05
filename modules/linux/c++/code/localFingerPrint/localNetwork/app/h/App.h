
#pragma once

#include "localNetwork/scanners/h/Scanner.h"
#include "localNetwork/model/h/Session.h"  
#include "localNetwork/h/SessionBuild.h"    

class App
{
private:
    
    Session session;
    Scanner scanner;
    SessionBuild builder;
public:
    

    void createSession(Session *session);
    void createHeaderSession(Session *ptr_session);


    void scannSession(Session *ptr_session, std::string flags, long sec, long usec);
    void scanNode(Node *ptr, std::string flags, long sec, long usec);
    //Linking pointers 
    void linkingNode_inPointer(Session &session, Node *node_ptr, std::string ip, std::string mac);

    //TODO create simple scan call 
    

    bool scanPort(std::string ip, int port, long sec, long usec);
};

