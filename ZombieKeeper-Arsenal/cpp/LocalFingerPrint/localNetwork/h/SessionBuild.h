#pragma once

#include <vector>
#include "localNetwork/model/h/Session.h"
#include "localNetwork/model/h/Node.h"

#include "FingerprintSession.h"



class SessionBuild
{
private:
    FingerprintSession fingerprintSession;
    Ping ping;
public:

    void buildSession(Session& targetSession);
    void buildNodes(std::string gateway, int cidr, Session & session);
    void buildSessionHeader(Session& targetSession);
    void searchNode(Session &session, Node* node_aloc_ptr, std::string ip, std::string mac );
   
    SessionBuild() = default;
    ~SessionBuild() = default;

};

