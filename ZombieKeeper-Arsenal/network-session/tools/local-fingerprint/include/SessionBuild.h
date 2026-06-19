#pragma once

#include <vector>
#include "model/Session.h"
#include "model/Node.h"

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
