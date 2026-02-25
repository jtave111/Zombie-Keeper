#pragma once
#include <thread>
#include <mutex>
#include "Ping.h"
#include "localNetwork/model/h/Port.h"
#include <vector>
#include "localNetwork/model/h/Node.h"
#include <iostream>
#include <fcntl.h>      
#include <sys/select.h> 
#include <errno.h>      
#include <cstring>


class Session; 

enum port_status{

    CLOSED = 0,          
    OPEN = 1,            
    FILTERED = 2,        
    OPEN_FILTERED = 3,   
    INTERNAL_ERROR = 4
};

class Scanner
{

private:

    Ping ping;
    
    Session* session = nullptr;

    Node* node = nullptr;

public:

    

    /*
    * TCP func
    */
    
    // port scan TCP
    port_status portScan_tcp(std::string ip, int port, long timeout_sec, long timeout_usec);
    //Overload
    bool portScan_tcp( Port *port_ptr, std::string ip, int port, long timeout_sec, long timeout_usec);
    
    //All ports all nodes
    void scan_all_TcpNodePorts(Session &session, long sec, long usec);
    void aux_allNode_TcpPorts(const std::string* ip, Node* node, long timeout_sec, long timeout_usec);
    
    //Any ports all nodes 
    void scan_any_TcpNodePorts(Session &session, long sec, long usec);
    void aux_any_TcpNodePorts(const std::string* ip, Node * node, long timeout_sec, long timeout_usec);

    //One node all ports or any ports - use flag ALL for all ports or use ANY for tatical tcp ports 
    void scan_OneNode_Tcp(Node &node, std::string flag, long sec, long usec);

    //Banner grabbing
    void one_banner_grabbing(std::string ip, int port, long timeout_sec, long timeout_usec);

    //Vector tatical tcp ports 
    std::vector<int> getTacticalTcpPorts() {
        return {
            
            21,   // FTP 
            22,   // SSH
            23,   // Telnet 
            25,   // SMTP 
            53,   // DNS
            80,   // HTTP
            443,  // HTTPS
            8080, // Web Proxy / Alt HTTP
            8180, // Apache Tomcat / Alt HTTP 
            8443, // Alt HTTPS
            135,  // MSRPC
            139,  // NetBIOS
            445,  // SMB 
            3389, // RDP         
            1433, // MSSQL
            3306, // MySQL
            5432, // PostgreSQL
            6379, // Redis
            27017,// MongoDB
            1524, // Ingreslock (Backdoor root shell)
            2049, // NFS (File Share - Mountable)
            2121, // CCProxy / Custom FTP
            3632, // Distcc (Remote Code Execution)
            5900, // VNC (Acesso visual remoto)
            6000, // X11 (Keylogging )
            6667, // IRC (Backdoors / Botnets)
            512,  // exec (R-Service)
            513,  // login (R-Service)
            514,  // shell (R-Service)
            1099, // Java RMI (Java Deserialization exploits)
            8009  // Apache Jserv (AJP Ghostcat exploit)
        };
    
    }

    

    /*
    * UDP func
    */
    
    //Port scan TCP
    int portScan_udp(std::string ip, int port, long timeout_sec, long timeout_usec);
    //OVerload
    port_status portScan_udp(Port *port_ptr, std::string ip, int port, long timeout_sec, long timeout_usec);
    
    void defineUDP_payload(int port, const char* &payload, int &payload_len);

   
    std::vector<int> getTacticalUdpPorts(){
       return{
            53,    // DNS (Recon, Zone Transfer, Amplification)
            67, 68,// DHCP (Internal network information)
            69,    // TFTP (Unauthenticated file transfer)
            88,    // Kerberos (Active Directory authentication)
            111,   // RPCBind / Portmapper (Target's service map)
            123,   // NTP (Server info, Amplification)
            137, 138, // NetBIOS (Hostname, Workgroup, MAC Address in Windows networks)
            161, 162, // SNMP (Goldmine! Routers, switches, and configs if community string is 'public')
            389,   // Connectionless LDAP (Active Directory enumeration)
            500,   // ISAKMP / IKE (IPsec VPN tunnels)
            514,   // Syslog (System logs)
            520,   // RIP (Legacy routing protocol, route injection)
            623,   // IPMI (Remote hardware management, famous for Cipher Zero flaws)
            1434,  // MS-SQL Monitor (Discovers hidden SQL Server instances)
            1812, 1813, // RADIUS (Corporate authentication servers)
            1900,  // SSDP / UPnP (Discovery of IoT devices and local routers)
            2049,  // NFS (Linux/Unix file sharing)
            4500,  // IPsec NAT-T (VPN tunnel complement)
            5060,  // SIP (VoIP telephony, extension enumeration)
            5353,  // mDNS / Bonjour / Avahi (Local service discovery, Apple/Linux)
            11211  // Memcached (In-memory database, no auth by default)
        };
    }


    /*
    * AUX func
    */
    
    
    //Referenciar na chamada 
    void setSession(Session* s){
        this->session = s;
    }

    void setNode(Node * n){
        this->node = n;
    }


};

