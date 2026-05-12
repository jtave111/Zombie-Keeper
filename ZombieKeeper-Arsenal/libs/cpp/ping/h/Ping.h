#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <cstring>
#include <unistd.h>

class Ping
{
private:
    /* data */
public:
    unsigned short checksum(void *b, int len);
    bool ping (const char *ip);

};

