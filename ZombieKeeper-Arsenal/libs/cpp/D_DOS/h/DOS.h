//
// Created by zero on 11/05/2026.
//

#ifndef D_DOS_DOS_H
#define D_DOS_DOS_H
#include <iostream>


class DOS
{
private:
    static unsigned short checksum(void *b, int len);
    
public:
    static void tcp_flood(const char *ip, int port);

    static void ping_flood(const char *ip, size_t size);

    static void dOS(int th, std::string type,  const char *ip);


};


#endif //D_DOS_DOS_H
