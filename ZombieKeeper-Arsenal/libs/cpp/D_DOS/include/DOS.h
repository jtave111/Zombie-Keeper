#pragma once
#include <iostream>


class DOS
{
public:

    struct targetHost {
        int port;
        const char *ip;
        size_t size;

    };

    static void tcp_flood(const struct targetHost *target_host);

    static void ping_flood(const struct targetHost *target_host);

    static int dOS(int th, const int type, const struct targetHost *target_host);

};
