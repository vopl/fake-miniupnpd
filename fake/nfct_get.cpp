extern "C"
{
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
}
#include <cassert>
#include "records.hpp"

extern "C" int get_nat_ext_addr(struct sockaddr* src, struct sockaddr *dst, uint8_t proto,
                     struct sockaddr_storage* ret_ext)
{
    if(!src || !dst)
    {
        return -2;
    }

    char iaddr[INET6_ADDRSTRLEN] {};
    unsigned short iport = 0;

    if(src->sa_family == AF_INET)
    {
        struct sockaddr_in *src4 = (struct sockaddr_in*)src;
        iport = ntohs(src4->sin_port);
        inet_ntop(src4->sin_family, &src4->sin_addr, iaddr, sizeof(INET6_ADDRSTRLEN));
    }
    else if(src->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *src6 = (struct sockaddr_in6*)src;
        iport = ntohs(src6->sin6_port);
        inet_ntop(src6->sin6_family, &src6->sin6_addr, iaddr, sizeof(INET6_ADDRSTRLEN));
    }
    else
    {
        return -1;
    }


    char raddr[INET6_ADDRSTRLEN] {};
    unsigned short rport = 0;

    if(dst->sa_family == AF_INET)
    {
        struct sockaddr_in *dst4 = (struct sockaddr_in*)dst;
        rport = ntohs(dst4->sin_port);
        inet_ntop(dst4->sin_family, &dst4->sin_addr, raddr, sizeof(INET6_ADDRSTRLEN));
    }
    else if(dst->sa_family == AF_INET6)
    {
        struct sockaddr_in6 *dst6 = (struct sockaddr_in6*)dst;
        rport = ntohs(dst6->sin6_port);
        inet_ntop(dst6->sin6_family, &dst6->sin6_addr, raddr, sizeof(INET6_ADDRSTRLEN));
    }
    else
    {
        return -1;
    }

    for(Record &r : _records)
    {
        if(r._uid < 0)
        {
            continue;
        }


        if(r._proto != proto) continue;
        if(r._rhost != raddr) continue;
        if(r._rport != rport) continue;
        if(r._ihost != iaddr) continue;
        if(r._iport != iport) continue;

        if(dst->sa_family == AF_INET)
        {
            struct sockaddr_in *ext4 = (struct sockaddr_in*)ret_ext;
            memset(ext4, 0, sizeof(struct sockaddr_in));
            ext4->sin_family = AF_INET;
            ext4->sin_port = htons(r._eport);
            inet_pton(ext4->sin_family, r._ehost.data(), &ext4->sin_addr);
        }
        else if(dst->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *ext6 = (struct sockaddr_in6*)ret_ext;
            memset(ext6, 0, sizeof(struct sockaddr_in6));
            ext6->sin6_family = AF_INET6;
            ext6->sin6_port = htons(r._eport);
            inet_pton(ext6->sin6_family, r._ehost.data(), &ext6->sin6_addr);
        }
        else
        {
            return -1;
        }

        return 1;
    }

    return 0;
}

