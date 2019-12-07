#pragma once

#include <string>
#include <deque>

struct Record
{
    int             _uid{-1};//     <0 null,    0 busy,     >0 pinhole
    std::string     _ifname;
    std::string     _ehost;
    unsigned short  _eport {};
    std::string     _rhost;
    unsigned short  _rport {};
    std::string     _ihost;
    unsigned short  _iport {};
    int             _proto {};
    std::string     _desc;
    unsigned int    _timestamp;
};

extern std::deque<Record>  _records;
