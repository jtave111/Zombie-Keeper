#include "h/Port.h"
#include <sstream> 

Port::Port(int number, std::string protocol, std::string service, std::string banner) 
    : number(number), protocol(protocol), service(service), banner(banner) {}



