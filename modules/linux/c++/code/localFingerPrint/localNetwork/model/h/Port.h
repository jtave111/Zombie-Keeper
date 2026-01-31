#pragma once 
#include <string>

class Port
{
private:
    int number;
    std::string protocol;
    std::string service; 
    std::string banner;

public:
    Port() = default;
    
    Port(int number, std::string protocol, std::string service, std::string banner);

    std::string toJson() const;

    int getNumber() const { return number; }
    
    const std::string& getProtocol() const { return protocol; }
    
    const std::string& getService() const { return service; }
    
    const std::string& getBanner() const { return banner; }


    void setNumber(int number) { 
        this->number = number; 
    }

    void setProtocol(const std::string& protocol) { 
        this->protocol = protocol; 
    }

    void setService(const std::string& service) { 
        this->service = service; 
    }

    void setBanner(const std::string& banner) { 
        this->banner = banner; 
    }
};