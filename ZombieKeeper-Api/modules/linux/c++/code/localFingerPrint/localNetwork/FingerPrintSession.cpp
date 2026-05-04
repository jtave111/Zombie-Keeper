#include "h/FingerprintSession.h"

#include <mutex>
#include <algorithm>

auto cleanString = [](std::string &s) {
    s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());    
};

std::string FingerprintSession::comand_exec(std::string comand ){

    char buffer [255];
    std::string result = "";

    FILE* pipe = popen(comand.c_str(), "r");

    try
    {
            
        while (fgets(buffer, sizeof(buffer), pipe) != NULL)
        {
            result += buffer;
        }


        pclose(pipe);
        
    }
    catch(...)
    {
        pclose(pipe);
        throw;
        
    }
    
    cleanString(result);

    return result;
}



//Binary calc 
std::string FingerprintSession::ipIntToStr (u_int32_t ip){

    return std::to_string( (ip >> 24) & 0xFF) + "." +
    std::to_string( (ip >> 16) & 0xFF ) + "." + 
    std::to_string( (ip >> 8 ) & 0xFF ) + "." + 
    std::to_string (ip & 0xFF);

    
}

u_int32_t FingerprintSession::iptStrToInt(std::string ip){


    std::stringstream ss(ip);

    u_int32_t a, b, c, d;

    char p;

    ss >> a >> p >> b >> p >> c >> p >> d;


    return (a << 24) | (b << 16) | (c << 8) | d;

}



//Module 1 calls
//-----------------------------------


//getGateway modules 

std::string FingerprintSession::gatewayIp_module1(){
    
    std::string comand = "ip route show default | awk '{print $3}'";

    std::string result = FingerprintSession::comand_exec(comand);

    return result ;

}

// getCidr & submask modules

std::string FingerprintSession::getCidr_module1(){

    std::string comand = "ip route show dev $(ip route show default | awk '{print $5}') | grep 'scope link' | awk '{print $1}'";

    std::string result = FingerprintSession::comand_exec(comand);

    std::stringstream ss (result);
    std::string base_ip;


    std::string CIDR = "";

    while (std::getline(ss, base_ip, '/'))
    {
        ss >> CIDR;
    }
    

    return CIDR;

}

std::string FingerprintSession::getNetworkIp_module1(){
    
    std::string comand = "ip route show dev $(ip route show default | awk '{print $5}') | grep 'scope link' | awk '{print $1}'";    
    std::string result = FingerprintSession::comand_exec(comand);

    std::stringstream ss(result);

    std::string base_ip;

    std::getline(ss, base_ip, '/');


    return base_ip;


}


std::string FingerprintSession::getSubmask_module1(){


   int cidr = std::stoi(FingerprintSession::getCidr_module1());

    u_int32_t submask = 0xFFFFFFFF  << (32 - cidr);

    std::string result = ipIntToStr(submask);

    return result;

}



//NetWorkIdentifier 

std::string FingerprintSession::getSSID_module1(){

    std::string comand = "iwgetid -r";

    std::string result = FingerprintSession::comand_exec(comand);

    return result;
}

std::string FingerprintSession::getBSSID_module1(){

    std::string comand = "iwconfig 2>/dev/null | grep -i \"Access Point\" | awk '{print $6}'";

    std::string result = FingerprintSession::comand_exec(comand);

    return result;

    
}

std::string FingerprintSession::makeIdentifierCombination_module1(){

    std::string SSID = getSSID_module1();
   // std::string BSSID = getBSSID_module1();
    std::string MAC_GATEWAY = (FingerprintSession::getMacAddress_module1(
        FingerprintSession::gatewayIp_module1()));

    return SSID + "-" + MAC_GATEWAY; 
}



// MAC 

std::string FingerprintSession::getMacAddress_module1(std::string ip){
    Ping ping;   

    if(!ping.ping(ip.c_str())) return "NULL";

    std::string command = "awk -v ip=\"" + ip + "\" '$1==ip {print $4}' /proc/net/arp";

    std::string result = FingerprintSession::comand_exec(command);

    if(!result.empty() && result.back() == '\n') result.pop_back();


    if(!result.empty() && result != "00:00:00:00:00:00") return result;


    std::string commandLocal = "ip -o addr show | grep \"inet " + ip + "/\" | awk '{print $2}' | xargs -I {} cat /sys/class/net/{}/address";
    result = FingerprintSession::comand_exec(commandLocal);
    
    if(result.empty()) return "unknown";


    return result;

}


//Nodes 

void  FingerprintSession::addIps(std::string ip, std::vector<std::string>& listIps ){
      
    Ping ping;    


    static std::mutex list_mutex;
    if(ping.ping(ip.c_str()) != false){

        std::lock_guard<std::mutex> lock(list_mutex);
        listIps.emplace_back(ip);
    
    }
    

}


std::vector<std::string> FingerprintSession::discoverNodes(std::string gateway, int cidr){

    std::vector<std::thread> th;

    std::vector<std::string> listIps;
    
    uint32_t gatewayInt = FingerprintSession::iptStrToInt(gateway);

    uint32_t mask =  0xFFFFFFFF << (32 - cidr);

    uint32_t network = gatewayInt & mask;

    uint32_t broadcast = network | ~mask;


    for(uint32_t i = network + 1; i < broadcast; i++){

      th.emplace_back(&FingerprintSession::addIps, this, FingerprintSession::ipIntToStr(i), std::ref(listIps));
    }


    for(auto& t: th){

        if(t.joinable()) t.join();
    }

    return listIps;

}