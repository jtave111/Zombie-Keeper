import urllib.request
import sys
import time

def login(jsession_id, test_url):
    """
    Testa se o JSESSIONID é válido acessando uma rota protegida.
    Retorna True se autorizado, False se bloqueado/redirecionado.
    """
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"JSESSIONID={jsession_id}"
    }
    
    request = urllib.request.Request(url=test_url, headers=headers)
    opener = urllib.request.build_opener()


    try:
        with opener.open(request) as res:
            
            if "login" in res.url:
                return False
            return True
            
    except urllib.error.HTTPError:
        return False
    except Exception as e:
        print(f"Erro: {e}")
        return False

def automation_request():
    
    if len(sys.argv) < 2:
        print("Uso: python3 request.py <SEU_JSESSIONID_AQUI>")
        return

    jsession_id = sys.argv[1]
   
    #"http://localhost:8080/c2-server/local-network/recon/session/LocalFingerPrint/any/0/300000"
   
    target_url =  sys.argv[2]

    print(f"JSESSIONID: {jsession_id} ...")

    if login(jsession_id, target_url):
        print("Start loop recon...")

       
        headers = {
            "Content-Type": "application/json",
            "Cookie": f"JSESSIONID={jsession_id}"
        }
        request = urllib.request.Request(url=target_url, headers=headers)
        opener = urllib.request.build_opener()

        while True:
            try:
                with opener.open(request) as res:
                   
                    if "login" in res.url:
                        print("Invalid JSESSIONID")
                        break
                    
                    print(res.read().decode())
                    
                print("Time req. . . ")
                time.sleep(5) 

            except urllib.error.HTTPError as e:
                print(f"HTTP ERROR  {e.code} - {e.reason}")
                break
            except KeyboardInterrupt:
                print("\nStop script...")
                break
            except Exception as e:
                print(f"Con. refused: {e}")
                break
    else:
        print("Unauthorized.")

    
def main():
   automation_request()
        

if __name__ == "__main__": 
    main()