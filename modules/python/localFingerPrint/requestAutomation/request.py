import urllib.request
import json
import sys


def login(url, username, password): 
    
    headers = {
        "Content-Type": "application/json"
    }

    data = json.dumps({
        "username": username,
        "password" : password
    }).encode()

    request = urllib.request.Request(url=url, data=data, headers=headers)
    with urllib.request.urlopen(request) as res:
        print(res.read())

# python script.py http://localhost:8080/auth/login testUser testPass

login(sys.argv[1], sys.argv[2], sys.argv[3])