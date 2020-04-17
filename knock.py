#!/usr/bin/python3

from scapy.all import *

#Mute Scapy
conf.verb=0

#hosts
hosts = ["172.16.1.1",
"172.16.1.2",
"172.16.1.3",
"172.16.1.4",
"172.16.1.7",
"172.16.1.31",
"172.16.1.33",
"172.16.1.60"]
#Knocking ports
ports=[13, 37, 30000, 3000]
#SendFlag
flg="S"
#Enter Door  
door=1337
#iface
ifc="tun0"

for host in hosts:
	print("Knocking Doors",ports,"in",host)
	sr(IP(dst = str(host))/TCP(dport = ports, flags = "S")   ,iface=ifc,timeout=1) 

	#See if target door is open
	resp, noresp = sr(IP(dst = str(host))/TCP(dport = door, flags = flg)   ,iface=ifc,timeout=1) 			
	if resp!="":
		for resposta in resp:	
			flag = resposta[1][TCP].flags			
			print("Target Door:",host,": %d %s" % (door, flag))

		
