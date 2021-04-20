#! /usr/bin/python3

"""
File: ARPScan.py
Version: 1.0
Date: 27 Mar 2021
Author: Pseudoer
Description: This python script utilises Scapy to detect ARP attacks on an interface or from recorded packet capture
             If an ARP attack is detected the user will be alerted with the attacker's details
			 Information on Scapy and installation can be found: https://scapy.net/
"""

import argparse, datetime
from scapy.all import *

# Function to complete an ARP scan on current network based on your IP and netmask, comparing attacker's MAC address to each user's MAC address
def network_locate(ip,mac):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),timeout=1, verbose=False) # Send ARP packets
	for element in ans: # For each answered packets
		if (element[1].hwsrc == mac): # If packet MAC address == attacker's MAC address
			return (element[1].psrc) # Return the attacker's IP address
	return ("Unable to locate attacker's IP on your network") # If unable to locate attacker's IP address return message

# Function to complete an ARP scan on parsed IP and return associated MAC address
def arp_scan(ip):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),timeout=3, verbose=False) # Send ARP packets
	return ans[0][1].hwsrc # Return associated MAC address

# Function to test is packet is an ARP reply and compare ARP reply MAC address with machine MAC address
def packetFunction(packet):
	if packet.haslayer(ARP) and packet[ARP].op == 2: # If packet is ARP reply
		try:
			dateTime = (datetime.fromtimestamp(packet.time)).strftime("%a, %d %b %Y, %H:%M:%S") # Format current date & time into string
			response_mac = packet[ARP].hwsrc # ARP reply packet's associated MAC address
			real_mac = arp_scan(packet[ARP].psrc) # Real MAC address of machine
			if real_mac != response_mac: # If associated MAC address != Real MAC address
				print("[*] ALERT!! You are under an ARP attack!")
				print(f"[-] {dateTime}\n[-] Real IP: {packet[ARP].psrc}\n[-] Real MAC: {real_mac}\n[-] Fake MAC (Attacker): {response_mac}")
				print(f"[-] Fake IP (Attacker): {network_locate(args.ip,response_mac)}\n") # Print attacker's IP address
				print("[*] SCANNING...\n")
		except IndexError: # If unable to locate real MAC addressfrom associated MAC address
			print("[*] CAUTION!! Unable to locate real MAC address!")
			print(f"[-] {dateTime}\n[-] Real IP: {packet[ARP].psrc}\n[-] Possible fake IP or firewall is blocking packets...\n")
			print("[*] SCANNING...\n")
			pass

# Main Program
parser = argparse.ArgumentParser(description="This python script utilises Scapy to detect ARP attacks on an interface or from recorded packet capture. If an ARP attack is detected the user will be alerted with the attacker's details.")

# Possible parsed arguments when executing the script
parser.add_argument("--interface", "-i", help="Utilse and set interface (e.g. -i eth0)")
parser.add_argument("--file", "-f", help="Utilise and set file location (e.g. -f capture.pcap)")
parser.add_argument("--ip", required=True, help="Your IP address and netmask (e.g. --ip 192.168.1.1/24)")
args = parser.parse_args() # Argument initialisation

if (args.interface and args.file): # If both interface and file arguments provided
    parser.print_help() # Return help menu
elif args.interface: # If interface argument provided
	print("[*] SCANNING...\n")
	sniff(store=False, prn=packetFunction, iface=args.interface) # Sniff packets on interface
elif args.file: # If file argument provided
	pkts = rdpcap(args.file) # Read pcap file
	print("[*] SCANNING...\n")
	for pkt in pkts: # For each packet in pcap file
		packetFunction(pkt)
else:
	parser.print_help() # Return help menu