
#!/usr/bin/python

# Import necessary modules
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import itertools
import thread

# Parse and create IP range
def ip_range(input_string):
    octets = input_string.split('.')
    chunks = [map(int, octet.split('-')) for octet in octets]
    ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]
    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))

# Scan each IP address with the identified port number
def scanner(ips):
    for i in ip_range(ips):
        src_port = RandShort()
        dst_port = port
        scan = sr1(IP(dst=i)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
        if scan is None:
            print "This port is closed on IP: " + i
        elif(scan.haslayer(TCP)):
            if(scan.getlayer(TCP).flags==0x12):
                print "This port is open for IP: " + i
        else:
            print "Unknown state"

# Request port number from user
port = int(raw_input('Enter which port to scan --> '))

# Request IP range from user - form should follow this format '192.168.1.1-26'
ips = raw_input('Enter your range using this format x.x.x.x-x --> ')

scanner(ips)
