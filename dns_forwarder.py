import argparse
import json
import sys, os
import socket
import _thread

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 2: DoH-capable DNS Forwarder
# Usage: python3 dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]

PORT = 53

# Send a UDP query to the DNS server
def sendUDP(ip,query):
    server = (ip,PORT)
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.connect(server)
    sock.send(query)
    data = sock.recv(1024)
    return data


def handler(data, address,socket,ip,deny_list):
    print('Request from client: ',data.encode('hex'),address)
    print('')

    # CHECK BLOCKED domains here???

    # Get UDP response from server
    UDPres = sendUDP(ip,data)

    print('UDP response:' , UDPres.encode('hex'))
    print('')
    # send back to client
    socket.sendto(UDPres,address)


if __name__ == 'main':

    # Set up argument parsing automation
    prog = 'python3 dns_forwarder.py'
    descr = 'A DoH-capable DNS Forwarder'
    parser = argparse.ArgumentParser(prog=prog, description=descr)
    parser.add_argument('-h', '--help',type=str, default='dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l '
                                                         'LOG_FILE] [--doh] [--doh_server DOH_SERVER]',
                        help='Use default DoH Server')
    parser.add_argument('-d', '--DST_IP', type=str, default=None, required=False,  help='DNS Server IP address')
    parser.add_argument('-f', '--DENY_LIST_FILE', type=str, default=None, required=True, help='List of domains to block')
    parser.add_argument('-l', '--LOG_FILE', type=str, default=None, help='Append-only log file')
    parser.add_argument('--doh', '--DOH', help='Use default DoH Server', action='store_true')
    parser.add_argument('--doh_server', '--DOH_SERVER', type=str, default=None, help='DoH Server IP address')

    # Parse the given args
    args = parser.parse_args()

    # Open and read in domains to block
    blocked_domains = []
    denyf_path = args.DENY_LIST_FILE
    denyf = open(denyf_path,'r')
    while True:
        nextl = denyf.readline()
        if nextl == '\n':
            break
        else:
            blocked_domains.append(nextl)

    if args.DOH_SERVER is not None:
        # DoH-capable Server IP provided --> send query to this DoH Server
        doh_ip = args.DOH_SERVER
        try:
            # UDP DNS query setup
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((doh_ip, PORT))
            while True:
                data, address = sock.recvfrom(1024)
                _thread.start_new_thread(handler(data, address, sock, doh_ip,blocked_domains))
        except Exception as e:
            print(e)
            sock.close()
    elif args.DOH:
        # DoH-capable server specified but not provided --> send to default DoH Server
        doh_ip = '8.8.8.8'
        try:
            # UDP DNS query setup
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((doh_ip, PORT))
            while True:
                data, address = sock.recvfrom(1024)
                _thread.start_new_thread(handler(data, address, sock, doh_ip, blocked_domains))
        except Exception as e:
            print(e)
            sock.close()
    elif args.DST_IP is not None:
        # DNS Server IP provided --> send query to this server
        dns_ip = args.DST_IP
        try:
            # UDP DNS query setup
            sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.bind((dns_ip,PORT))
            while True:
                data, address = sock.recvfrom(1024)
                _thread.start_new_thread(handler(data, address, sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            sock.close()
    else:
        # No DoH-capable or DNS Server specified --> send query to default DNS Server
        dns_ip = '8.8.8.8'
        try:
            # UDP DNS query setup
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((dns_ip, PORT))
            while True:
                data, address = sock.recvfrom(1024)
                _thread.start_new_thread(handler(data, address, sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            sock.close()







