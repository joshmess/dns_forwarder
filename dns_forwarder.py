import argparse
import socket
import _thread

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 2: DoH-capable DNS Forwarder
# Usage: python3 dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]

PORT = 53


# Send a UDP query to the DNS server
def sendUDP(ip, query):
    server = (ip, PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(server)
    sock.send(query)
    res = sock.recv(1024)
    return res


# New thread to handle UDP DNS request
def udphandler(data, address, socket, ip ,deny_list):
    print('Request from client: ',data.encode('hex'),address)
    print('')

    # CHECK BLOCKED domains here???

    # Get UDP response from server
    udpRes = sendUDP(ip, data)

    print('UDP response:' , udpRes.encode('hex'))
    print('')
    # send back to client
    socket.sendto(udpRes, address)


if __name__ == '__main__':

    # Set up argument parsing automation
    prog = 'python3 dns_forwarder.py'
    descr = 'A DoH-capable DNS Forwarder'
    parser = argparse.ArgumentParser(prog=prog, description=descr)

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
        doh_host = args.DOH_SERVER
        #send using DoH protocol
    elif args.DOH:
        # DoH-capable server specified but not provided --> send to default DoH Server
        doh_host = 'dns.google'
        # send using DoH protocol
    elif args.DST_IP is not None:
        # DNS Server IP provided --> send query to this server
        dns_ip = args.DST_IP
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            udp_client_sock.bind((dns_ip,PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(udphandler(data, address, udp_client_sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
    else:
        # No DoH-capable or DNS Server specified --> send query to default DNS Server
        dns_ip = '1.1.1.1'
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind((dns_ip, PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(udphandler(data, address, udp_client_sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
