import argparse
import _thread
from scapy.all import *
from scapy.layers.dns import DNSQR
import urllib.request

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 2: DoH-capable DNS Forwarder
# Usage: python3 dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]


UDPPORT = 53
TCPPORT = 443


# New thread to handle DoH requests
def dohHandler(data, address, socket, doh_host, deny_list):
    # implement DNS over HTTPS
    print('Request from client: ', data.encode('hex'), address)
    print('')

    dns_req = scapy.IP(dst=doh_host) / scapy.TCP(dport=TCPPORT) / scapy.DNS(data)
    qname = dns_req[DNSQR].qname

    # Check if domain name should be blocked, log if needed
    if qname in deny_list:
        # QNAME should be denied
        print('ERR: Non existent domain.')
        if logging:
            logf.write("" + qname + "DENY")
        # Send back NXDOMAIN message

    else:
        # Send using DNS over HTTP protocol
        response = scapy.sr1(dns_req, verbose=0)                # DOES THIS GET ANS FROM SERVER?????
                                                                # RESOURCE RECORD TYPE?????
        # Log if necessary
        if logging:
            logf.write("" + qname + "ALLOW")

        print('')
        # send back to client
        socket.sendto(bytes(response), address)                 # WILL THIS WORK????


# New thread to handle UDP request to be sent to DNS server (-d)
def dnsHandler(data, address, socket, dns_ip, deny_list):

    print('Request from client: ', data.encode('hex'), address)
    print('')

    # Form a DNS request using scapy
    dns_req = scapy.IP(dst=dns_ip)/scapy.UDP(dport=UDPPORT)/scapy.DNS(data)
    qname = dns_req[DNSQR].qname                               # WIll THIS WORK????

    # Check if domain name should be blocked, log if needed
    if qname in deny_list:
        # QNAME should be denied
        print('ERR: Non existent domain.')
        if logging:
            logf.write("" + qname + "DENY")
        # Send back NXDOMAIN message

    else:

        response = scapy.sr1(dns_req, verbose=0)                # DOES THIS GET ANS FROM SERVER?????
                                                                # RESOURCE RECORD TYPE?????

        # Log if necessary
        if logging:
            logf.write("" + qname + "ALLOW")
        print('')
        # send back to client
        socket.sendto(bytes(response), address)                 # WILL THIS WORK????


if __name__ == '__main__':

    # Set up argument parsing automation
    prog = 'python3 dns_forwarder.py'
    descr = 'A DoH-capable DNS Forwarder'
    parser = argparse.ArgumentParser(prog=prog, description=descr)

    parser.add_argument('-d', '--DST_IP', type=str, default=None, required=False,  help='DNS Server IP address')
    parser.add_argument('-f', '--DENY_LIST_FILE', type=str, default=None, required=True, help='List of domains to block')
    parser.add_argument('-l', '--LOG_FILE', type=str, default=None, help='Append-only log file')
    parser.add_argument('-doh', '--DOH', help='Use default DoH Server', action='store_true')
    parser.add_argument('-doh_server', '--DOH_SERVER', type=str, default=None, help='DoH Server IP address')

    # Parse the given args
    args = parser.parse_args()

    # Open and read in domains to block
    denyf_path = args.DENY_LIST_FILE
    denyf = open(denyf_path,'r')
    blocked_domains = denyf.readlines()

    # Check for log file and open if there
    logging = False
    if args.LOG_FILE is not None:
        logf = open(args.LOG_FILE, "a")
        logging = True

    if args.DOH_SERVER is not None:
        # DoH-capable Server IP provided --> send query to this DoH Server
        doh_host = args.DOH_SERVER
        try:
            # UDP DNS query setup
            tcp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client_sock.bind(('', TCPPORT))
            while True:
                data, address = tcp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dohHandler(data, address, tcp_client_sock, doh_host, blocked_domains))
        except Exception as e:
            print(e)
            tcp_client_sock.close()
    elif args.DOH:
        # DoH-capable server specified but not provided --> send to default DoH Server
        doh_host = 'dns.google'
        try:
            # UDP DNS query setup
            tcp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client_sock.bind(('', TCPPORT))
            while True:
                data, address = tcp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dohHandler(data, address, tcp_client_sock, doh_host, blocked_domains))
        except Exception as e:
            print(e)
            tcp_client_sock.close()
    elif args.DST_IP is not None:
        # DNS Server IP provided --> send query to this server
        dns_ip = args.DST_IP
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind(('', UDPPORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                print('starting thread')
                _thread.start_new_thread(dnsHandler(data, address, udp_client_sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
    else:
        # No DoH-capable or DNS Server specified --> send query to default DNS Server
        dns_ip = '8.8.8.8'
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind(('', UDPPORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dnsHandler(data, address, udp_client_sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()