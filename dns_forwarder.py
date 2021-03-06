import argparse
import _thread
from scapy.all import DNS, DNSQR, IP, UDP
from scapy.layers.dns import DNSQR
import urllib.request
import socket

# Author: Josh Messitte (811976008)
# CSCI 6760 Project 2: DoH-capable DNS Forwarder
# Run the server: python3 dns_forwarder.py [-h] [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]
# Test the server: dig -p 6760 @your_ip_address example_domain_name

UDP_PORT = 53

# Send a UDP query to the DNS server
def sendUDP(dns_ip, query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((dns_ip, UDP_PORT))
    sock.send(query)
    data = sock.recv(1024)
    return data


# New thread to handle DoH requests
def dohHandler(data, address, csocket, doh_host, deny_list):
    # implement DNS over HTTPS
    dns_req = IP(dst=doh_host) / UDP(dport=UDP_PORT) / DNS(data)
    qid = dns_req[DNS].id
    qname = dns_req[DNSQR].qname
    orig_qname = qname
    qname_str = qname.decode()
    qname_str = qname_str[:-1]
    qname = qname_str.encode()

    qtype = dns_req[DNSQR].qtype

    if qtype == 1:
        query_type = 'A'
    if qtype == 5:
        query_type = 'CNAME'
    if qtype == 2:
        query_type = 'NS'
    if qtype == 15:
        query_type = 'MX'

    # Check if domain name should be blocked, log if needed
    for domain in deny_list:

        domain = domain.strip()
        domainbytes = domain.encode()
        if qname == domainbytes:
            # QNAME should be denied
            if logging:
                logf.write(qname.decode())
                logf.write(' ')
                logf.write(query_type)
                logf.write(' DENY\n')
            nxd = DNS(id=qid, rcode=3, qd=DNSQR(qtype=qtype, qname=orig_qname))
            resp_pkt = nxd
            csocket.sendto(bytes(resp_pkt), address)
            return

    # Log if necessary
    if logging:
        logf.write(qname.decode())
        logf.write(' ')
        logf.write(query_type)
        logf.write(' ALLOWED\n')

    # Send using HTTPS protocol
    url = 'https://' + qname_str
    req = urllib.request.Request(url)
    req.add_header('Referer', doh_host)
    r = urllib.request.urlopen(req)
    resp = r.read()
    csocket.sendto(resp, address)


# New thread to handle UDP request to be sent to DNS server (-d)
def dnsHandler(data, address, csocket, dns_ip, deny_list):
    # Form a DNS request using scapy
    dns_req = IP(dst=dns_ip) / UDP(dport=UDP_PORT) / DNS(data)
    qid = dns_req[DNS].id
    qname = dns_req[DNSQR].qname
    orig_qname = qname
    qname_str = qname.decode()
    qname_str = qname_str[:-1]
    qname = qname_str.encode()

    qtype = dns_req[DNSQR].qtype

    if qtype == 1:
        query_type = 'A'
    if qtype == 5:
        query_type = 'CNAME'
    if qtype == 2:
        query_type = 'NS'
    if qtype == 15:
        query_type = 'MX'

    # Check if domain name should be blocked, log if needed
    for domain in deny_list:
        domain = domain.strip()
        domainbytes = domain.encode()

        if qname == domainbytes:
            # QNAME should be denied
            if logging:
                logf.write(qname.decode())
                logf.write(' ')
                logf.write(query_type)
                logf.write(' DENY\n')
            nxd = DNS(id=qid,rcode=3,qd=DNSQR(qtype=qtype,qname=orig_qname))
            resp_pkt = nxd
            csocket.sendto(bytes(resp_pkt), address)
            return

    # Send UDP query to upstream DNS resolver
    udp_response = sendUDP(dns_ip, data)
    # Log if necessary
    if logging:
        logf.write(qname.decode())
        logf.write(' ')
        logf.write(query_type)
        logf.write(' ALLOWED\n')
    # send back to client
    csocket.sendto(udp_response, address)


if __name__ == '__main__':

    # Set up argument parsing automation
    prog = 'python3 dns_forwarder.py'
    descr = 'A DoH-capable DNS Forwarder'
    parser = argparse.ArgumentParser(prog=prog, description=descr)

    parser.add_argument('-d', '--DST_IP', type=str, default=None, required=False, help='DNS Server IP address')
    parser.add_argument('-f', '--DENY_LIST_FILE', type=str, default=None, required=True,
                        help='List of domains to block')
    parser.add_argument('-l', '--LOG_FILE', type=str, default=None, help='Append-only log file')
    parser.add_argument('--doh', help='Use default DoH Server', action='store_true')
    parser.add_argument('--doh_server', type=str, default=None, help='DoH Server IP address')

    # Parse the given args
    args = parser.parse_args()

    # Open and read in domains to block
    denyf_path = args.DENY_LIST_FILE
    denyf = open(denyf_path, 'r')
    blocked_domains = denyf.readlines()

    # Check for log file and open if there
    logging = False
    if args.LOG_FILE is not None:
        logf = open(args.LOG_FILE, "a")
        logging = True

    if args.doh_server is not None:
        # DoH-capable Server IP provided --> send query to this DoH Server
        doh_host = args.doh_server
        try:
            # UDP DNS  setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind(('', UDP_PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dohHandler(data, address, udp_client_sock, doh_host, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
    elif args.doh:
        # DoH-capable server specified but not provided --> send to default DoH Server
        doh_host = '8.8.8.8'
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind(('', UDP_PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dohHandler(data, address, udp_client_sock, doh_host, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
    elif args.DST_IP is not None:
        # DNS Server IP provided --> send query to this server
        dns_ip = args.DST_IP
        try:
            # UDP DNS query setup
            udp_client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_client_sock.bind(('', UDP_PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
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
            udp_client_sock.bind(('', UDP_PORT))
            while True:
                data, address = udp_client_sock.recvfrom(1024)
                _thread.start_new_thread(dnsHandler(data, address, udp_client_sock, dns_ip, blocked_domains))
        except Exception as e:
            print(e)
            udp_client_sock.close()
