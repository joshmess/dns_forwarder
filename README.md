# dns_forwarder
Computer Networks

This project uses Python to build a simple DNS forwarder with domain blocking and DoH capabilities. This DNS forwarder receives an arbitrary DNS message from a client, checks if the domain name should be blocked, and if so responds with an NXDomain message. If the queried domain name is allowed, it forwards the DNS message to either a standard DNS resolver or a DoH-capable resolver and wait for the response from the resolver and forward it back to the client.


Run the server:
```
python3 dns_forwarder.py [-h] -f DENY_LIST_FILE [-d DST_IP] [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]
```

Test the server:
```
dig @your_ip_address example_domain_name
```

### Questions:
- successfully match id of packets when sending back to client
- sudo systemctl stop systemd-resolved before running

### Outstanding Issues:
- finish sending back NXDOMAIN message (match txIDs)
- finish implementing DoH using urllib




