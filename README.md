# trstats
Computer Networks

```
python3 trstats.py [-h] -f DENY_LIST_FILE [-d DST_IP] [-l LOG_FILE] [--doh] [--doh_server DOH_SERVER]
```

This project uses Python to build a simple DNS forwarder with domain blocking and DoH capabilities. This DNS forwarder receives an arbitrary DNS message from a client, checks if the domain name should be blocked, and if so respond with an NXDomain message. If the queried domain name is allowed, forward the DNS message to either standard DNS resolver or a DoH-capable resolver and wait for the response from the resolver and forward it back to the client.

