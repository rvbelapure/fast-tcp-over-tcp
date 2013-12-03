TCP Fast Open and T/TCP : Low Latency Transport Layer Protocols
================================================================

TCP handshakes are significant source of latency in current networks as most of
the communication is so short that the data transfer terminates in few round 
trips after handshaking. The handshake itself takes up time equal to 2 round-
trips, as current TCP standards do not permit data exchange till client and 
server establish the connection via handshake. Thus it is important to modify 
this 3 way handshake to reduce the delay of web transactions to as close as 
possible to one round-trip time (RTT).

Another challenge here is to ensure security from several types of attacks and 
especially denial of service (DoS) attacks when we modify / bypass the 
3-Way-Handshake (3WHS) to optimize the TCP data transfer. It is also important 
to have fall-back defense mechanisms in place to address the security concerns 
for both client and server and to mitigate the risk of failure.

As a result, we follow two different approaches to improve the TCP latency. The 
first approach is to piggyback data in SYN packet as proposed by Radhakrishnan 
et al in TCP Fast Open. For second implementation, we follow the two mechanisms 
suggested by RFC 1644, viz. Bypassing 3-way-handshake and reducing the TIME-WAIT 
delay. This protocol is especially designed for transaction based connections.

This provides an implementation of TCP Fast Open and Transactional TCP using a 
base TCP which itself acts as an overlay over existing networks.

To compile the applications, just run "make" in top level directory.


Resources:
1. TCP Fast Open
	- http://research.google.com/pubs/pub37517.html

2. T/TCP : TCP Extensions for Transactions Functional Specification
	- http://tools.ietf.org/html/rfc1644.html
