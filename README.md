

Bandwidth Audit
===============

This is a project early in development.


Reads a pcap file and prints total in bytes by source-ip, destination-ip pairs.

The eventual intent is to also be able to run as a lightweight daemon that will produce much smaller logs than a full tcpdump, when you are mostly just interested in finding out how your bandwidth is being used.
