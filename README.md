

Bandwidth Audit
===============

This is a project early in development.


Reads a pcap file and prints total in bytes by source-ip, destination-ip pairs.

The eventual intent is to also be able to run as a lightweight daemon that will produce much smaller logs than a full tcpdump, when you are mostly just interested in finding out how your bandwidth is being used.


Building
========


Install [rust](https://www.rust-lang.org/en-US/install.html) and libpcap (already present on many systems).

Run

    cargo build
    
_or_ build without installing rust/cargo by running

    ./build-with-docker.sh


This will produce a linux binary in `./target/release/`
