FROM rust:1.23.0

RUN apt-get update && apt-get install -y  libpcap-dev \
    && rm -rf /var/lib/apt/lists/* 


