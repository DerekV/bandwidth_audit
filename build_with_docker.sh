#!/bin/sh


docker build -t bandwidth-audit-builder .
docker run \
       --rm \
       --user "$(id -u)":"$(id -g)" \
       -v "$PWD":/usr/src/myapp \
       -w /usr/src/myapp \
       -i bandwidth-audit-builder \
       cargo build --release
