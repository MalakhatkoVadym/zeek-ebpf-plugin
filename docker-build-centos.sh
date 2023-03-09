#!/bin/sh

set -e

docker build -t zeek-ebpf-centos-builder -f docker/Dockerfile.centos docker
docker run \
    -e TARGET_DISTRO=centos \
    -v $(pwd):/data \
    -v $(pwd)/out:/out \
    -v $(pwd)/zeek-src:/zeek \
    -it zeek-ebpf-centos-builder
