#!/bin/sh

set -e

docker build -t zeek-ebpf-ubuntu-builder -f docker/Dockerfile.ubuntu docker
docker run \
    -e TARGET_DISTRO=ubuntu \
    -v $(pwd):/data \
    -v $(pwd)/out:/out \
    -v $(pwd)/zeek-src:/zeek \
    -it zeek-ebpf-ubuntu-builder
