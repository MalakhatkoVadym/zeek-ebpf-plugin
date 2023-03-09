#!/bin/sh

set -e

if [ "${NPROC}" = "" ]; then
    NPROC=$(nproc)
fi

get_zeek_source() {
    cd /zeek
    if [ ! -d .git ]; then
        git clone --recurse-submodules https://github.com/zeek/zeek/ .
    fi

    git submodule update
}

configure_zeek() {
    cd /zeek
    ./configure --prefix=/usr
}

configure_plugin() {
    cd /data
    ./configure \
        --with-kernel=/usr/src/linux \
        --install-root=/usr \
        --zeek-dist=/zeek
}

build_zeek() {
    cd /zeek/build
    make -j${NPROC}
}

build_plugin() {
    cd /data/build
    make -j${NPROC}
}

package_zeek_deb() {
    # Install zeek
    DESTDIR=/out/zeek_0.0-9999 make install

    # Create files for .deb
    mkdir -p /out/zeek_0.0-9999/DEBIAN
    cat >/out/zeek_0.0-9999/DEBIAN/control <<EOF
Package: zeek
Version: 0.0-9999
Section: net
Priority: optional
Architecture: amd64
Maintainer: Mark Poliakov <m.poliakov@sirinsoftware.com>
Description: zeek packet analyzer
EOF

    cd /out
    dpkg-deb --build zeek_0.0-9999
}

get_zeek_source
configure_zeek
build_zeek

case "${TARGET_DISTRO}" in
    centos)
        # TODO package zeek for centos8
        ;;
    debian|ubuntu)
        package_zeek_deb
        ;;
    *)
        exit 1
        ;;
esac

configure_plugin
# TODO This breaks
# build_plugin
