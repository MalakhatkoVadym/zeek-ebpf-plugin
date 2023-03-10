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

build_zeek_rpm() {
    rpmdev-setuptree

    cat >/root/rpmbuild/SPECS/zeek.spec <<-"EOF"
%define  debug_package %{nil}

Name:           zeek
Version:        0.0.9999
Release:        1%{?dist}
Summary:        zeek packet analyzer

License:        BSD
# URL:
Source0:        %{name}-%{version}.tar.gz

# BuildRequires:
# Requires:

%description
Zeek packet analyzer

%prep
%autosetup

%build
./configure --prefix="%{_prefix}" \
	--conf-files-dir="%{_sysconfdir}/zeek" \
	--localstatedir="%{_var}"
cd build
make -j`nproc`

%install
# RPATH is used bu Zeek and can't be safely disabled.
# Thus, disable checks for rpath. They produce errors and fail build.
export QA_RPATHS=0x0001

[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

cd %{_builddir}/zeek-%{version}

make DESTDIR=$RPM_BUILD_ROOT install

# Remove timestamps from all static libs
find "${RPM_BUILD_ROOT}" -type f -name '*.a' -exec objcopy --enable-deterministic-archives {} \;

# Create a list of installed files - required content of future RPM package
find "${RPM_BUILD_ROOT}" ! -type d -o -empty | sed "s~^${RPM_BUILD_ROOT}~~g" | grep -v "share/man" > %{_builddir}/zeek-%{version}/files.list

rm -rf "${RPM_BUILD_ROOT}/usr/share/man"

%files -f %{_builddir}/zeek-%{version}/files.list

%changelog
* Fri Mar 10 2023 root
-
EOF

    cd /zeek
    python3 ci/collect-repo-info.py >repo-info.json

    tar \
        --xform='s/^\.\//.\/zeek-0.0.9999\//' \
        --exclude=./build \
        --exclude=./.git \
        -czvf /root/rpmbuild/SOURCES/zeek-0.0.9999.tar.gz .

    rm -f repo-info.json

    cd /root/rpmbuild
    rpmbuild --noclean -bb SPECS/zeek.spec

    mv /root/rpmbuild/RPMS/x86_64/zeek-0.0.9999-*.el8.x86_64.rpm /out
}

get_zeek_source

case "${TARGET_DISTRO}" in
    centos)
        build_zeek_rpm
        ;;
    debian|ubuntu)
        configure_zeek
        build_zeek

        package_zeek_deb
        ;;
    *)
        exit 1
        ;;
esac

# TODO This breaks
# configure_plugin
# build_plugin
