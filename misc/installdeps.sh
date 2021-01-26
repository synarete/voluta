#!/bin/sh
#
# helper script to install dependencies on local machine, prior to build,
# either for redhat or debian based systems.
#

_install_deb() {
  apt-get install \
    gcc \
    git \
    make \
    automake \
    libtool \
    uuid-dev \
    attr-dev \
    libcap-dev \
    libunwind-dev \
    libgcrypt-dev \
    python3-docutils \
    dpkg-dev \
    debhelper
}

_install_rpm() {
  dnf install \
    gcc \
    git \
    make \
    automake \
    libtool \
    libuuid-devel \
    libattr-devel \
    libcap-devel \
    libunwind-devel \
    libgcrypt-devel \
    python3-docutils
}

[[ -f '/etc/redhat-release' ]] && _install_rpm
[[ -f '/etc/debian_version' ]] && _install_deb

