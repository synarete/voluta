#!/bin/sh
#
# helper script to install dependencies on local machine, prior to build,
# either for redhat or debian based systems.
#

_install_deb() {
  echo "# run as privileged user:"
  echo apt-get install \
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
    debhelper \
    kernel-headers
}

_install_rpm() {
  echo "# run as privileged user:"
  echo dnf install \
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
    python3-docutils \
    kernel-headers
}

if [[ -f '/etc/redhat-release' ]]; then
  _install_rpm
elif [[ -f '/etc/debian_version' ]]; then
  _install_deb
else
  echo "# unknown packaging manager"
fi

