#!/bin/bash
self=$(basename ${BASH_SOURCE[0]})
base=$(dirname ${self})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

if [[ -f '/etc/redhat-release' ]]; then
  run ${base}/packagize-rpm.sh
elif [[ -f '/etc/debian_version' ]]; then
  run ${base}/packagize-deb.sh
else
  die "unknown packaging system"
fi

