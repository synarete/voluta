#!/bin/bash -e
self=$(basename ${BASH_SOURCE[0]})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { "$@" || die "Failed to execute: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH

# Variables
name=voluta
selfdir=$(realpath $(dirname ${BASH_SOURCE[0]}))
basedir=$(realpath ${selfdir}/../../)
sourcedir=${selfdir}
builddir=${basedir}/build/doc/html
conf_in=${selfdir}/conf.py.in
conf_py=${builddir}/conf.py
version_sh=${basedir}/version.sh
version=$(try ${version_sh} --version)
release=$(try ${version_sh} --release)
revision=$(try ${version_sh} --revision)


# Prepare sphinx
run mkdir -p ${builddir}
run sed \
  -e "s,[@]NAME[@],${name},g" \
  -e "s,[@]VERSION[@],${version},g" \
  -e "s,[@]RELEASE[@],${release},g" \
  -e "s,[@]REVISION[@],${revision},g" \
  ${conf_in} > ${conf_py}

# Let shinx do it magic
run sphinx-build -b html -c ${builddir} ${sourcedir} ${builddir}

# Github stuff
touch ${builddir}/.nojekyll
