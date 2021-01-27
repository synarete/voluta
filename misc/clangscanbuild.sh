#!/bin/bash  -e
self=$(basename ${BASH_SOURCE[0]})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH


_require_clang_bin() {
  run which clang
  run which clang++
  run which scan-build
}

_setup_clang_env() {
  export CCC_ANALYZER_CPLUSPLUS=1
  export CCC_CC="$(which clang)"
  export CCC_CXX="$(which clang++)"
}

_clang_analyzer_checkers_args() {
  clang -cc1 -analyzer-checker-help \
    | awk '{print $1}' \
    | egrep -v 'OVERVIEW|USAGE|CHECKERS' \
    | egrep -v 'osx|debug|fuchsia|cplusplus|optin|strcpy' \
    | egrep -v 'DeprecatedOrUnsafeBufferHandling' \
    | awk '{print $1}' \
    | sed '/^$/d' \
    | awk '{print " -enable-checker "$1} ' \
    | tr "\n" " "
}

_clang_scan_build() {
  local topdir="$1"
  local builddir="${topdir}/build"
  local outdir="${builddir}/html"
  local analyzer="$(which clang)"

  cd ${topdir}
  run mkdir -p ${outdir}

  cd ${builddir}
  _setup_clang_env

  run scan-build \
    --use-analyzer=${analyzer} ../configure

  run scan-build \
    --use-analyzer=${analyzer} \
    -maxloop 100 -k -v -o ${outdir} \
    $(_clang_analyzer_checkers_args) \
    make all
}

_do_bootstrap() {
  local topdir="$1"

  ${topdir}/bootstrap -r
}


# main:
selfdir=$(realpath $(dirname ${BASH_SOURCE[0]}))
basedir=$(realpath ${selfdir}/../)
rootdir=${1:-${basedir}}

cd ${rootdir}
_require_clang_bin
_do_bootstrap ${rootdir}
_clang_scan_build ${rootdir}


