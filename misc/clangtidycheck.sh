#!/bin/bash -e

_clang_tidy_check_list() {
  clang-tidy --list-checks -checks='*' | \
    egrep -v 'Enabled checks' | \
    egrep -v '(abseil|android|boost|cplusplus|osx|optin)' | \
    egrep -v '(fuchsia|objc|zircon|security)' | \
    egrep -v '(magic-numbers|hicpp-signed-bitwise|llvm-include-order)' | \
    egrep -v '(cppcoreguidelines-init-variables)' | \
    egrep -v '(Uninitialized|DeprecatedOrUnsafeBufferHandling)' | \
    awk '{print $1}' | \
    tr "\n" " "
}

_clang_tidy_check() {
  basedir=$(realpath $(dirname ${BASH_SOURCE[0]})/../)
  srcs=$(find ${basedir} -type f -name '*.c')
  chks=$(_clang_tidy_check_list | tr " " ",")
  idefs="-I${basedir}/include -I${basedir}/lib"
  xdefs="-DVOLUTA_LIBPRIVATE=1 -DVOLUTA_UNITEST=1"

  clang-tidy ${srcs} -checks='-*',${chks} -- ${idefs} ${xdefs}
}

_clang_tidy_version() {
  which clang-tidy
  clang-tidy -version
}

_clang_tidy_version
_clang_tidy_check


