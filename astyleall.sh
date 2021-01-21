#!/bin/bash -e
self=$(basename ${BASH_SOURCE[0]})
root=$(readlink -f $(dirname ${self}))
yell() { echo "$self: $*" >&2; }
die() { yell "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH

try which astyle &> /dev/null

astyle1tbs() {
  try astyle -Q \
    --style=1tbs \
    --suffix=none \
    --indent=force-tab=8 \
    --convert-tabs \
    --align-pointer=name \
    --pad-oper \
    --pad-header \
    --unpad-paren \
    --min-conditional-indent=0 \
    --indent-preprocessor \
    --add-braces \
    --add-one-line-braces \
    --break-after-logical \
    --max-code-length=79 \
    --indent-col1-comments \
    --lineend=linux \
    "$@"
    # --indent-switches
}

astylesrcs() {
  srcs=$(find ${root} -type f -name "*.[ch]")
  for src in ${srcs}; do
    astyle1tbs ${src}
  done
}

astylesrcs
exit $?
