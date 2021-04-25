#!/bin/bash -e
self=$(basename ${BASH_SOURCE[0]})
root=$(readlink -f $(dirname ${self}))
checkcstyle_py=${root}/misc/checkcstyle.py

${checkcstyle_py} ${root}/src ${root}/test ${root}/include
