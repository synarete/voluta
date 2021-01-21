#!/bin/bash -e
#
# usage: BS=<4|8|16|32|64..> RUNTIME=<30|60|90..> fio2csv <test-dir>
#

self=$(basename ${BASH_SOURCE[0]})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { msg "$@" >&2; echo "# $*" && try "$@"; }

export LC_ALL=C
unset CDPATH


KILO=1024
MEGA=$((KILO * KILO))
GIGA=$((MEGA * KILO))
DATASIZE=${GIGA}
RUNTIME=${RUNTIME:-30}

# TODO: echo 1 > /sys/block/<dev>/queue/iostats

_fio_minimal() {
  local testdir=$1
  local jobs=$2
  local bs=$3
  local bs_size=$((${bs} * 1024))
  local rwmix=$4
  local ioengine="psync"
  local size=$((DATASIZE / ${jobs}))
  local base=$(basename ${testdir})
  local name=${base}-bs${bs}-jobs${jobs}
  local filename=${testdir}/${name}

  run fio --name=${name} \
    --filename=${filename} \
    --numjobs=${jobs} \
    --bs=${bs_size} \
    --size=${size} \
    --fallocate=none \
    --rw=randrw \
    --rwmixwrite=${rwmix} \
    --ioengine=psync \
    --sync=1 \
    --direct=1 \
    --time_based \
    --runtime=${RUNTIME} \
    --thinktime=0 \
    --norandommap \
    --group_reporting \
    --randrepeat=1 \
    --unlink=1 \
    --fsync_on_close=1 \
    --minimal \
    ;
}

_fio_jobs() {
  local testdir=$(realpath $1)
  local jobs=(1 2 4 8 16 32)
  local bs=8
  local rwmix=50

  for job in ${jobs[@]}; do
    _fio_minimal ${testdir} ${job} ${bs} ${rwmix}
  done
}

_fio_rwmix() {
  local testdir=$(realpath $1)
  local job=1
  local bs=8
  local rwmixs=(10 25 50 75 90)

  for rwmix in ${rwmixs[@]}; do
    _fio_minimal ${testdir} ${job} ${bs} ${rwmix}
  done
}

_fio_to_cvs() {
  for testdir in "$@"; do
    if [[ -d ${testdir} ]]; then
      _fio_jobs ${testdir}
      #_fio_rwmix ${testdir}
    fi    
  done
}

_fio_verify() {
  try which fio > /dev/null
}

_fio_verify
_fio_to_cvs "$@"



