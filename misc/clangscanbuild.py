#!/usr/bin/env python3
#
# clang-scan-build
#
# Wrapper over Clang's scan-build static-code analyzer using autotools build.
#
# Copyright (C) 2017 Synarete
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

import sys
import os
import shlex
import subprocess
import distutils.spawn


def msg(txt: str) -> None:
    name = os.path.basename(__file__)
    print(name + ': ' + txt)


def die(txt: str) -> None:
    msg(txt)
    sys.exit(-1)


def getext(path: str) -> str:
    return str(os.path.splitext(path)[1])


def locate_bin(name: str) -> str:
    xbin = distutils.spawn.find_executable(name)
    if not xbin:
        die('failed to find ' + name)
    return str(xbin).strip()


def setup_clang_env() -> tuple:
    clang = locate_bin('clang')
    clangxx = locate_bin('clang++')
    scan_build = locate_bin('scan-build')
    os.environ['CCC_ANALYZER_CPLUSPLUS'] = '1'
    os.environ['CCC_CC'] = str(clang)
    os.environ['CCC_CXX'] = str(clangxx)
    return (clang, clangxx, scan_build)


def subexec(cmd, wd=None) -> str:
    '''Execute command as sub-process, die upon failure'''
    pipes = subprocess.Popen(shlex.split(cmd),
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             cwd=wd,
                             shell=False,
                             env=os.environ.copy())
    std_out, std_err = pipes.communicate()
    if pipes.returncode != 0:
        die('failed: ' + cmd)
    out = std_err or std_out
    return out.decode('UTF-8')


def shellexec(cmd: str, wd: str) -> None:
    msg('cd ' + wd)
    os.chdir(wd)
    msg(cmd)
    os.system(cmd)


def clang_analyzer_checkers(clang: str, subs: tuple) -> list:
    '''Returns a list of Clang's available sub-checkers'''
    cmd = '{} -cc1 -analyzer-checker-help'.format(clang)
    out = subexec(cmd)
    checkers = []
    for ln in out.split('\n'):
        lln = ln + ' . '
        chk = lln.split()[0]
        prefix = chk.split('.')[0]
        if prefix in subs:  # 'debug'
            checkers.append(chk)
    return checkers


def clang_scan_build(srcdir: str) -> None:
    '''Run clang tool on root-dir of project'''
    (clang, clangxx, scan_build) = setup_clang_env()
    subs = ('core', 'unix', 'deadcode', 'nullability', 'unix', 'valist')
    chks = clang_analyzer_checkers(clang, subs)
    enable_chks = ' '.join([' -enable-checker ' + chk for chk in chks])
    builddir = os.path.join(srcdir, 'build')
    outdir = os.path.join(builddir, 'html')
    os.makedirs(outdir, exist_ok=True)
    cmd = '{} --use-analyzer={} ../configure'.format(scan_build, clang)
    shellexec(cmd, builddir)
    opts = '--use-analyzer={} -maxloop 64 -k -v -o {}'.format(clang, outdir)
    cmd = '{} {} {} make all'.format(scan_build, opts, enable_chks)
    shellexec(cmd, builddir)


def resolve_srcdir(path: str) -> str:
    '''Locate autotools source root dir with configure'''
    if not path:
        die('missing top source-dir')
    if not os.path.isdir(path):
        die('not a directory: ' + path)
    configure = os.path.join(path, 'configure')
    if not os.path.isfile(configure):
        die('no configure file: ' + configure)
    return os.path.realpath(path)


def settitle(title: str) -> None:
    try:
        import setproctitle
        setproctitle.setproctitle(title)
    except ImportError:
        pass


def main() -> None:
    settitle(os.path.basename(sys.argv[0]))
    srcroot = '.' if (len(sys.argv[1:]) == 0) else sys.argv[1]
    clang_scan_build(resolve_srcdir(srcroot))


if __name__ == '__main__':
    main()


